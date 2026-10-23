package gomsf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type Client struct {
	host                string
	port                int
	uri                 string
	ssl                 bool
	username            string
	password            string
	token               string
	authGeneration      uint64
	tokenMu             sync.RWMutex
	reauthMu            sync.Mutex
	reauth              *reauthAttempt
	client              *http.Client
	callTimeout         time.Duration
	consolePollInterval time.Duration
	sessionPollInterval time.Duration
}

// reauthAttempt is one in-flight re-authentication shared by every caller
// that saw the same rejected token. Waiters wake when done is closed and
// read token/err, which are written before the close; the fields are not
// touched afterwards.
type reauthAttempt struct {
	done  chan struct{}
	token string
	err   error
}

type ClientOption func(*Client)

const (
	defaultConsolePollInterval = 500 * time.Millisecond
	defaultSessionPollInterval = time.Second
	// defaultLoginTimeout bounds the one call made without a caller-supplied
	// context: the initial authentication in NewClient.
	defaultLoginTimeout = 30 * time.Second
	// defaultCallTimeout is the fallback for callers that pass a context
	// without a deadline. It is long enough for module reloads and imports
	// but still turns an otherwise indefinite hang into a timeout. Callers
	// that need longer should pass a context with a longer deadline.
	defaultCallTimeout = 2 * time.Minute
)

func WithHost(host string) ClientOption {
	return func(c *Client) {
		c.host = host
	}
}

func WithPort(port int) ClientOption {
	return func(c *Client) {
		c.port = port
	}
}

func WithURI(uri string) ClientOption {
	return func(c *Client) {
		c.uri = uri
	}
}

func WithSSL(ssl bool) ClientOption {
	return func(c *Client) {
		c.ssl = ssl
	}
}

func WithUsername(username string) ClientOption {
	return func(c *Client) {
		c.username = username
	}
}

func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.client = client
	}
}

func WithConsolePollInterval(interval time.Duration) ClientOption {
	return func(c *Client) {
		c.consolePollInterval = interval
	}
}

func WithSessionPollInterval(interval time.Duration) ClientOption {
	return func(c *Client) {
		c.sessionPollInterval = interval
	}
}

// WithCallTimeout sets the fallback deadline applied to RPC calls whose
// context has no deadline. The default is two minutes; non-positive values
// keep the default. A caller-provided context deadline always wins.
func WithCallTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.callTimeout = timeout
	}
}

func NewClient(password string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		host:                "127.0.0.1",
		port:                55553,
		uri:                 "/api/",
		ssl:                 true,
		username:            "msf",
		callTimeout:         defaultCallTimeout,
		consolePollInterval: defaultConsolePollInterval,
		sessionPollInterval: defaultSessionPollInterval,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = newDefaultHTTPClient()
	}

	loginCtx, cancel := context.WithTimeout(context.Background(), defaultLoginTimeout)
	defer cancel()

	token, err := c.login(loginCtx, c.username, password)
	if err != nil {
		return nil, err
	}

	c.tokenMu.Lock()
	c.token = token
	c.password = password
	c.tokenMu.Unlock()

	return c, nil
}

func NewClientWithToken(token string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		host:                "127.0.0.1",
		port:                55553,
		uri:                 "/api/",
		ssl:                 true,
		username:            "msf",
		token:               token,
		callTimeout:         defaultCallTimeout,
		consolePollInterval: defaultConsolePollInterval,
		sessionPollInterval: defaultSessionPollInterval,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = newDefaultHTTPClient()
	}

	return c, nil
}

// newDefaultHTTPClient returns a client tuned for the concurrent polling the
// library performs. The standard transport only keeps two idle connections
// per host, so an event poll watching many streams would repeatedly open TLS
// connections. It has no global timeout: every call is bounded by its
// context, and NewClient bounds its own login separately.
func newDefaultHTTPClient() *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{}
	}

	transport := base.Clone()
	transport.MaxIdleConns = 100
	transport.MaxIdleConnsPerHost = 16
	return &http.Client{Transport: transport}
}

func (c *Client) url() string {
	scheme := "http"
	if c.ssl {
		scheme = "https"
	}

	// net.JoinHostPort brackets IPv6 literals; strip brackets first so a
	// caller that already supplied them does not end up with [[::1]].
	host := c.host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(c.port)) + c.uri
}

// Call performs an RPC round trip. If the server rejects the token and the
// client was constructed with NewClient, it re-authenticates once and retries.
// Logout is exempt: a rejected token there only ends the local session.
func (c *Client) Call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
	// Capture the token once and use it for both the request and the
	// staleness check. Re-reading it in between lets a concurrent re-auth
	// swap in a token that the retry path then wrongly treats as fresh.
	failedToken := c.Token()

	result, err := c.callWithToken(ctx, failedToken, method, args...)
	if err == nil || method == AuthLogin || method == AuthLogout || !c.hasPassword() || !isInvalidTokenError(err) {
		return result, err
	}

	token, err := c.reloginIfStale(ctx, failedToken)
	if err != nil {
		return nil, err
	}

	return c.callWithToken(ctx, token, method, args...)
}

// callWithToken performs the RPC round trip authenticated with token. Every
// method except auth.login requires one.
func (c *Client) callWithToken(ctx context.Context, token string, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
	if method != AuthLogin && token == "" {
		return nil, ErrNotAuthenticated
	}

	ctx, cancel := c.withCallDeadline(ctx)
	defer cancel()

	reqArgs := make([]interface{}, 0, len(args)+2)
	reqArgs = append(reqArgs, string(method))

	if method != AuthLogin {
		reqArgs = append(reqArgs, token)
	}

	reqArgs = append(reqArgs, args...)

	payload, err := msgpack.Marshal(reqArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "binary/message-pack")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// msfrpcd encodes strings as binary and some maps (module.info targets)
	// with integer keys, so decode maps with tolerant keys and normalize
	// afterwards. The decoder trusts the server the same way the caller does:
	// it is not hardened against a hostile msfrpcd, but map pre-allocation
	// and the total response size are bounded so malformed lengths cannot
	// drive the allocation cost far past the payload.
	decoder := msgpack.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	decoder.SetMapDecoder(stringKeyedMap)

	var result interface{}
	if err := decoder.Decode(&result); err != nil {
		if resp.StatusCode != http.StatusOK {
			// Wrap so a decode failure caused by the caller's cancellation
			// still matches errors.Is(err, context.Canceled).
			return nil, fmt.Errorf("request failed: http status %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	result = convertBytesToString(result)

	// msfrpcd reports server exceptions as a non-200 response whose body is
	// still the structured error; those are RPC errors, not transport
	// failures. Any other non-200 body (a proxy or gateway error page) is
	// not a msgpack result and must not be returned as one.
	if rpcErr, ok := responseRPCError(result); ok {
		return nil, rpcErr
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed: http status %d", resp.StatusCode)
	}

	return result, nil
}

// withCallDeadline applies the client's fallback deadline when the caller
// supplied a context without one. A caller-provided deadline always wins.
func (c *Client) withCallDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}

	timeout := c.callTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

// login performs auth.login and returns the fresh token without storing it;
// callers decide whether the client keeps the session.
func (c *Client) login(ctx context.Context, username, password string) (string, error) {
	result, err := c.Call(ctx, AuthLogin, username, password)
	if err != nil {
		return "", err
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: expected auth result map", ErrUnexpectedResponse)
	}

	if res, ok := m["result"].(string); !ok || res != "success" {
		return "", fmt.Errorf("authentication failed")
	}

	token, ok := m["token"].(string)
	if !ok {
		return "", fmt.Errorf("%w: missing auth token", ErrUnexpectedResponse)
	}

	return token, nil
}

func (c *Client) Logout(ctx context.Context) error {
	c.tokenMu.RLock()
	token := c.token
	c.tokenMu.RUnlock()

	if token == "" {
		return nil
	}

	// A stale token has nothing to end server-side; treat it as logged out
	// instead of re-authenticating and killing the fresh token. Authenticate
	// with the same token that is being revoked so a concurrent re-auth
	// cannot make this call revoke a token it did not authenticate with.
	_, err := c.callWithToken(ctx, token, AuthLogout, token)
	if err != nil && !isInvalidTokenError(err) {
		return err
	}

	// Bumping the generation rejects login results from callers that were
	// already re-authenticating when the logout happened.
	c.tokenMu.Lock()
	c.token = ""
	c.password = ""
	c.authGeneration++
	c.tokenMu.Unlock()

	return nil
}

func (c *Client) hasPassword() bool {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.password != ""
}

func (c *Client) Token() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

func (c *Client) IsAuthenticated() bool {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token != ""
}

// reloginIfStale re-authenticates a client whose token the server rejected
// and returns the token the caller should retry with. Only one login runs at
// a time; concurrent callers wait for it and share its result, including a
// failure, and the wait honors ctx. A login that completes after Logout does
// not restore the session: the fresh token is handed to the retrying caller
// only.
func (c *Client) reloginIfStale(ctx context.Context, failedToken string) (string, error) {
	for {
		c.reauthMu.Lock()
		attempt := c.reauth
		if attempt == nil {
			attempt = &reauthAttempt{done: make(chan struct{})}
			c.reauth = attempt
			c.reauthMu.Unlock()

			c.runReauth(ctx, attempt, failedToken)
			return attempt.token, attempt.err
		}
		c.reauthMu.Unlock()

		select {
		case <-attempt.done:
			// A login canceled by the leader's context says nothing about
			// this caller's context; let a caller whose context is still
			// alive trigger a fresh attempt instead of inheriting that
			// cancellation.
			if attempt.err != nil && isContextError(attempt.err) && ctx.Err() == nil {
				continue
			}
			return attempt.token, attempt.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// runReauth performs the shared login attempt and publishes its outcome.
func (c *Client) runReauth(ctx context.Context, attempt *reauthAttempt, failedToken string) {
	defer func() {
		c.reauthMu.Lock()
		if c.reauth == attempt {
			c.reauth = nil
		}
		c.reauthMu.Unlock()
		close(attempt.done)
	}()

	// Another caller may have refreshed the token while this attempt was
	// being registered; reuse that token instead of logging in again.
	if token := c.Token(); token != failedToken {
		attempt.token = token
		return
	}

	c.tokenMu.RLock()
	generation := c.authGeneration
	password := c.password
	c.tokenMu.RUnlock()

	token, err := c.login(ctx, c.username, password)
	if err != nil {
		attempt.err = err
		return
	}

	c.tokenMu.Lock()
	if c.authGeneration == generation {
		c.token = token
	}
	c.tokenMu.Unlock()

	attempt.token = token
}

func isInvalidTokenError(err error) bool {
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		return false
	}
	message := strings.EqualFold(rpcErr.Message, "Invalid Authentication Token") ||
		strings.EqualFold(rpcErr.Message, "Invalid Token")
	return message
}

// maxDecodedMapSize bounds the number of entries accepted for a decoded map;
// the length prefix on the wire is untrusted and msfrpcd responses stay far
// below this.
const maxDecodedMapSize = 1 << 20

// maxDecodedMapPrealloc caps the initial bucket allocation for a decoded map.
// Pre-allocating the full wire length would let a five-byte length prefix
// claim enormous memory before any entries are read; the map still grows as
// real entries arrive.
const maxDecodedMapPrealloc = 1 << 10

// maxResponseBytes bounds how much of a response body is decoded at all.
// Real msfrpcd responses (module listings, console output, loot) stay far
// below this; anything larger is treated as malformed.
const maxResponseBytes = 256 << 20

// stringKeyedMap decodes a msgpack map into map[string]interface{} regardless
// of the wire key type: binary and string keys map directly, other key types
// (msfrpcd uses integer indices) are formatted. Normalization collisions are
// rejected instead of silently overwriting the earlier value.
func stringKeyedMap(d *msgpack.Decoder) (interface{}, error) {
	n, err := d.DecodeMapLen()
	if err != nil {
		return nil, err
	}
	if n == -1 {
		return nil, nil
	}
	if n > maxDecodedMapSize {
		return nil, fmt.Errorf("msgpack map length %d exceeds limit %d", n, maxDecodedMapSize)
	}

	prealloc := n
	if prealloc > maxDecodedMapPrealloc {
		prealloc = maxDecodedMapPrealloc
	}
	m := make(map[string]interface{}, prealloc)
	for i := 0; i < n; i++ {
		key, err := d.DecodeInterface()
		if err != nil {
			return nil, err
		}
		value, err := d.DecodeInterface()
		if err != nil {
			return nil, err
		}
		normalized := interfaceKeyToString(key)
		if _, exists := m[normalized]; exists {
			return nil, fmt.Errorf("duplicate map key after normalization: %q", normalized)
		}
		m[normalized] = value
	}

	return m, nil
}

func interfaceKeyToString(key interface{}) string {
	switch k := key.(type) {
	case string:
		return k
	case []byte:
		return string(k)
	default:
		return fmt.Sprintf("%v", k)
	}
}

func convertBytesToString(v interface{}) interface{} {
	switch val := v.(type) {
	case []byte:
		return string(val)
	case map[string]interface{}:
		for k, v := range val {
			val[k] = convertBytesToString(v)
		}
		return val
	case []interface{}:
		for i, v := range val {
			val[i] = convertBytesToString(v)
		}
		return val
	case map[interface{}]interface{}:
		m := make(map[string]interface{}, len(val))
		for k, v := range val {
			var key string
			switch kt := k.(type) {
			case []byte:
				key = string(kt)
			case string:
				key = kt
			default:
				key = fmt.Sprintf("%v", kt)
			}
			m[key] = convertBytesToString(v)
		}
		return m
	default:
		return v
	}
}

func decodeResult(data interface{}, target interface{}) error {
	encoded, err := msgpack.Marshal(data)
	if err != nil {
		return fmt.Errorf("%w: encode response: %v", ErrUnexpectedResponse, err)
	}
	if err := msgpack.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("%w: decode response: %v", ErrUnexpectedResponse, err)
	}
	return nil
}

func decodeList[T any](result interface{}, key string) ([]*T, error) {
	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	raw, ok := data[key].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected %s list", ErrUnexpectedResponse, key)
	}

	encoded, err := msgpack.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid %s list: %v", ErrUnexpectedResponse, key, err)
	}

	var values []*T
	if err := msgpack.Unmarshal(encoded, &values); err != nil {
		return nil, fmt.Errorf("%w: invalid %s list: %v", ErrUnexpectedResponse, key, err)
	}
	for i, value := range values {
		if value == nil {
			return nil, fmt.Errorf("%w: nil %s entry at index %d", ErrUnexpectedResponse, key, i)
		}
	}

	return values, nil
}

func responseMap(result interface{}) (map[string]interface{}, error) {
	m, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected map", ErrUnexpectedResponse)
	}
	return m, nil
}

func responseStringSlice(result interface{}, key string) ([]string, error) {
	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	raw, ok := data[key].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected %s list", ErrUnexpectedResponse, key)
	}

	values := make([]string, len(raw))
	for i, item := range raw {
		value, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: expected %s[%d] string", ErrUnexpectedResponse, key, i)
		}
		values[i] = value
	}

	return values, nil
}

// responseIDSlice decodes a list of identifiers that msfrpcd sends as
// integers (module.compatible_sessions returns integer session IDs),
// normalizing them to the string form the library exposes.
func responseIDSlice(result interface{}, key string) ([]string, error) {
	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	raw, ok := data[key].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected %s list", ErrUnexpectedResponse, key)
	}

	values := make([]string, len(raw))
	for i, item := range raw {
		value, ok := identifierToString(item)
		if !ok {
			return nil, fmt.Errorf("%w: expected %s[%d] identifier", ErrUnexpectedResponse, key, i)
		}
		values[i] = value
	}

	return values, nil
}

// identifierToString accepts a string or any of the integer widths msgpack
// decoding can produce for a small number.
func identifierToString(item interface{}) (string, bool) {
	switch id := item.(type) {
	case string:
		return id, true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", id), true
	default:
		return "", false
	}
}

func responseString(data map[string]interface{}, key string) (string, error) {
	value, ok := data[key].(string)
	if !ok {
		return "", fmt.Errorf("%w: expected %s string", ErrUnexpectedResponse, key)
	}
	return value, nil
}

func optionalString(data map[string]interface{}, key string) string {
	value, _ := data[key].(string)
	return value
}

// responseResultFailure reports whether an RPC result carries an explicit
// {"result":"failure"} verdict. msfrpcd uses this form for console and
// plugin operations instead of the error flag the rest of the API uses.
func responseResultFailure(result interface{}) bool {
	data, ok := result.(map[string]interface{})
	if !ok {
		return false
	}
	res, _ := data["result"].(string)
	return res == "failure"
}

// responseResultStatus returns the "result" verdict used by DB operations,
// which spell failure as "failed" rather than "failure".
func responseResultStatus(result interface{}) (string, error) {
	data, err := responseMap(result)
	if err != nil {
		return "", err
	}
	return responseString(data, "result")
}

func responseRPCError(result interface{}) (*RPCError, bool) {
	data, ok := result.(map[string]interface{})
	if !ok {
		return nil, false
	}

	isError, ok := data["error"].(bool)
	if !ok || !isError {
		return nil, false
	}

	message, _ := data["error_message"].(string)
	class, _ := data["error_class"].(string)

	return &RPCError{
		Class:   class,
		Message: message,
	}, true
}

func rpcErrorMessage(err error, message string) bool {
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		return false
	}
	return strings.EqualFold(rpcErr.Message, message)
}

func (c *Client) consolePollIntervalValue() time.Duration {
	if c.consolePollInterval <= 0 {
		return defaultConsolePollInterval
	}
	return c.consolePollInterval
}

func (c *Client) sessionPollIntervalValue() time.Duration {
	if c.sessionPollInterval <= 0 {
		return defaultSessionPollInterval
	}
	return c.sessionPollInterval
}

func waitForPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// commandTimeoutError maps errors raised by a command helper's own deadline
// onto ErrCommandTimeout. Cancellation of the caller's context and unrelated
// RPC failures pass through unchanged.
func commandTimeoutError(parent, cmd context.Context, command string, err error) error {
	if parent.Err() == nil && cmd.Err() != nil {
		return fmt.Errorf("%w: %s", ErrCommandTimeout, command)
	}
	return err
}
