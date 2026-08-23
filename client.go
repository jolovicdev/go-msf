package gomsf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
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
	tokenMu             sync.RWMutex
	reauthMu            sync.Mutex
	client              *http.Client
	consolePollInterval time.Duration
	sessionPollInterval time.Duration
}

type ClientOption func(*Client)

const (
	defaultConsolePollInterval = 500 * time.Millisecond
	defaultSessionPollInterval = time.Second
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

func NewClient(password string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		host:                "127.0.0.1",
		port:                55553,
		uri:                 "/api/",
		ssl:                 true,
		username:            "msf",
		consolePollInterval: defaultConsolePollInterval,
		sessionPollInterval: defaultSessionPollInterval,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	if err := c.login(context.Background(), c.username, password); err != nil {
		return nil, err
	}

	c.password = password

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
		consolePollInterval: defaultConsolePollInterval,
		sessionPollInterval: defaultSessionPollInterval,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.client == nil {
		c.client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return c, nil
}

func (c *Client) url() string {
	scheme := "http"
	if c.ssl {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, c.host, c.port, c.uri)
}

// Call performs an RPC round trip. If the server rejects the token and the
// client was constructed with NewClient, it re-authenticates once and retries.
func (c *Client) Call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
	failedToken := c.Token()

	result, err := c.call(ctx, method, args...)
	if err == nil || method == AuthLogin || c.password == "" || !isInvalidTokenError(err) {
		return result, err
	}

	if err := c.reloginIfStale(ctx, failedToken); err != nil {
		return nil, err
	}

	return c.call(ctx, method, args...)
}

func (c *Client) call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
	c.tokenMu.RLock()
	token := c.token
	c.tokenMu.RUnlock()

	if method != AuthLogin && token == "" {
		return nil, ErrNotAuthenticated
	}

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
	// afterwards.
	decoder := msgpack.NewDecoder(resp.Body)
	decoder.SetMapDecoder(stringKeyedMap)

	var result interface{}
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	result = convertBytesToString(result)

	if rpcErr, ok := responseRPCError(result); ok {
		return nil, rpcErr
	}

	return result, nil
}

func (c *Client) login(ctx context.Context, username, password string) error {
	result, err := c.Call(ctx, AuthLogin, username, password)
	if err != nil {
		return err
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w: expected auth result map", ErrUnexpectedResponse)
	}

	if res, ok := m["result"].(string); !ok || res != "success" {
		return fmt.Errorf("authentication failed")
	}

	token, ok := m["token"].(string)
	if !ok {
		return fmt.Errorf("%w: missing auth token", ErrUnexpectedResponse)
	}

	c.tokenMu.Lock()
	c.token = token
	c.tokenMu.Unlock()

	return nil
}

func (c *Client) Logout(ctx context.Context) error {
	c.tokenMu.RLock()
	token := c.token
	c.tokenMu.RUnlock()

	if token == "" {
		return nil
	}

	_, err := c.Call(ctx, AuthLogout, token)
	if err != nil {
		return err
	}

	c.tokenMu.Lock()
	c.token = ""
	c.tokenMu.Unlock()

	return nil
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

func (c *Client) reloginIfStale(ctx context.Context, failedToken string) error {
	c.reauthMu.Lock()
	defer c.reauthMu.Unlock()

	if c.Token() != failedToken {
		return nil
	}

	return c.login(ctx, c.username, c.password)
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

// maxDecodedMapSize bounds the pre-allocation performed for a decoded map;
// the length prefix on the wire is untrusted and msfrpcd responses stay far
// below this.
const maxDecodedMapSize = 1 << 20

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

	m := make(map[string]interface{}, n)
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
		return err
	}
	return msgpack.Unmarshal(encoded, target)
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
	class, _ := data["error_string"].(string)

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
	return rpcErr.Message == message
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
