package gomsf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
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
	token               string
	tokenMu             sync.RWMutex
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

	if err := c.login(c.username, password); err != nil {
		return nil, err
	}

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

func (c *Client) Call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
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

	var result interface{}
	if err := msgpack.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	result = convertBytesToString(result)

	if rpcErr, ok := responseRPCError(result); ok {
		return nil, rpcErr
	}

	return result, nil
}

func (c *Client) login(username, password string) error {
	result, err := c.Call(context.Background(), AuthLogin, username, password)
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
