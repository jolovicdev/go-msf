package gomsf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func getTestClient(t *testing.T) *Client {
	t.Helper()

	if os.Getenv("RUN_MSF_INTEGRATION") != "1" {
		t.Skip("set RUN_MSF_INTEGRATION=1 to run live Metasploit RPC tests")
	}

	password := os.Getenv("MSF_PASSWORD")
	if password == "" {
		password = "testpass123"
	}

	username := os.Getenv("MSF_USERNAME")
	if username == "" {
		username = "msf"
	}

	host := os.Getenv("MSF_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	port := 55553
	if p := os.Getenv("MSF_PORT"); p != "" {
		parsed, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("Failed to parse port: %v", err)
		}
		port = parsed
	}

	ssl := os.Getenv("MSF_SSL") != "false"

	client, err := NewClient(password,
		WithHost(host),
		WithPort(port),
		WithSSL(ssl),
		WithUsername(username),
	)
	if err != nil {
		t.Fatalf("Failed to connect to msfrpcd: %v", err)
	}

	return client
}

func TestNewClient(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	if !client.IsAuthenticated() {
		t.Error("Expected client to be authenticated")
	}

	if client.Token() == "" {
		t.Error("Expected token to be set")
	}
}

func TestClient_Call_Unauthenticated(t *testing.T) {
	c := &Client{
		host: "127.0.0.1",
		port: 55553,
		uri:  "/api/",
		ssl:  false,
	}

	_, err := c.Call(context.Background(), CoreVersion)
	if err != ErrNotAuthenticated {
		t.Errorf("Expected ErrNotAuthenticated, got: %v", err)
	}
}

func TestClient_Logout(t *testing.T) {
	client := getTestClient(t)

	err := client.Logout(context.Background())
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}

	if client.IsAuthenticated() {
		t.Error("Expected client to be unauthenticated after logout")
	}
}

type reauthServer struct {
	mu         sync.Mutex
	validToken string
	logins     int
}

func (s *reauthServer) handle(w http.ResponseWriter, r *http.Request) {
	var payload interface{}
	if err := msgpack.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	args, ok := convertBytesToString(payload).([]interface{})
	if !ok || len(args) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch args[0] {
	case "auth.login":
		s.mu.Lock()
		s.logins++
		s.validToken = "fresh-token-" + strconv.Itoa(s.logins)
		token := s.validToken
		s.mu.Unlock()
		_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{"result": "success", "token": token})
	case "core.version":
		token, _ := args[1].(string)
		s.mu.Lock()
		valid := token == s.validToken
		s.mu.Unlock()
		if !valid {
			_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{
				"error":         true,
				"error_message": "Invalid Token",
				"error_string":  "Msf::RPC::Exception",
			})
			return
		}
		_ = msgpack.NewEncoder(w).Encode(map[string]interface{}{"version": "6.4.42"})
	}
}

func newReauthClient(t *testing.T, server *reauthServer) *Client {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url failed: %v", err)
	}

	client, err := NewClient("password",
		WithHost(u.Hostname()),
		WithPort(mustPort(t, u)),
		WithURI("/"),
		WithSSL(false),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	return client
}

func TestClientCall_ReauthenticatesOnInvalidToken(t *testing.T) {
	server := &reauthServer{}
	client := newReauthClient(t, server)

	server.mu.Lock()
	server.validToken = "rotated-by-server-restart"
	server.mu.Unlock()

	_, err := client.Call(context.Background(), CoreVersion)
	if err != nil {
		t.Fatalf("expected call to recover via re-auth, got %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if server.logins != 2 {
		t.Fatalf("expected exactly one re-login (2 total), got %d", server.logins)
	}
}

func TestClientCall_ReauthSingleFlight(t *testing.T) {
	server := &reauthServer{}
	client := newReauthClient(t, server)

	server.mu.Lock()
	server.validToken = "rotated-by-server-restart"
	server.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = client.Call(context.Background(), CoreVersion)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if server.logins != 2 {
		t.Fatalf("expected concurrent invalid-token calls to share one re-login (2 total), got %d", server.logins)
	}
}

func TestClientWithToken_NoReauthWithoutPassword(t *testing.T) {
	server := &reauthServer{validToken: "initial"}

	ts := httptest.NewServer(http.HandlerFunc(server.handle))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url failed: %v", err)
	}

	client, err := NewClientWithToken("stale-token",
		WithHost(u.Hostname()),
		WithPort(mustPort(t, u)),
		WithURI("/"),
		WithSSL(false),
	)
	if err != nil {
		t.Fatalf("NewClientWithToken failed: %v", err)
	}

	_, err = client.Call(context.Background(), CoreVersion)
	if !errors.Is(err, ErrRPC) {
		t.Fatalf("expected RPC error to surface, got %v", err)
	}

	server.mu.Lock()
	defer server.mu.Unlock()
	if server.logins != 0 {
		t.Fatalf("expected no login attempts without stored password, got %d", server.logins)
	}
}
