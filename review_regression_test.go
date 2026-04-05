package gomsf

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type fakeRPCCaller struct {
	call func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error)
}

func (f fakeRPCCaller) Call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
	return f.call(ctx, method, args...)
}

func TestNewClientWithToken_DefaultTLSVerificationEnabled(t *testing.T) {
	client, err := NewClientWithToken("token")
	if err != nil {
		t.Fatalf("NewClientWithToken failed: %v", err)
	}

	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		if client.client.Transport == nil {
			return
		}
		t.Fatalf("expected *http.Transport, got %T", client.client.Transport)
	}

	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default client disables TLS verification")
	}
}

func TestNewClient_UsesCustomUsername(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload interface{}
		if err := msgpack.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		args, ok := convertBytesToString(payload).([]interface{})
		if !ok {
			t.Fatalf("expected args slice, got %T", payload)
		}

		if got := args[1]; got != "custom-user" {
			t.Fatalf("expected custom username, got %#v", got)
		}

		if err := msgpack.NewEncoder(w).Encode(map[string]interface{}{
			"result": "success",
			"token":  "token",
		}); err != nil {
			t.Fatalf("encode failed: %v", err)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse url failed: %v", err)
	}

	client, err := NewClient("password",
		WithHost(u.Hostname()),
		WithPort(mustPort(t, u)),
		WithURI("/"),
		WithSSL(false),
		WithUsername("custom-user"),
	)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.username != "custom-user" {
		t.Fatalf("expected custom username, got %q", client.username)
	}
}

func TestNewModuleWithContext_UsesCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("expected canceled context, got %v", ctx.Err())
			}
			return nil, context.Canceled
		},
	}

	_, err := NewModuleManager(rpc).Use(ctx, ExploitModuleType, "test/module")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNewModuleWithContext_InvalidResponseReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return "not-a-map", nil
		},
	}

	_, err := NewModuleWithContext(context.Background(), rpc, ExploitModuleType, "test/module")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestNewModuleWithContext_InvalidOptionEntryReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"RHOSTS": "invalid"}, nil
		},
	}

	_, err := NewModuleWithContext(context.Background(), rpc, ExploitModuleType, "test/module")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestNewModuleWithContext_InvalidEnumEntryReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"TARGET": map[string]interface{}{
					"enums": []interface{}{"one", 2},
				},
			}, nil
		},
	}

	_, err := NewModuleWithContext(context.Background(), rpc, ExploitModuleType, "test/module")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestDbManagerConnect_FailedResultReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"result": "failure"}, nil
		},
	}

	err := NewDbManager(rpc).Connect(context.Background(), map[string]interface{}{"adapter": "bogus"})
	if err == nil {
		t.Fatal("expected connect failure")
	}
}

func TestMsfConsoleRunCommand_TimeoutReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			switch method {
			case ConsoleWrite:
				return map[string]interface{}{}, nil
			case ConsoleRead:
				return map[string]interface{}{
					"data":   "",
					"prompt": "msf6 > ",
					"busy":   true,
				}, nil
			default:
				return nil, nil
			}
		},
	}

	_, err := NewMsfConsole(rpc, "0").RunCommand(context.Background(), "version", 10*time.Millisecond)
	if !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("expected ErrCommandTimeout, got %v", err)
	}
}

func TestResponseStringSlice_InvalidElementReturnsError(t *testing.T) {
	_, err := responseStringSlice(map[string]interface{}{"tokens": []interface{}{"ok", 1}}, "tokens")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestWithHTTPClient_PreservesCallerTLSPolicy(t *testing.T) {
	custom := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	client, err := NewClientWithToken("token", WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("NewClientWithToken failed: %v", err)
	}

	if client.client != custom {
		t.Fatal("expected custom HTTP client to be preserved")
	}
}

func TestModuleInvalidOptionErrorsUseSentinel(t *testing.T) {
	mod := &Module{
		options: map[string]*MsfModuleOption{
			"TARGET": {
				Enums: []string{"one", "two"},
			},
		},
		runOptions: make(map[string]interface{}),
	}

	if _, err := mod.OptionInfo("MISSING"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption from OptionInfo, got %v", err)
	}

	if _, err := mod.GetOption("MISSING"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption from GetOption, got %v", err)
	}

	if err := mod.SetOption("MISSING", "value"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption from SetOption, got %v", err)
	}

	if err := mod.SetOption("TARGET", "three"); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption from enum validation, got %v", err)
	}
}

func TestPollIntervalsAreConfigurable(t *testing.T) {
	client, err := NewClientWithToken("token",
		WithConsolePollInterval(25*time.Millisecond),
		WithSessionPollInterval(75*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NewClientWithToken failed: %v", err)
	}

	console := NewMsfConsole(client, "1")
	if console.pollInterval != 25*time.Millisecond {
		t.Fatalf("expected console poll interval 25ms, got %v", console.pollInterval)
	}

	meterpreter := NewMeterpreterSession(client, "1")
	if meterpreter.pollInterval != 75*time.Millisecond {
		t.Fatalf("expected meterpreter poll interval 75ms, got %v", meterpreter.pollInterval)
	}

	shell := NewShellSession(client, "1")
	if shell.pollInterval != 75*time.Millisecond {
		t.Fatalf("expected shell poll interval 75ms, got %v", shell.pollInterval)
	}
}

func TestClientCall_RPCErrorPayloadReturnsTypedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := msgpack.NewEncoder(w).Encode(map[string]interface{}{
			"error":         true,
			"error_message": "boom",
			"error_string":  "Msf::RPC::Exception",
		}); err != nil {
			t.Fatalf("encode failed: %v", err)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse url failed: %v", err)
	}

	client, err := NewClientWithToken("token",
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
		t.Fatalf("expected ErrRPC, got %v", err)
	}

	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Message != "boom" {
		t.Fatalf("expected rpc message boom, got %q", rpcErr.Message)
	}
}

func TestAuthManagerTokenGenerate_InvalidResponseReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return "invalid", nil
		},
	}

	_, err := NewAuthManager(rpc).TokenGenerate(context.Background())
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestJobManagerList_InvalidEntryReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"1": 5}, nil
		},
	}

	_, err := NewJobManager(rpc).List(context.Background())
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestSessionManagerList_InvalidResponseReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return "invalid", nil
		},
	}

	_, err := NewSessionManager(rpc).List(context.Background())
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestWorkspaceManagerGet_InvalidWorkspaceReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"workspace": "invalid"}, nil
		},
	}

	_, err := NewWorkspaceManager(rpc).Get(context.Background(), "default")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestConsoleManagerList_InvalidEntryReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"consoles": []interface{}{"invalid"},
			}, nil
		},
	}

	_, err := NewConsoleManager(rpc).List(context.Background())
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestMsfConsoleIsBusy_NotFoundReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"consoles": []interface{}{},
			}, nil
		},
	}

	_, err := NewMsfConsole(rpc, "99").IsBusy(context.Background())
	if !errors.Is(err, ErrConsoleNotFound) {
		t.Fatalf("expected ErrConsoleNotFound, got %v", err)
	}
}

func TestSessionManagerList_InvalidEntryReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"1": "invalid",
			}, nil
		},
	}

	_, err := NewSessionManager(rpc).List(context.Background())
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func mustPort(t *testing.T, u *url.URL) int {
	t.Helper()

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port failed: %v", err)
	}
	return port
}
