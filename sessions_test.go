package gomsf

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSessionManager_List(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	sessions, err := client.Sessions().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if sessions == nil {
		t.Error("Expected sessions to be non-nil")
	}
}

func TestSessionManager_Get_NotFound(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	_, err := client.Sessions().Get(context.Background(), "99999")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got: %v", err)
	}
}

func TestSessionManager_CompatibleModules(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	sessions, err := client.Sessions().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(sessions) == 0 {
		t.Skip("No active sessions, skipping CompatibleModules test")
	}

	var sessionID string
	for id := range sessions {
		sessionID = id
		break
	}

	mods, err := client.Sessions().CompatibleModules(context.Background(), sessionID)
	if err != nil {
		t.Errorf("CompatibleModules failed: %v", err)
	}

	if mods == nil {
		t.Log("CompatibleModules returned nil")
	}
}

func TestRunWithOutput_TimeoutBoundsReads(t *testing.T) {
	slowReadRPC := func() RPCCaller {
		return fakeRPCCaller{
			call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
				switch method {
				case SessionShellRead, SessionMeterpreterRead:
					select {
					case <-time.After(120 * time.Millisecond):
						return map[string]interface{}{"data": "DONE"}, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				default:
					return map[string]interface{}{}, nil
				}
			},
		}
	}

	run := map[string]func(context.Context, time.Duration) (string, error){
		"shell": func(ctx context.Context, timeout time.Duration) (string, error) {
			return NewShellSession(slowReadRPC(), "1").RunWithOutput(ctx, "echo DONE", []string{"DONE"}, timeout)
		},
		"meterpreter": func(ctx context.Context, timeout time.Duration) (string, error) {
			return NewMeterpreterSession(slowReadRPC(), "1").RunWithOutput(ctx, "getuid", []string{"DONE"}, timeout)
		},
	}

	for name, call := range run {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := call(context.Background(), 20*time.Millisecond)
			if !errors.Is(err, ErrCommandTimeout) {
				t.Fatalf("expected ErrCommandTimeout, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
				t.Errorf("20ms timeout took %s", elapsed)
			}
		})
	}
}

func TestRunWithOutput_CallerCancellationPassesThrough(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if method == SessionShellRead {
				select {
				case <-time.After(120 * time.Millisecond):
					return map[string]interface{}{"data": "DONE"}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return map[string]interface{}{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := NewShellSession(rpc, "1").RunWithOutput(ctx, "echo DONE", []string{"DONE"}, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestSessionManager_CompatibleModulesSendsIntegerID(t *testing.T) {
	var sentID interface{}
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if method == SessionCompatibleModules {
				sentID = args[0]
			}
			return map[string]interface{}{"modules": []interface{}{"post/multi/manage/shell_to_meterpreter"}}, nil
		},
	}

	mods, err := NewSessionManager(rpc).CompatibleModules(context.Background(), "2")
	if err != nil {
		t.Fatalf("CompatibleModules failed: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("unexpected modules: %v", mods)
	}
	if id, ok := sentID.(int); !ok || id != 2 {
		t.Fatalf("expected integer session id 2, got %#v", sentID)
	}

	if _, err := NewSessionManager(rpc).CompatibleModules(context.Background(), "not-a-number"); err == nil {
		t.Fatal("expected error for non-numeric session id")
	}
}
