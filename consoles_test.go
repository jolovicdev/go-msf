package gomsf

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConsoleManager_Create(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if console.ID == "" {
		t.Error("Expected console ID to be non-empty")
	}

	err = client.Consoles().Destroy(context.Background(), console.ID)
	if err != nil {
		t.Errorf("Destroy failed: %v", err)
	}
}

func TestConsoleManager_List(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	consoles, err := client.Consoles().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if consoles == nil {
		t.Error("Expected consoles to be non-nil")
	}
}

func TestMsfConsole_WriteRead(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer client.Consoles().Destroy(context.Background(), console.ID)

	consoleObj, err := client.Consoles().GetConsole(context.Background(), console.ID)
	if err != nil {
		t.Fatalf("GetConsole failed: %v", err)
	}

	err = consoleObj.Write(context.Background(), "help")
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var result *ConsoleReadResult
	for {
		result, err = consoleObj.Read(ctx)
		if err != nil {
			t.Errorf("Read failed: %v", err)
			break
		}
		if result.Data != "" || !result.Busy {
			break
		}
		if err := waitForPoll(ctx, defaultConsolePollInterval); err != nil {
			t.Errorf("Timed out waiting for console data: %v", err)
			break
		}
	}

	if result != nil && result.Data == "" {
		t.Log("Console data was empty (this may be OK if buffer cleared)")
	}
}

func TestMsfConsole_RunCommand(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer client.Consoles().Destroy(context.Background(), console.ID)

	consoleObj, err := client.Consoles().GetConsole(context.Background(), console.ID)
	if err != nil {
		t.Fatalf("GetConsole failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output, err := consoleObj.RunCommand(ctx, "version", 5*time.Second)
	if err != nil {
		t.Errorf("RunCommand failed: %v", err)
	}

	if output == "" {
		t.Error("Expected some output from version command")
	}
}

func TestMsfConsole_IsBusy(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer client.Consoles().Destroy(context.Background(), console.ID)

	consoleObj, err := client.Consoles().GetConsole(context.Background(), console.ID)
	if err != nil {
		t.Fatalf("GetConsole failed: %v", err)
	}

	busy, err := consoleObj.IsBusy(context.Background())
	if err != nil {
		t.Errorf("IsBusy failed: %v", err)
	}

	if busy {
		t.Log("Console is busy (this may be OK)")
	}
}

func TestMsfConsole_Tabs(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer client.Consoles().Destroy(context.Background(), console.ID)

	consoleObj, err := client.Consoles().GetConsole(context.Background(), console.ID)
	if err != nil {
		t.Fatalf("GetConsole failed: %v", err)
	}

	tabs, err := consoleObj.Tabs(context.Background(), "he")
	if err != nil {
		t.Errorf("Tabs failed: %v", err)
	}

	if tabs == nil {
		t.Log("Tabs returned nil (this may be OK)")
	}
}

func TestConsoleWrappers_FailureResultReturnsConsoleNotFound(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"result": "failure"}, nil
		},
	}

	ctx := context.Background()
	con := NewMsfConsole(rpc, "999999")

	if _, err := con.Read(ctx); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("Read: expected ErrConsoleNotFound, got %v", err)
	}
	if err := con.Write(ctx, "version"); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("Write: expected ErrConsoleNotFound, got %v", err)
	}
	if err := con.SessionKill(ctx); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("SessionKill: expected ErrConsoleNotFound, got %v", err)
	}
	if err := con.SessionDetach(ctx); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("SessionDetach: expected ErrConsoleNotFound, got %v", err)
	}
	if _, err := con.Tabs(ctx, "ver"); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("Tabs: expected ErrConsoleNotFound, got %v", err)
	}
	if err := NewConsoleManager(rpc).Destroy(ctx, "999999"); !errors.Is(err, ErrConsoleNotFound) {
		t.Errorf("Destroy: expected ErrConsoleNotFound, got %v", err)
	}
}

func TestMsfConsole_RunCommandDrainsPendingOutput(t *testing.T) {
	var reads int
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if method != ConsoleRead {
				return map[string]interface{}{}, nil
			}
			reads++
			switch reads {
			case 1:
				return map[string]interface{}{"data": "banner output\n", "prompt": "msf > ", "busy": false}, nil
			case 2:
				return map[string]interface{}{"data": "", "prompt": "msf > ", "busy": true}, nil
			case 3:
				return map[string]interface{}{"data": "command output\n", "prompt": "msf > ", "busy": false}, nil
			default:
				return map[string]interface{}{"data": "", "prompt": "msf > ", "busy": false}, nil
			}
		},
	}

	out, err := NewMsfConsole(rpc, "1").RunCommand(context.Background(), "version", 2*time.Second)
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if strings.Contains(out, "banner") {
		t.Errorf("pending banner output leaked into command output: %q", out)
	}
	if !strings.Contains(out, "command output") {
		t.Errorf("missing command output: %q", out)
	}
}

func TestMsfConsole_RunCommandCompletesWithoutFinalOutput(t *testing.T) {
	var reads int
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if method != ConsoleRead {
				return map[string]interface{}{}, nil
			}
			reads++
			switch reads {
			case 2:
				return map[string]interface{}{"data": "command output\n", "busy": true}, nil
			default:
				return map[string]interface{}{"data": "", "busy": false}, nil
			}
		},
	}

	out, err := NewMsfConsole(rpc, "1").RunCommand(context.Background(), "version", 2*time.Second)
	if err != nil {
		t.Fatalf("RunCommand failed: %v", err)
	}
	if out != "command output\n" {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestMsfConsole_RunCommandTimeoutBoundsReads(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			if method == ConsoleRead {
				select {
				case <-time.After(120 * time.Millisecond):
					return map[string]interface{}{"data": "DONE", "busy": false}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return map[string]interface{}{}, nil
		},
	}

	start := time.Now()
	_, err := NewMsfConsole(rpc, "1").RunCommand(context.Background(), "version", 20*time.Millisecond)
	if !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("expected ErrCommandTimeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("20ms timeout took %s", elapsed)
	}
}
