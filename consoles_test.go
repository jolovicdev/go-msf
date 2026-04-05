package gomsf

import (
	"context"
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
