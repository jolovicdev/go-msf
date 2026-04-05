package gomsf

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_FullWorkflow(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	version, err := client.Core().Version(ctx)
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}
	t.Logf("Connected to Metasploit %s", version.Version)

	exploits, err := client.Modules().Exploits(ctx)
	if err != nil {
		t.Fatalf("Failed to list exploits: %v", err)
	}
	if len(exploits) == 0 {
		t.Error("No exploits found")
	}

	aux, err := client.Modules().Auxiliary(ctx)
	if err != nil {
		t.Fatalf("Failed to list auxiliary modules: %v", err)
	}
	if len(aux) == 0 {
		t.Error("No auxiliary modules found")
	}

	mod, err := client.Modules().Use(ctx, AuxiliaryModuleType, "scanner/portscan/tcp")
	if err != nil {
		t.Fatalf("Failed to load module: %v", err)
	}

	options := mod.Options()
	if len(options) == 0 {
		t.Error("Module has no options")
	}

	required := mod.RequiredOptions()
	t.Logf("Module has %d required options", len(required))

	mod.SetOption("RHOSTS", "127.0.0.1")
	mod.SetOption("PORTS", "1-100")

	val, _ := mod.GetOption("RHOSTS")
	if val != "127.0.0.1" {
		t.Errorf("Expected RHOSTS to be 127.0.0.1, got %v", val)
	}

	sessions, err := client.Sessions().List(ctx)
	if err != nil {
		t.Fatalf("Failed to list sessions: %v", err)
	}
	t.Logf("Found %d active sessions", len(sessions))

	jobs, err := client.Jobs().List(ctx)
	if err != nil {
		t.Fatalf("Failed to list jobs: %v", err)
	}
	t.Logf("Found %d jobs", len(jobs))

	console, err := client.Consoles().Create(ctx)
	if err != nil {
		t.Fatalf("Failed to create console: %v", err)
	}
	t.Logf("Created console %s", console.ID)

	con, err := client.Consoles().GetConsole(ctx, console.ID)
	if err != nil {
		t.Fatalf("Failed to get console: %v", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	output, err := con.RunCommand(ctx2, "show auxiliary", 10*time.Second)
	if err != nil {
		t.Errorf("RunCommand failed: %v", err)
	}
	if output == "" {
		t.Error("Expected output from console command")
	}

	err = client.Consoles().Destroy(ctx, console.ID)
	if err != nil {
		t.Errorf("Failed to destroy console: %v", err)
	}

	workspaces, err := client.DB().Workspaces().List(ctx)
	if err != nil {
		t.Logf("Workspaces list failed (DB may not be connected): %v", err)
	} else {
		t.Logf("Found %d workspaces", len(workspaces))
	}

	tokens, err := client.Auth().TokenList(ctx)
	if err != nil {
		t.Fatalf("Failed to list tokens: %v", err)
	}
	t.Logf("Found %d tokens", len(tokens))

	t.Log("Integration test completed successfully")
}
