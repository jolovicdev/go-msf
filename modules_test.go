package gomsf

import (
	"context"
	"testing"
)

func TestModuleManager_Exploits(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	exploits, err := client.Modules().Exploits(context.Background())
	if err != nil {
		t.Fatalf("Exploits failed: %v", err)
	}

	if len(exploits) == 0 {
		t.Error("Expected at least one exploit")
	}
}

func TestModuleManager_Payloads(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	payloads, err := client.Modules().Payloads(context.Background())
	if err != nil {
		t.Fatalf("Payloads failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("Expected at least one payload")
	}
}

func TestModuleManager_Auxiliary(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	aux, err := client.Modules().Auxiliary(context.Background())
	if err != nil {
		t.Fatalf("Auxiliary failed: %v", err)
	}

	if len(aux) == 0 {
		t.Error("Expected at least one auxiliary module")
	}
}

func TestModuleManager_Post(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	post, err := client.Modules().Post(context.Background())
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	if len(post) == 0 {
		t.Error("Expected at least one post module")
	}
}

func TestModuleManager_Encoders(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	encoders, err := client.Modules().Encoders(context.Background())
	if err != nil {
		t.Fatalf("Encoders failed: %v", err)
	}

	if len(encoders) == 0 {
		t.Error("Expected at least one encoder")
	}
}

func TestModuleManager_Nops(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	nops, err := client.Modules().Nops(context.Background())
	if err != nil {
		t.Fatalf("Nops failed: %v", err)
	}

	if len(nops) == 0 {
		t.Error("Expected at least one nop module")
	}
}

func TestModuleManager_Use(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	if mod.Name != "windows/smb/ms08_067_netapi" {
		t.Errorf("Expected module name to be windows/smb/ms08_067_netapi, got %s", mod.Name)
	}

	if mod.ModuleType != ExploitModuleType {
		t.Errorf("Expected module type to be exploit, got %s", mod.ModuleType)
	}
}

func TestModule_Options(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	options := mod.Options()
	if len(options) == 0 {
		t.Error("Expected at least one option")
	}

	required := mod.RequiredOptions()
	if len(required) == 0 {
		t.Log("Module has no required options (this may be OK)")
	}
}

func TestModule_SetOption(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	err = mod.SetOption("RHOSTS", "192.168.1.1")
	if err != nil {
		t.Errorf("SetOption failed: %v", err)
	}

	val, err := mod.GetOption("RHOSTS")
	if err != nil {
		t.Errorf("GetOption failed: %v", err)
	}

	if val != "192.168.1.1" {
		t.Errorf("Expected RHOSTS to be 192.168.1.1, got %v", val)
	}
}

func TestModule_SetOption_Invalid(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	err = mod.SetOption("INVALID_OPTION", "value")
	if err == nil {
		t.Error("Expected error for invalid option")
	}
}
