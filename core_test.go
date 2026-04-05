package gomsf

import (
	"context"
	"testing"
)

func TestCoreManager_Version(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	version, err := client.Core().Version(context.Background())
	if err != nil {
		t.Fatalf("Version failed: %v", err)
	}

	if version.Version == "" {
		t.Error("Expected version to be non-empty")
	}

	if version.APIVersion == "" {
		t.Error("Expected API version to be non-empty")
	}
}

func TestCoreManager_ModuleStats(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	stats, err := client.Core().ModuleStats(context.Background())
	if err != nil {
		t.Fatalf("ModuleStats failed: %v", err)
	}

	if stats == nil {
		t.Error("Expected stats to be non-nil")
	}
}

func TestCoreManager_SetGlobal(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	err := client.Core().SetGlobal(context.Background(), "TEST_VAR", "test_value")
	if err != nil {
		t.Errorf("SetGlobal failed: %v", err)
	}

	err = client.Core().UnsetGlobal(context.Background(), "TEST_VAR")
	if err != nil {
		t.Errorf("UnsetGlobal failed: %v", err)
	}
}

func TestCoreManager_Save(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	err := client.Core().Save(context.Background())
	if err != nil {
		t.Errorf("Save failed: %v", err)
	}
}

func TestCoreManager_ReloadModules(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	err := client.Core().ReloadModules(context.Background())
	if err != nil {
		t.Errorf("ReloadModules failed: %v", err)
	}
}
