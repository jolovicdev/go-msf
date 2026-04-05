package gomsf

import (
	"context"
	"testing"
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
