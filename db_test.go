package gomsf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDbManager_Status(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	status, err := client.DB().Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if status == nil {
		t.Log("Status returned nil (database may not be connected)")
	}
}

func TestDbManager_CurrentWorkspace(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	workspace, err := client.DB().CurrentWorkspace(context.Background())
	if err != nil {
		t.Fatalf("CurrentWorkspace failed: %v", err)
	}

	t.Logf("Current workspace: %s", workspace)
}

func TestWorkspaceManager_List(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	workspaces, err := client.DB().Workspaces().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if workspaces == nil {
		t.Log("Workspaces is nil (database may not be connected)")
	}
}

func TestWorkspaceManager_AddRemove(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	wsName := "test_workspace_go_msf"

	err := client.DB().Workspaces().Add(context.Background(), wsName)
	if err != nil {
		if !isDBUnavailableError(err) {
			t.Fatalf("Add workspace failed: %v", err)
		}
		return
	}

	err = client.DB().Workspaces().Remove(context.Background(), wsName)
	if err != nil {
		t.Errorf("Remove workspace failed: %v", err)
	}
}

func TestWorkspaceManager_Current(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ws, err := client.DB().Workspaces().Current(context.Background())
	if err != nil {
		t.Fatalf("Current failed: %v", err)
	}

	if ws == nil {
		t.Log("Current workspace is nil (database may not be connected)")
	}
}

func TestDbManager_SetWorkspace(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	err := client.DB().SetWorkspace(context.Background(), "default")
	if err != nil {
		if !isDBUnavailableError(err) {
			t.Fatalf("SetWorkspace failed: %v", err)
		}
	}
}

func isDBUnavailableError(err error) bool {
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		return false
	}

	return strings.Contains(rpcErr.Message, "Database Not Loaded") ||
		strings.Contains(rpcErr.Message, "No connection pool")
}
