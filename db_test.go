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

func TestDbManager_Reads(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			switch method {
			case DbHosts:
				return map[string]interface{}{"hosts": []interface{}{
					map[string]interface{}{"address": "10.0.0.1", "os_name": "Linux", "name": "web01"},
				}}, nil
			case DbServices:
				return map[string]interface{}{"services": []interface{}{
					map[string]interface{}{"host": "10.0.0.1", "port": 22, "proto": "tcp", "name": "ssh", "state": "open"},
				}}, nil
			case DbVulns:
				return map[string]interface{}{"vulns": []interface{}{
					map[string]interface{}{"host": "10.0.0.1", "name": "CVE-2021-44228", "refs": "CVE-2021-44228"},
				}}, nil
			case DbLoots:
				return map[string]interface{}{"loots": []interface{}{
					map[string]interface{}{"host": "10.0.0.1", "ltype": "host.os.session", "name": "hostname", "data": "web01"},
				}}, nil
			case DbCreds:
				return map[string]interface{}{"creds": []interface{}{
					map[string]interface{}{"host": "10.0.0.1", "port": 22, "proto": "tcp", "user": "root", "pass": "toor", "type": "password"},
				}}, nil
			default:
				return nil, nil
			}
		},
	}

	ctx := context.Background()
	db := NewDbManager(rpc)

	hosts, err := db.Hosts(ctx, nil)
	if err != nil {
		t.Fatalf("Hosts failed: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Address != "10.0.0.1" || hosts[0].OSName != "Linux" {
		t.Fatalf("unexpected hosts: %+v", hosts)
	}

	services, err := db.Services(ctx, nil)
	if err != nil {
		t.Fatalf("Services failed: %v", err)
	}
	if len(services) != 1 || services[0].Port != 22 || services[0].Name != "ssh" {
		t.Fatalf("unexpected services: %+v", services)
	}

	vulns, err := db.Vulns(ctx, nil)
	if err != nil {
		t.Fatalf("Vulns failed: %v", err)
	}
	if len(vulns) != 1 || vulns[0].Name != "CVE-2021-44228" {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}

	loots, err := db.Loots(ctx, nil)
	if err != nil {
		t.Fatalf("Loots failed: %v", err)
	}
	if len(loots) != 1 || loots[0].Type != "host.os.session" {
		t.Fatalf("unexpected loots: %+v", loots)
	}

	creds, err := db.Creds(ctx, nil)
	if err != nil {
		t.Fatalf("Creds failed: %v", err)
	}
	if len(creds) != 1 || creds[0].User != "root" || creds[0].Type != "password" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestDbManager_Reads_DatabaseNotLoaded(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return nil, &RPCError{Message: "Database Not Loaded"}
		},
	}

	db := NewDbManager(rpc)
	ctx := context.Background()

	results := map[string]func() (int, error){
		"hosts":    func() (int, error) { v, err := db.Hosts(ctx, nil); return len(v), err },
		"services": func() (int, error) { v, err := db.Services(ctx, nil); return len(v), err },
		"vulns":    func() (int, error) { v, err := db.Vulns(ctx, nil); return len(v), err },
		"loots":    func() (int, error) { v, err := db.Loots(ctx, nil); return len(v), err },
		"creds":    func() (int, error) { v, err := db.Creds(ctx, nil); return len(v), err },
	}

	for name, read := range results {
		count, err := read()
		if err != nil {
			t.Fatalf("%s: expected nil error for unloaded database, got %v", name, err)
		}
		if count != 0 {
			t.Fatalf("%s: expected empty result for unloaded database, got %d", name, count)
		}
	}
}

func TestDbManager_Creds_InvalidEntry(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"creds": []interface{}{"invalid"}}, nil
		},
	}

	_, err := NewDbManager(rpc).Creds(context.Background(), nil)
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}
