package gomsf

import (
	"context"
	"testing"
)

func TestPluginManager_List(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	plugins, err := client.Plugins().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if plugins == nil {
		t.Error("Expected plugins to be non-nil")
	}
}

func TestPluginManager_FailureResultReturnsError(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{"result": "failure"}, nil
		},
	}

	if err := NewPluginManager(rpc).Load(context.Background(), "nonexistent"); err == nil {
		t.Error("Expected load failure to return an error")
	}

	if err := NewPluginManager(rpc).Unload(context.Background(), "nonexistent"); err == nil {
		t.Error("Expected unload failure to return an error")
	}
}
