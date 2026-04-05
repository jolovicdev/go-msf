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
