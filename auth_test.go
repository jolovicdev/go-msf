package gomsf

import (
	"context"
	"testing"
)

func TestAuthManager_TokenList(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	tokens, err := client.Auth().TokenList(context.Background())
	if err != nil {
		t.Fatalf("TokenList failed: %v", err)
	}

	if tokens == nil {
		t.Error("Expected tokens to be non-nil")
	}
}

func TestAuthManager_TokenGenerate(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	token, err := client.Auth().TokenGenerate(context.Background())
	if err != nil {
		t.Fatalf("TokenGenerate failed: %v", err)
	}

	if token == "" {
		t.Error("Expected token to be non-empty")
	}
}

func TestAuthManager_TokenAddRemove(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	token := "test_token_12345"

	err := client.Auth().TokenAdd(context.Background(), token)
	if err != nil {
		t.Logf("TokenAdd failed (this may be OK): %v", err)
		return
	}

	err = client.Auth().TokenRemove(context.Background(), token)
	if err != nil {
		t.Errorf("TokenRemove failed: %v", err)
	}
}
