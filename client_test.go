package gomsf

import (
	"context"
	"os"
	"strconv"
	"testing"
)

func getTestClient(t *testing.T) *Client {
	t.Helper()

	if os.Getenv("RUN_MSF_INTEGRATION") != "1" {
		t.Skip("set RUN_MSF_INTEGRATION=1 to run live Metasploit RPC tests")
	}

	password := os.Getenv("MSF_PASSWORD")
	if password == "" {
		password = "testpass123"
	}

	username := os.Getenv("MSF_USERNAME")
	if username == "" {
		username = "msf"
	}

	host := os.Getenv("MSF_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	port := 55553
	if p := os.Getenv("MSF_PORT"); p != "" {
		parsed, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("Failed to parse port: %v", err)
		}
		port = parsed
	}

	ssl := os.Getenv("MSF_SSL") != "false"

	client, err := NewClient(password,
		WithHost(host),
		WithPort(port),
		WithSSL(ssl),
		WithUsername(username),
	)
	if err != nil {
		t.Fatalf("Failed to connect to msfrpcd: %v", err)
	}

	return client
}

func TestNewClient(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	if !client.IsAuthenticated() {
		t.Error("Expected client to be authenticated")
	}

	if client.Token() == "" {
		t.Error("Expected token to be set")
	}
}

func TestClient_Call_Unauthenticated(t *testing.T) {
	c := &Client{
		host: "127.0.0.1",
		port: 55553,
		uri:  "/api/",
		ssl:  false,
	}

	_, err := c.Call(context.Background(), CoreVersion)
	if err != ErrNotAuthenticated {
		t.Errorf("Expected ErrNotAuthenticated, got: %v", err)
	}
}

func TestClient_Logout(t *testing.T) {
	client := getTestClient(t)

	err := client.Logout(context.Background())
	if err != nil {
		t.Errorf("Logout failed: %v", err)
	}

	if client.IsAuthenticated() {
		t.Error("Expected client to be unauthenticated after logout")
	}
}
