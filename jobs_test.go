package gomsf

import (
	"context"
	"errors"
	"testing"
)

func TestJobManager_List(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	jobs, err := client.Jobs().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if jobs == nil {
		t.Error("Expected jobs to be non-nil")
	}
}

func TestJobManager_Info_NotFound(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	info, err := client.Jobs().Info(context.Background(), "99999")
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected ErrJobNotFound, got: %v", err)
	}

	if info != nil {
		t.Fatalf("expected nil info for non-existent job, got: %#v", info)
	}
}
