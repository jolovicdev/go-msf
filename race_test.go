package gomsf

import (
	"context"
	"sync"
	"testing"
)

func TestConcurrent_ClientAccess(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10
	numCalls := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numCalls; j++ {
				_, err := client.Core().Version(ctx)
				if err != nil {
					t.Errorf("goroutine %d call %d: Version failed: %v", id, j, err)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestConcurrent_ModuleOperations(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()
	var wg sync.WaitGroup

	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_, err := client.Modules().Exploits(ctx)
			if err != nil {
				t.Errorf("Exploits failed: %v", err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_, err := client.Modules().Payloads(ctx)
			if err != nil {
				t.Errorf("Payloads failed: %v", err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			_, err := client.Modules().Auxiliary(ctx)
			if err != nil {
				t.Errorf("Auxiliary failed: %v", err)
			}
		}
	}()

	wg.Wait()
}

func TestConcurrent_ConsoleOperations(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()

	console, err := client.Consoles().Create(ctx)
	if err != nil {
		t.Fatalf("Create console failed: %v", err)
	}
	defer client.Consoles().Destroy(ctx, console.ID)

	con, err := client.Consoles().GetConsole(ctx, console.ID)
	if err != nil {
		t.Fatalf("GetConsole failed: %v", err)
	}

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := con.IsBusy(ctx)
			if err != nil {
				t.Errorf("IsBusy failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestConcurrent_MixedOperations(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	ctx := context.Background()
	var wg sync.WaitGroup

	operations := []func(){
		func() { client.Core().Version(ctx) },
		func() { client.Modules().Exploits(ctx) },
		func() { client.Sessions().List(ctx) },
		func() { client.Jobs().List(ctx) },
		func() { client.Plugins().List(ctx) },
		func() { client.Auth().TokenList(ctx) },
		func() { client.DB().Status(ctx) },
	}

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				op := operations[(id+j)%len(operations)]
				op()
			}
		}(i)
	}

	wg.Wait()
}
