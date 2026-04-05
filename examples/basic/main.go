package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	gomsf "github.com/jolovicdev/go-msf"
)

func main() {
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
			log.Fatalf("Invalid MSF_PORT: %v", err)
		}
		port = parsed
	}

	ssl := os.Getenv("MSF_SSL") != "false"

	client, err := gomsf.NewClient(password,
		gomsf.WithHost(host),
		gomsf.WithPort(port),
		gomsf.WithSSL(ssl),
		gomsf.WithUsername(username),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Logout(context.Background())

	fmt.Println("Connected to Metasploit RPC")

	version, err := client.Core().Version(context.Background())
	if err != nil {
		log.Fatalf("Failed to get version: %v", err)
	}
	fmt.Printf("Version: %s (Ruby: %s, API: %s)\n", version.Version, version.RubyVersion, version.APIVersion)

	workspaces, err := client.DB().Workspaces().List(context.Background())
	if err != nil {
		fmt.Printf("Database workspaces unavailable: %v\n", err)
	} else {
		fmt.Printf("Workspaces: %v\n", workspaces)
	}

	current, err := client.DB().CurrentWorkspace(context.Background())
	if err != nil {
		fmt.Printf("Current workspace unavailable: %v\n", err)
	} else {
		fmt.Printf("Current workspace: %s\n", current)
	}

	exploits, err := client.Modules().Exploits(context.Background())
	if err != nil {
		log.Fatalf("Failed to list exploits: %v", err)
	}
	fmt.Printf("Available exploits: %d\n", len(exploits))

	sessions, err := client.Sessions().List(context.Background())
	if err != nil {
		log.Fatalf("Failed to list sessions: %v", err)
	}
	fmt.Printf("Active sessions: %d\n", len(sessions))

	console, err := client.Consoles().Create(context.Background())
	if err != nil {
		log.Fatalf("Failed to create console: %v", err)
	}
	fmt.Printf("Created console: %s\n", console.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	consoleObj, err := client.Consoles().GetConsole(ctx, console.ID)
	if err != nil {
		log.Fatalf("Failed to get console: %v", err)
	}
	output, err := consoleObj.RunCommand(ctx, "help", 5*time.Second)
	if err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}
	fmt.Printf("Console output:\n%s\n", output)

	if err := client.Consoles().Destroy(context.Background(), console.ID); err != nil {
		log.Fatalf("Failed to destroy console: %v", err)
	}
	fmt.Println("Console destroyed")
}
