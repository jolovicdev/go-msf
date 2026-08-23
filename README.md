# go-msf

[![Go Reference](https://pkg.go.dev/badge/github.com/jolovicdev/go-msf.svg)](https://pkg.go.dev/github.com/jolovicdev/go-msf)
[![Go Report Card](https://goreportcard.com/badge/github.com/jolovicdev/go-msf)](https://goreportcard.com/report/github.com/jolovicdev/go-msf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)](https://github.com/jolovicdev/go-msf/releases)

> Production-ready Go client for the Metasploit Framework RPC API. Automate penetration testing, security research, and red team operations with type-safe Go.

`go-msf` is a modern, idiomatic Go library for interacting with [Metasploit's RPC API](https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/). Build security automation tools, CI/CD security pipelines, and custom exploit frameworks with clean, type-safe Go code.

## Features

- **Complete RPC Coverage** — Core, modules, consoles, sessions, jobs, plugins, auth, and database operations
- **Event Monitoring** — `Client.Events` polls sessions, jobs and watched output streams and emits state changes on a channel; the foundation for UIs and automation
- **Automatic Re-auth** — Clients built with `NewClient` re-authenticate once and retry when msfrpcd invalidates their token
- **Type-Safe API** — Strongly typed requests and responses with validation
- **Context Support** — Full `context.Context` integration for timeouts and cancellation
- **Error Handling** — Structured error types for RPC failures, timeouts, and validation errors
- **Concurrent-Safe** — Designed for safe use across goroutines
- **Zero Dependencies** — Minimal external dependencies (only msgpack for RPC encoding)

## Installation

```bash
go get github.com/jolovicdev/go-msf
```

Requires Go 1.26 or later.

## Version

**v2.0.0** — See [releases](https://github.com/jolovicdev/go-msf/releases) for changes. Versioning follows [Semantic Versioning](https://semver.org/).

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	gomsf "github.com/jolovicdev/go-msf"
)

func main() {
	ctx := context.Background()

	client, err := gomsf.NewClient(
		"yourpassword",
		gomsf.WithHost("127.0.0.1"),
		gomsf.WithPort(55553),
		gomsf.WithSSL(false),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Logout(ctx)

	version, err := client.Core().Version(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Metasploit v%s connected\n", version.Version)
}
```

## Prerequisites

### Starting Metasploit RPC

Using `msfrpcd` (recommended for production):

```bash
msfrpcd -P yourpassword -S -f
```

With explicit bind options:

```bash
msfrpcd -P yourpassword -a 127.0.0.1 -p 55553 -S -f
```

From `msfconsole` (for development):

```
load msgrpc Pass=yourpassword
```

## API Documentation

### Client Configuration

```go
// Password authentication
client, err := gomsf.NewClient(password, options...)

// Token authentication (if you already have a token)
client, err := gomsf.NewClientWithToken(token, options...)
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `WithHost(host)` | `127.0.0.1` | RPC server host |
| `WithPort(port)` | `55553` | RPC server port |
| `WithURI(uri)` | `/api/` | RPC endpoint path |
| `WithSSL(enabled)` | `true` | Use HTTPS (disable with `false`) |
| `WithUsername(username)` | `msf` | RPC username |
| `WithHTTPClient(client)` | `http.DefaultClient` | Custom HTTP client |
| `WithConsolePollInterval(d)` | `500ms` | Console polling interval |
| `WithSessionPollInterval(d)` | `1s` | Session polling interval |

### Core Operations

```go
version, err := client.Core().Version(ctx)
stats, err := client.Core().ModuleStats(ctx)
threads, err := client.Core().ThreadList(ctx)
err = client.Core().ReloadModules(ctx)
```

### Module Management

```go
// List available modules
exploits, err := client.Modules().Exploits(ctx)
payloads, err := client.Modules().Payloads(ctx)
aux, err := client.Modules().Auxiliary(ctx)

// Use a module
mod, err := client.Modules().Use(ctx, gomsf.ExploitModuleType, "windows/smb/ms08_067_netapi")
if err != nil {
    return err
}

// Set options
if err := mod.SetOption("RHOSTS", "192.168.1.10"); err != nil {
    return err
}

// Execute
result, err := mod.Execute(ctx)
```

### Console Operations

```go
console, err := client.Consoles().Create(ctx)
if err != nil {
    return err
}
defer client.Consoles().Destroy(ctx, console.ID)

con, err := client.Consoles().GetConsole(ctx, console.ID)
if err != nil {
    return err
}

output, err := con.RunCommand(ctx, "show exploits", 10*time.Second)
```

### Session Management

```go
sessions, err := client.Sessions().List(ctx)
session, err := client.Sessions().Get(ctx, "1")
err = client.Sessions().Stop(ctx, "1")

// Meterpreter interaction
meterpreter := gomsf.NewMeterpreterSession(client, "1")
output, err := meterpreter.RunWithOutput(ctx, "getuid", []string{">"}, 30*time.Second)
```

### Jobs

```go
jobs, err := client.Jobs().List(ctx)
info, err := client.Jobs().Info(ctx, "0")
err = client.Jobs().Stop(ctx, "0")
```

### Plugins

```go
plugins, err := client.Plugins().List(ctx)
err = client.Plugins().Load(ctx, "plugin_name")
err = client.Plugins().Unload(ctx, "plugin_name")
```

### Database

```go
status, err := client.DB().Status(ctx)
driver, err := client.DB().Driver(ctx)
workspace, err := client.DB().CurrentWorkspace(ctx)
workspaces, err := client.DB().Workspaces().List(ctx)
```

## Error Handling

The library provides structured error types for reliable error handling:

| Error | Description |
|-------|-------------|
| `ErrNotAuthenticated` | Call requires authentication but client has no token |
| `ErrUnexpectedResponse` | Metasploit returned malformed/unexpected data |
| `ErrCommandTimeout` | Console or session command timed out |
| `ErrSessionNotFound` | Session ID does not exist |
| `ErrConsoleNotFound` | Console ID does not exist |
| `ErrInvalidOption` | Invalid module option or enum value |
| `ErrJobNotFound` | Job ID does not exist |
| `ErrRPC` | Metasploit returned structured RPC error |

Handle RPC errors:

```go
var rpcErr *gomsf.RPCError
if errors.Is(err, gomsf.ErrRPC) && errors.As(err, &rpcErr) {
    fmt.Printf("RPC Error: %s - %s\n", rpcErr.Class, rpcErr.Message)
}
```

## Testing

Run unit tests:

```bash
go test ./...
```

Run integration tests (requires running Metasploit RPC):

```bash
export RUN_MSF_INTEGRATION=1
export MSF_PASSWORD=testpass123
export MSF_USERNAME=msf
export MSF_HOST=127.0.0.1
export MSF_PORT=55553
export MSF_SSL=false

go test -v ./...
```

## Security Considerations

- **SSL/TLS**: The library defaults to SSL enabled. Use `WithSSL(false)` only in trusted development environments.
- **Self-Signed Certificates**: When using self-signed certs, provide a custom `*http.Client` with appropriate TLS configuration via `WithHTTPClient()`.
- **Credentials**: Never hardcode credentials. Use environment variables or secure secret management.

## Examples

See the [examples](https://github.com/jolovicdev/go-msf/tree/main/examples) directory for complete working examples.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Related Projects

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — The world's most used penetration testing framework
- [pymetasploit3](https://github.com/DanMcInerney/pymetasploit3) — Python3 library for Metasploit RPC

## License

MIT License — see [LICENSE](LICENSE) for details.

Copyright (c) 2026 Dušan Jolović

---

**Keywords**: metasploit golang, metasploit rpc client, go penetration testing, security automation, red team tools, metasploit api, exploit framework go, security research tools, msfrpcd client, golang offensive security