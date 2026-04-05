/*
Package gomsf provides a Go client for Metasploit's RPC API.

The package is organized around a Client plus manager types for each RPC
domain, including core operations, modules, consoles, sessions, jobs,
plugins, authentication, and database access.

Typical usage starts with NewClient or NewClientWithToken, then accesses
managers from the client:

	client, err := gomsf.NewClient("password", gomsf.WithSSL(false))
	if err != nil {
		return err
	}

	version, err := client.Core().Version(ctx)
	if err != nil {
		return err
	}

The package prefers explicit failures over silent coercion. Malformed RPC
payloads return ErrUnexpectedResponse. Structured Metasploit RPC failures
return *RPCError and match ErrRPC. Command helper methods for consoles and
sessions return ErrCommandTimeout on timeout. Module option validation
errors match ErrInvalidOption.

Live Metasploit integration tests are opt-in through RUN_MSF_INTEGRATION=1.
*/
package gomsf
