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
sessions return ErrCommandTimeout. Module option validation errors match
ErrInvalidOption.

Clients created with NewClient recover automatically when msfrpcd rejects
their token (after a restart or token removal): the call re-authenticates
once and retries. Clients created with NewClientWithToken have no stored
password and surface the RPC error instead.

Client.Events starts an EventMonitor that polls session.list, job.list and
any watched session or console output streams, and emits state changes on a
channel. It is the intended foundation for UIs and automation:

	monitor := client.Events(ctx)

	for event := range monitor.C() {
		switch event.Type {
		case gomsf.EventSessionOpened:
			monitor.WatchSession(event.SessionID)
		case gomsf.EventSessionOutput:
			fmt.Print(event.Data)
		}
	}

Note that the monitor consumes output: watching a session or console
transfers ownership of its output stream, because the underlying RPC reads
drain the server-side buffer.

Live Metasploit integration tests are opt-in through RUN_MSF_INTEGRATION=1.
*/
package gomsf
