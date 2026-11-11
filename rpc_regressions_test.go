package gomsf

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// installReauthAttempt parks a shared re-authentication attempt on the client
// so a waiter's path can be exercised without network I/O.
func installReauthAttempt(client *Client, token string) *reauthAttempt {
	attempt := &reauthAttempt{done: make(chan struct{}), token: token}
	client.reauthMu.Lock()
	client.reauth = attempt
	client.reauthMu.Unlock()
	return attempt
}

// TestClientReauthWaiterUsesNewestToken reproduces a waiter that wakes after
// another caller has already refreshed the token again. Retrying with the
// completed attempt's token fails with "Invalid Token"; the waiter must use
// the newest token instead.
func TestClientReauthWaiterUsesNewestToken(t *testing.T) {
	tests := []struct {
		name         string
		currentToken string
		want         string
	}{
		{
			// A second refresh completed while the waiter was asleep, so the
			// client already holds a token newer than the attempt's.
			name:         "newer token",
			currentToken: "token-3",
			want:         "token-3",
		},
		{
			// Logout cleared the client token while the login was in flight.
			// The documented behavior is that the retrying caller still gets
			// the attempt's fresh token, which is what makes its call work.
			name:         "logged out",
			currentToken: "",
			want:         "token-2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClientWithToken("token-1")
			if err != nil {
				t.Fatalf("NewClientWithToken failed: %v", err)
			}

			attempt := installReauthAttempt(client, "token-2")

			client.tokenMu.Lock()
			client.token = tc.currentToken
			client.tokenMu.Unlock()

			var (
				token     string
				reauthErr error
				done      = make(chan struct{})
			)
			go func() {
				token, reauthErr = client.reloginIfStale(context.Background(), "token-1")
				close(done)
			}()

			// Wake the waiter after the newer token state is published.
			close(attempt.done)

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("waiter did not return")
			}

			if reauthErr != nil {
				t.Fatalf("reloginIfStale failed: %v", reauthErr)
			}
			if token != tc.want {
				t.Fatalf("waiter retried with %q, want %q", token, tc.want)
			}
		})
	}
}

// TestConsoleUnmarshalMsgpackIdentifierForms covers direct msgpack decoding
// of a console whose ID arrives as a raw binary string, the form msfrpcd puts
// on the wire. String and integer IDs must keep working.
func TestConsoleUnmarshalMsgpackIdentifierForms(t *testing.T) {
	tests := []struct {
		name    string
		id      interface{}
		want    string
		wantErr bool
	}{
		{name: "binary", id: []byte("3"), want: "3"},
		{name: "string", id: "3", want: "3"},
		{name: "integer", id: 3, want: "3"},
		{name: "empty binary", id: []byte(""), wantErr: true},
		{name: "missing", id: nil, wantErr: true},
		{name: "boolean", id: true, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := msgpack.Marshal(map[string]interface{}{
				"id":     tc.id,
				"prompt": "msf6 > ",
				"busy":   true,
			})
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			var console Console
			err = msgpack.Unmarshal(payload, &console)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for id %#v, got console %+v", tc.id, console)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalMsgpack failed for id %#v: %v", tc.id, err)
			}
			if console.ID != tc.want {
				t.Fatalf("ID = %q, want %q", console.ID, tc.want)
			}
			if console.Prompt != "msf6 > " || !console.Busy {
				t.Fatalf("unexpected console fields: %+v", console)
			}
		})
	}
}

// TestSessionManagerListRejectsNilResult guards against a nil session.list
// result decoding into an empty map and being reported as a successful empty
// session table.
func TestSessionManagerListRejectsNilResult(t *testing.T) {
	tests := []struct {
		name   string
		result interface{}
	}{
		{name: "nil result", result: nil},
		{name: "typed nil map", result: map[string]interface{}(nil)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rpc := fakeRPCCaller{
				call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
					return tc.result, nil
				},
			}

			sessions, err := NewSessionManager(rpc).List(context.Background())
			if !errors.Is(err, ErrUnexpectedResponse) {
				t.Fatalf("expected ErrUnexpectedResponse, got sessions %v and err %v", sessions, err)
			}
		})
	}
}

func TestSessionManagerListAcceptsEmptyMap(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{}, nil
		},
	}

	sessions, err := NewSessionManager(rpc).List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if sessions == nil {
		t.Fatal("expected an empty non-nil session map")
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no sessions, got %v", sessions)
	}
}
