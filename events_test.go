package gomsf

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const eventTestInterval = 5 * time.Millisecond

func waitForEvent(t *testing.T, ch <-chan Event, typ EventType) Event {
	t.Helper()

	deadline := time.After(2 * time.Second)
	return receiveEvent(t, ch, typ, deadline)
}

func waitForLiveEvent(t *testing.T, ch <-chan Event, typ EventType) Event {
	t.Helper()

	deadline := time.After(20 * time.Second)
	return receiveEvent(t, ch, typ, deadline)
}

func receiveEvent(t *testing.T, ch <-chan Event, typ EventType, deadline <-chan time.Time) Event {
	t.Helper()

	for {
		select {
		case e, ok := <-ch:
			if !ok {
				t.Fatalf("event channel closed while waiting for %s", typ)
			}
			if e.Type == typ {
				return e
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", typ)
		}
	}
}

func newEventTestRPC(t *testing.T, mu *sync.Mutex, call func(method MsfRpcMethod) (interface{}, error)) fakeRPCCaller {
	t.Helper()

	return fakeRPCCaller{call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
		mu.Lock()
		defer mu.Unlock()
		return call(method)
	}}
}

func TestEventMonitor_SessionOpenClose(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]interface{}{}

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			out := make(map[string]interface{}, len(sessions))
			for k, v := range sessions {
				out[k] = v
			}
			return out, nil
		case JobList:
			return map[string]interface{}{}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)

	mu.Lock()
	sessions["1"] = map[string]interface{}{"type": "shell", "desc": "cmd"}
	mu.Unlock()

	opened := waitForEvent(t, monitor.C(), EventSessionOpened)
	if opened.Session == nil || opened.Session.Type != "shell" {
		t.Fatalf("expected opened session of type shell, got %+v", opened.Session)
	}

	mu.Lock()
	delete(sessions, "1")
	mu.Unlock()

	closed := waitForEvent(t, monitor.C(), EventSessionClosed)
	if closed.Session == nil || closed.Session.Desc != "cmd" {
		t.Fatalf("expected closed session with original snapshot, got %+v", closed.Session)
	}
}

func TestEventMonitor_JobStartStop(t *testing.T) {
	var mu sync.Mutex
	jobs := map[string]interface{}{}

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			return map[string]interface{}{}, nil
		case JobList:
			out := make(map[string]interface{}, len(jobs))
			for k, v := range jobs {
				out[k] = v
			}
			return out, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)

	mu.Lock()
	jobs["0"] = "Exploit handler"
	mu.Unlock()

	started := waitForEvent(t, monitor.C(), EventJobStarted)
	if started.Job == nil || started.Job.ID != "0" || started.Job.Name != "Exploit handler" {
		t.Fatalf("expected job 0 started, got %+v", started.Job)
	}

	mu.Lock()
	delete(jobs, "0")
	mu.Unlock()

	stopped := waitForEvent(t, monitor.C(), EventJobStopped)
	if stopped.Job == nil || stopped.Job.ID != "0" {
		t.Fatalf("expected job 0 stopped, got %+v", stopped.Job)
	}
}

func TestEventMonitor_WatchedSessionOutput(t *testing.T) {
	var mu sync.Mutex
	shellReads := 0
	meterpreterReads := 0
	sessions := map[string]interface{}{
		"1": map[string]interface{}{"type": "shell"},
		"2": map[string]interface{}{"type": "meterpreter"},
	}

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			out := make(map[string]interface{}, len(sessions))
			for k, v := range sessions {
				out[k] = v
			}
			return out, nil
		case JobList:
			return map[string]interface{}{}, nil
		case SessionShellRead:
			shellReads++
			if shellReads == 1 {
				return map[string]interface{}{"data": "whoami\n"}, nil
			}
			return map[string]interface{}{"data": ""}, nil
		case SessionMeterpreterRead:
			meterpreterReads++
			if meterpreterReads == 1 {
				return map[string]interface{}{"data": "sysinfo\n"}, nil
			}
			return map[string]interface{}{"data": ""}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)
	monitor.WatchSession("1")
	monitor.WatchSession("2")

	shellOut := waitForEvent(t, monitor.C(), EventSessionOutput)
	if shellOut.SessionID != "1" || shellOut.Data != "whoami\n" {
		t.Fatalf("expected shell output for session 1, got %+v", shellOut)
	}

	meterpreterOut := waitForEvent(t, monitor.C(), EventSessionOutput)
	if meterpreterOut.SessionID != "2" || meterpreterOut.Data != "sysinfo\n" {
		t.Fatalf("expected meterpreter output for session 2, got %+v", meterpreterOut)
	}
}

func TestEventMonitor_WatchedConsoleOutput(t *testing.T) {
	var mu sync.Mutex
	reads := 0

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList, JobList:
			return map[string]interface{}{}, nil
		case ConsoleRead:
			reads++
			if reads == 1 {
				return map[string]interface{}{"data": "workspace\n", "prompt": "msf6 > ", "busy": false}, nil
			}
			return map[string]interface{}{"data": "", "prompt": "msf6 > ", "busy": false}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)
	monitor.WatchConsole("7")

	out := waitForEvent(t, monitor.C(), EventConsoleOutput)
	if out.ConsoleID != "7" || out.Data != "workspace\n" {
		t.Fatalf("expected console output for console 7, got %+v", out)
	}
}

func TestEventMonitor_UnwatchedSessionsAreNotRead(t *testing.T) {
	var mu sync.Mutex
	reads := 0

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			return map[string]interface{}{}, nil
		case JobList:
			return map[string]interface{}{}, nil
		case SessionShellRead, SessionMeterpreterRead:
			reads++
			return map[string]interface{}{"data": ""}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if reads != 0 {
		t.Fatalf("expected no session reads without watchers, got %d", reads)
	}
}

func TestEventMonitor_ClosedSessionStopsBeingRead(t *testing.T) {
	var mu sync.Mutex
	sessions := map[string]interface{}{
		"1": map[string]interface{}{"type": "shell"},
	}
	reads := 0

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			out := make(map[string]interface{}, len(sessions))
			for k, v := range sessions {
				out[k] = v
			}
			return out, nil
		case JobList:
			return map[string]interface{}{}, nil
		case SessionShellRead:
			reads++
			return map[string]interface{}{"data": ""}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)
	monitor.WatchSession("1")

	waitForEvent(t, monitor.C(), EventSessionOpened)

	mu.Lock()
	delete(sessions, "1")
	mu.Unlock()

	waitForEvent(t, monitor.C(), EventSessionClosed)

	mu.Lock()
	readsAfterClose := reads
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if reads > readsAfterClose {
		t.Fatalf("expected reads to stop after session close, got %d after close", reads-readsAfterClose)
	}
}

func TestEventMonitor_PollErrorEmitsErrorEvent(t *testing.T) {
	var mu sync.Mutex

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		switch method {
		case SessionList:
			return nil, errors.New("poll failed")
		case JobList:
			return map[string]interface{}{}, nil
		default:
			return map[string]interface{}{}, nil
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)

	e := waitForEvent(t, monitor.C(), EventError)
	if e.Err == nil || e.Err.Error() != "poll failed" {
		t.Fatalf("expected poll error event, got %+v", e)
	}
}

func TestEventMonitor_ContextCancelClosesChannel(t *testing.T) {
	var mu sync.Mutex

	rpc := newEventTestRPC(t, &mu, func(method MsfRpcMethod) (interface{}, error) {
		return map[string]interface{}{}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())

	monitor := NewEventMonitor(ctx, rpc,
		WithEventSessionInterval(eventTestInterval),
		WithEventJobInterval(eventTestInterval),
		WithEventOutputInterval(eventTestInterval),
	)

	cancel()

	select {
	case _, ok := <-monitor.C():
		if ok {
			t.Fatal("expected channel to be closed, got event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}
