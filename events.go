package gomsf

import (
	"context"
	"sync"
	"time"
)

type EventType string

const (
	EventSessionOpened EventType = "session_opened"
	EventSessionClosed EventType = "session_closed"
	EventSessionOutput EventType = "session_output"
	EventConsoleOutput EventType = "console_output"
	EventJobStarted    EventType = "job_started"
	EventJobStopped    EventType = "job_stopped"
	EventError         EventType = "error"
)

// Event is one state change observed by an EventMonitor. Which fields are set
// depends on Type: SessionID and Session for session_opened/session_closed,
// SessionID and Data for session_output, ConsoleID and Data for
// console_output, Job for job_started/job_stopped, Err for error.
type Event struct {
	Type      EventType
	Timestamp time.Time
	Session   *Session
	SessionID string
	ConsoleID string
	Job       *Job
	Data      string
	Err       error
}

// EventMonitor polls session.list, job.list and watched output streams, and
// emits the resulting state changes on a channel. Sessions already open when
// the monitor starts are reported as session_opened, so a late-attaching UI
// receives the full current state.
//
// Watching a session or console transfers ownership of its output to the
// monitor: session.shell_read / session.meterpreter_read / console.read drain
// the server-side buffer, so a watched stream must only be read through the
// monitor's events.
type EventMonitor struct {
	rpc             RPCCaller
	sessionInterval time.Duration
	jobInterval     time.Duration
	outputInterval  time.Duration
	buffer          int

	mu              sync.Mutex
	watchedSessions map[string]bool
	watchedConsoles map[string]bool

	ch chan Event
}

type EventOption func(*EventMonitor)

const (
	defaultEventBuffer         = 256
	defaultEventJobInterval    = time.Second
	defaultEventOutputInterval = 500 * time.Millisecond
)

func WithEventSessionInterval(interval time.Duration) EventOption {
	return func(m *EventMonitor) {
		m.sessionInterval = interval
	}
}

func WithEventJobInterval(interval time.Duration) EventOption {
	return func(m *EventMonitor) {
		m.jobInterval = interval
	}
}

func WithEventOutputInterval(interval time.Duration) EventOption {
	return func(m *EventMonitor) {
		m.outputInterval = interval
	}
}

func WithEventBuffer(size int) EventOption {
	return func(m *EventMonitor) {
		m.buffer = size
	}
}

// Events starts an EventMonitor against the connected msfrpcd. Cancel ctx to
// stop it; the returned channel is closed after the monitor stops.
func (c *Client) Events(ctx context.Context, opts ...EventOption) *EventMonitor {
	return NewEventMonitor(ctx, c, opts...)
}

func NewEventMonitor(ctx context.Context, rpc RPCCaller, opts ...EventOption) *EventMonitor {
	m := &EventMonitor{
		rpc:             rpc,
		sessionInterval: defaultSessionPollInterval,
		jobInterval:     defaultEventJobInterval,
		outputInterval:  defaultEventOutputInterval,
		buffer:          defaultEventBuffer,
		watchedSessions: make(map[string]bool),
		watchedConsoles: make(map[string]bool),
	}

	for _, opt := range opts {
		opt(m)
	}
	if m.sessionInterval <= 0 {
		m.sessionInterval = defaultSessionPollInterval
	}
	if m.jobInterval <= 0 {
		m.jobInterval = defaultEventJobInterval
	}
	if m.outputInterval <= 0 {
		m.outputInterval = defaultEventOutputInterval
	}
	if m.buffer <= 0 {
		m.buffer = defaultEventBuffer
	}

	m.ch = make(chan Event, m.buffer)
	go m.run(ctx)

	return m
}

// C returns the event channel. It is closed when the monitor stops.
func (m *EventMonitor) C() <-chan Event {
	return m.ch
}

// WatchSession adds a session to the polled output streams.
func (m *EventMonitor) WatchSession(sid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchedSessions[sid] = true
}

// UnwatchSession removes a session from the polled output streams.
func (m *EventMonitor) UnwatchSession(sid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.watchedSessions, sid)
}

// WatchConsole adds a console to the polled output streams.
func (m *EventMonitor) WatchConsole(cid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.watchedConsoles[cid] = true
}

// UnwatchConsole removes a console from the polled output streams.
func (m *EventMonitor) UnwatchConsole(cid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.watchedConsoles, cid)
}

func (m *EventMonitor) run(ctx context.Context) {
	defer close(m.ch)

	sessionTicker := time.NewTicker(m.sessionInterval)
	defer sessionTicker.Stop()
	jobTicker := time.NewTicker(m.jobInterval)
	defer jobTicker.Stop()
	outputTicker := time.NewTicker(m.outputInterval)
	defer outputTicker.Stop()

	lastSessions := make(map[string]*Session)
	lastJobs := make(map[string]string)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sessionTicker.C:
			sessions, err := NewSessionManager(m.rpc).List(ctx)
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), Err: err})
				continue
			}
			m.diffSessions(ctx, lastSessions, sessions)
			lastSessions = sessions
		case <-jobTicker.C:
			jobs, err := NewJobManager(m.rpc).List(ctx)
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), Err: err})
				continue
			}
			m.diffJobs(ctx, lastJobs, jobs)
			lastJobs = jobs
		case <-outputTicker.C:
			m.pollOutputs(ctx, lastSessions)
		}
	}
}

func (m *EventMonitor) diffSessions(ctx context.Context, last, current map[string]*Session) {
	for id, session := range current {
		if _, ok := last[id]; !ok {
			m.emit(ctx, Event{Type: EventSessionOpened, Timestamp: time.Now(), SessionID: id, Session: session})
		}
	}
	for id, session := range last {
		if _, ok := current[id]; !ok {
			m.emit(ctx, Event{Type: EventSessionClosed, Timestamp: time.Now(), SessionID: id, Session: session})
			m.UnwatchSession(id)
		}
	}
}

func (m *EventMonitor) diffJobs(ctx context.Context, last, current map[string]string) {
	for id, name := range current {
		if _, ok := last[id]; !ok {
			m.emit(ctx, Event{Type: EventJobStarted, Timestamp: time.Now(), Job: &Job{ID: id, Name: name}})
		}
	}
	for id, name := range last {
		if _, ok := current[id]; !ok {
			m.emit(ctx, Event{Type: EventJobStopped, Timestamp: time.Now(), Job: &Job{ID: id, Name: name}})
		}
	}
}

func (m *EventMonitor) pollOutputs(ctx context.Context, sessions map[string]*Session) {
	m.mu.Lock()
	sessionIDs := make([]string, 0, len(m.watchedSessions))
	for sid := range m.watchedSessions {
		sessionIDs = append(sessionIDs, sid)
	}
	consoleIDs := make([]string, 0, len(m.watchedConsoles))
	for cid := range m.watchedConsoles {
		consoleIDs = append(consoleIDs, cid)
	}
	m.mu.Unlock()

	for _, sid := range sessionIDs {
		// A watched session missing from the last snapshot closed between
		// refreshes; the session poll will emit session_closed and unwatch it.
		s := sessions[sid]
		if s == nil {
			continue
		}

		var data string
		var err error
		if s.Type == "meterpreter" {
			data, err = NewMeterpreterSession(m.rpc, sid).Read(ctx)
		} else {
			data, err = NewShellSession(m.rpc, sid).Read(ctx)
		}
		if err != nil {
			m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), SessionID: sid, Err: err})
			continue
		}
		if data != "" {
			m.emit(ctx, Event{Type: EventSessionOutput, Timestamp: time.Now(), SessionID: sid, Data: data})
		}
	}

	for _, cid := range consoleIDs {
		result, err := NewMsfConsole(m.rpc, cid).Read(ctx)
		if err != nil {
			m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), ConsoleID: cid, Err: err})
			continue
		}
		if result.Data != "" {
			m.emit(ctx, Event{Type: EventConsoleOutput, Timestamp: time.Now(), ConsoleID: cid, Data: result.Data})
		}
	}
}

func (m *EventMonitor) emit(ctx context.Context, e Event) {
	select {
	case m.ch <- e:
	case <-ctx.Done():
	}
}
