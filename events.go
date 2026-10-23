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
// Event delivery applies backpressure: when the consumer falls behind and
// the channel is full, polling pauses until the consumer drains it, so
// events are never dropped but a slow consumer slows the monitor down with
// it. Size the buffer with WithEventBuffer if consumers may stall.
//
// Session, job and watched-output polling run in separate loops, and each
// RPC is bounded by WithEventPollTimeout (30 seconds by default), so one
// stuck stream or list call does not stall the others.
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
	pollTimeout     time.Duration
	buffer          int

	mu              sync.Mutex
	watchedSessions map[string]bool
	watchedConsoles map[string]bool
	sessions        map[string]*Session

	ch chan Event
}

type EventOption func(*EventMonitor)

const (
	defaultEventBuffer         = 256
	defaultEventJobInterval    = time.Second
	defaultEventOutputInterval = 500 * time.Millisecond
	// defaultEventPollTimeout bounds one session/job list call or one
	// watched output read. Without it a monitor context without a deadline
	// would let a stuck msfrpcd response hang a poll loop indefinitely.
	defaultEventPollTimeout = 30 * time.Second
	// eventOutputConcurrency bounds the parallel reads issued for watched
	// sessions and consoles so a large watch set does not serialize into
	// one poll interval per stream or flood msfrpcd.
	eventOutputConcurrency = 8
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

// WithEventPollTimeout bounds one session/job list call or one watched output
// read. The default is 30 seconds.
func WithEventPollTimeout(timeout time.Duration) EventOption {
	return func(m *EventMonitor) {
		m.pollTimeout = timeout
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
		pollTimeout:     defaultEventPollTimeout,
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
	if m.pollTimeout <= 0 {
		m.pollTimeout = defaultEventPollTimeout
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
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		m.pollSessions(ctx)
	}()
	go func() {
		defer wg.Done()
		m.pollJobs(ctx)
	}()
	go func() {
		defer wg.Done()
		m.pollOutputStreams(ctx)
	}()
	wg.Wait()
	close(m.ch)
}

// pollSessions owns session.list and the session snapshot that output
// polling uses. It runs independently of the job and output loops so a slow
// session poll cannot delay either.
func (m *EventMonitor) pollSessions(ctx context.Context) {
	ticker := time.NewTicker(m.sessionInterval)
	defer ticker.Stop()

	last := make(map[string]*Session)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollCtx, cancel := m.pollContext(ctx)
			sessions, err := NewSessionManager(m.rpc).List(pollCtx)
			cancel()
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), Err: err})
				continue
			}
			m.setSessions(sessions)
			m.diffSessions(ctx, last, sessions)
			last = sessions
		}
	}
}

// pollJobs owns job.list and runs independently of the other polls.
func (m *EventMonitor) pollJobs(ctx context.Context) {
	ticker := time.NewTicker(m.jobInterval)
	defer ticker.Stop()

	last := make(map[string]string)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pollCtx, cancel := m.pollContext(ctx)
			jobs, err := NewJobManager(m.rpc).List(pollCtx)
			cancel()
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), Err: err})
				continue
			}
			m.diffJobs(ctx, last, jobs)
			last = jobs
		}
	}
}

// pollOutputStreams runs the watched output fan-out independently of the
// session and job list polls.
func (m *EventMonitor) pollOutputStreams(ctx context.Context) {
	ticker := time.NewTicker(m.outputInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollOutputs(ctx, m.sessionSnapshot())
		}
	}
}

// pollContext applies the monitor's per-RPC timeout. A caller context with an
// earlier deadline still wins.
func (m *EventMonitor) pollContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := m.pollTimeout
	if timeout <= 0 {
		timeout = defaultEventPollTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func (m *EventMonitor) setSessions(sessions map[string]*Session) {
	m.mu.Lock()
	m.sessions = sessions
	m.mu.Unlock()
}

func (m *EventMonitor) sessionSnapshot() map[string]*Session {
	m.mu.Lock()
	sessions := m.sessions
	m.mu.Unlock()
	return sessions
}

func (m *EventMonitor) diffSessions(ctx context.Context, last, current map[string]*Session) {
	for id, session := range current {
		if _, ok := last[id]; !ok {
			m.emit(ctx, Event{Type: EventSessionOpened, Timestamp: time.Now(), SessionID: id, Session: session})
		}
	}
	for id, session := range last {
		if _, ok := current[id]; !ok {
			// Stop output polling before announcing the close so a consumer
			// reacting to the event does not race a new read of the dead
			// session.
			m.UnwatchSession(id)
			m.emit(ctx, Event{Type: EventSessionClosed, Timestamp: time.Now(), SessionID: id, Session: session})
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

	if len(sessionIDs)+len(consoleIDs) == 0 {
		return
	}

	// One watched stream is one RPC round trip. Run a bounded number in
	// parallel and emit each event as soon as its read finishes: a slow or
	// hung stream must not hold back output already collected from the
	// others. Every read also gets the monitor's poll timeout.
	sem := make(chan struct{}, eventOutputConcurrency)
	var wg sync.WaitGroup

	acquire := func() bool {
		select {
		case sem <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	}

	for _, sid := range sessionIDs {
		// A watched session missing from the last snapshot closed between
		// refreshes; the session poll will emit session_closed and unwatch it.
		s := sessions[sid]
		if s == nil {
			continue
		}

		wg.Add(1)
		go func(sid string, sessionType string) {
			defer wg.Done()
			if !acquire() {
				return
			}
			defer func() { <-sem }()

			streamCtx, cancel := m.pollContext(ctx)
			defer cancel()

			var data string
			var err error
			if sessionType == "meterpreter" {
				data, err = NewMeterpreterSession(m.rpc, sid).Read(streamCtx)
			} else {
				data, err = NewShellSession(m.rpc, sid).Read(streamCtx)
			}
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), SessionID: sid, Err: err})
				return
			}
			if data != "" {
				m.emit(ctx, Event{Type: EventSessionOutput, Timestamp: time.Now(), SessionID: sid, Data: data})
			}
		}(sid, s.Type)
	}

	for _, cid := range consoleIDs {
		wg.Add(1)
		go func(cid string) {
			defer wg.Done()
			if !acquire() {
				return
			}
			defer func() { <-sem }()

			streamCtx, cancel := m.pollContext(ctx)
			defer cancel()

			result, err := NewMsfConsole(m.rpc, cid).Read(streamCtx)
			if err != nil {
				m.emit(ctx, Event{Type: EventError, Timestamp: time.Now(), ConsoleID: cid, Err: err})
				return
			}
			if result.Data != "" {
				m.emit(ctx, Event{Type: EventConsoleOutput, Timestamp: time.Now(), ConsoleID: cid, Data: result.Data})
			}
		}(cid)
	}

	wg.Wait()
}

func (m *EventMonitor) emit(ctx context.Context, e Event) {
	select {
	case m.ch <- e:
	case <-ctx.Done():
	}
}
