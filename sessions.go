package gomsf

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type SessionManager struct {
	rpc RPCCaller
}

func NewSessionManager(rpc RPCCaller) *SessionManager {
	return &SessionManager{rpc: rpc}
}

func (m *SessionManager) List(ctx context.Context) (map[string]*Session, error) {
	result, err := m.rpc.Call(ctx, SessionList)
	if err != nil {
		return nil, err
	}

	// Decode the whole map in one pass; decoding each session separately
	// re-serialized every entry and scaled poorly with large session tables.
	sessions := make(map[string]*Session)
	if err := decodeResult(result, &sessions); err != nil {
		return nil, err
	}
	for id, session := range sessions {
		if session == nil {
			return nil, fmt.Errorf("%w: nil session %s", ErrUnexpectedResponse, id)
		}
	}

	return sessions, nil
}

func (m *SessionManager) Get(ctx context.Context, sid string) (*Session, error) {
	sessions, err := m.List(ctx)
	if err != nil {
		return nil, err
	}

	session, ok := sessions[sid]
	if !ok {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (m *SessionManager) Stop(ctx context.Context, sid string) error {
	_, err := m.rpc.Call(ctx, SessionStop, sid)
	if err != nil && rpcErrorMessage(err, "Unknown Session ID") {
		return fmt.Errorf("%w: %s", ErrSessionNotFound, sid)
	}
	return err
}

func (m *SessionManager) CompatibleModules(ctx context.Context, sid string) ([]string, error) {
	// The server indexes sessions by integer ID and does not convert a
	// string argument, so a string ID would silently match nothing.
	id, err := strconv.Atoi(sid)
	if err != nil {
		return nil, fmt.Errorf("invalid session id %q: %w", sid, err)
	}

	result, err := m.rpc.Call(ctx, SessionCompatibleModules, id)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "modules")
}

type MeterpreterSession struct {
	rpc          RPCCaller
	SID          string
	pollInterval time.Duration
}

func NewMeterpreterSession(rpc RPCCaller, sid string) *MeterpreterSession {
	pollInterval := defaultSessionPollInterval
	if provider, ok := rpc.(interface{ sessionPollIntervalValue() time.Duration }); ok {
		pollInterval = provider.sessionPollIntervalValue()
	}

	return &MeterpreterSession{rpc: rpc, SID: sid, pollInterval: pollInterval}
}

func (s *MeterpreterSession) Read(ctx context.Context) (string, error) {
	result, err := s.rpc.Call(ctx, SessionMeterpreterRead, s.SID)
	if err != nil {
		return "", err
	}

	data, err := responseMap(result)
	if err != nil {
		return "", err
	}

	return responseString(data, "data")
}

func (s *MeterpreterSession) Write(ctx context.Context, data string) error {
	if !strings.HasSuffix(data, "\n") {
		data += "\n"
	}
	_, err := s.rpc.Call(ctx, SessionMeterpreterWrite, s.SID, data)
	return err
}

func (s *MeterpreterSession) RunSingle(ctx context.Context, cmd string) (string, error) {
	_, err := s.rpc.Call(ctx, SessionMeterpreterRunSingle, s.SID, cmd)
	if err != nil {
		return "", err
	}
	if err := waitForPoll(ctx, s.pollInterval); err != nil {
		return "", err
	}
	return s.Read(ctx)
}

func (s *MeterpreterSession) RunScript(ctx context.Context, path string) (string, error) {
	_, err := s.rpc.Call(ctx, SessionMeterpreterScript, s.SID, path)
	if err != nil {
		return "", err
	}
	if err := waitForPoll(ctx, s.pollInterval); err != nil {
		return "", err
	}
	return s.Read(ctx)
}

func (s *MeterpreterSession) Detach(ctx context.Context) error {
	_, err := s.rpc.Call(ctx, SessionMeterpreterSessionDetach, s.SID)
	return err
}

func (s *MeterpreterSession) Kill(ctx context.Context) error {
	_, err := s.rpc.Call(ctx, SessionMeterpreterSessionKill, s.SID)
	return err
}

func (s *MeterpreterSession) Tabs(ctx context.Context, line string) ([]string, error) {
	result, err := s.rpc.Call(ctx, SessionMeterpreterTabs, s.SID, line)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "tabs")
}

func (s *MeterpreterSession) DirectorySeparator(ctx context.Context) (string, error) {
	result, err := s.rpc.Call(ctx, SessionMeterpreterDirectorySeparator, s.SID)
	if err != nil {
		return "", err
	}

	data, err := responseMap(result)
	if err != nil {
		return "", err
	}

	return responseString(data, "separator")
}

// RunWithOutput writes cmd and collects output until one of endStrings
// appears in it, or until any output arrives when endStrings is empty. The
// timeout bounds the whole helper: the write, every read and every poll
// wait.
func (s *MeterpreterSession) RunWithOutput(parent context.Context, cmd string, endStrings []string, timeout time.Duration) (string, error) {
	return runSessionCommand(parent, cmd, endStrings, timeout, s.pollInterval,
		func(ctx context.Context) error { return s.Write(ctx, cmd) },
		s.Read,
	)
}

type ShellSession struct {
	rpc          RPCCaller
	SID          string
	pollInterval time.Duration
}

func NewShellSession(rpc RPCCaller, sid string) *ShellSession {
	pollInterval := defaultSessionPollInterval
	if provider, ok := rpc.(interface{ sessionPollIntervalValue() time.Duration }); ok {
		pollInterval = provider.sessionPollIntervalValue()
	}

	return &ShellSession{rpc: rpc, SID: sid, pollInterval: pollInterval}
}

func (s *ShellSession) Read(ctx context.Context) (string, error) {
	result, err := s.rpc.Call(ctx, SessionShellRead, s.SID)
	if err != nil {
		return "", err
	}

	data, err := responseMap(result)
	if err != nil {
		return "", err
	}

	return responseString(data, "data")
}

func (s *ShellSession) Write(ctx context.Context, data string) error {
	if !strings.HasSuffix(data, "\n") {
		data += "\n"
	}
	_, err := s.rpc.Call(ctx, SessionShellWrite, s.SID, data)
	return err
}

func (s *ShellSession) Upgrade(ctx context.Context, lhost string, lport int) error {
	_, err := s.rpc.Call(ctx, SessionShellUpgrade, s.SID, lhost, lport)
	return err
}

// RunWithOutput writes cmd and collects output until one of endStrings
// appears in it, or until any output arrives when endStrings is empty. The
// timeout bounds the whole helper: the write, every read and every poll
// wait.
func (s *ShellSession) RunWithOutput(parent context.Context, cmd string, endStrings []string, timeout time.Duration) (string, error) {
	return runSessionCommand(parent, cmd, endStrings, timeout, s.pollInterval,
		func(ctx context.Context) error { return s.Write(ctx, cmd) },
		s.Read,
	)
}

// runSessionCommand is the polling loop shared by shell and meterpreter
// command helpers. Output accumulates in a byte slice, and each new chunk is
// searched only in the window that a match completing in it can start. The
// accumulator is never converted back to a string for scanning, so no step is
// proportional to the whole output on every read.
func runSessionCommand(
	parent context.Context,
	cmd string,
	endStrings []string,
	timeout time.Duration,
	interval time.Duration,
	write func(context.Context) error,
	read func(context.Context) (string, error),
) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if err := write(ctx); err != nil {
		return "", commandTimeoutError(parent, ctx, cmd, err)
	}

	ends := make([][]byte, len(endStrings))
	for i, end := range endStrings {
		ends[i] = []byte(end)
	}

	var output []byte
	previousLen := 0
	for {
		data, err := read(ctx)
		if err != nil {
			return string(output), commandTimeoutError(parent, ctx, cmd, err)
		}

		if data != "" {
			output = append(output, data...)
			if len(ends) == 0 {
				return string(output), nil
			}
			if outputContainsEnd(output, previousLen, ends) {
				return string(output), nil
			}
			previousLen = len(output)
		}

		if err := waitForPoll(ctx, interval); err != nil {
			return string(output), commandTimeoutError(parent, ctx, cmd, err)
		}
	}
}

// outputContainsEnd reports whether any end marker appears in output, which
// has previousLen bytes of already-scanned content followed by new data. A
// match that is complete now and was not complete before must start no
// earlier than previousLen-len(marker)+1, so only that suffix is rescanned.
func outputContainsEnd(output []byte, previousLen int, ends [][]byte) bool {
	for _, end := range ends {
		start := previousLen - len(end) + 1
		if start < 0 {
			start = 0
		}
		if bytes.Contains(output[start:], end) {
			return true
		}
	}
	return false
}
