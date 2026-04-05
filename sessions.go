package gomsf

import (
	"context"
	"fmt"
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

	sessions, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	resultSessions := make(map[string]*Session, len(sessions))
	for id, data := range sessions {
		var session Session
		if err := decodeResult(data, &session); err != nil {
			return nil, fmt.Errorf("%w: invalid session %s", ErrUnexpectedResponse, id)
		}
		resultSessions[id] = &session
	}

	return resultSessions, nil
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
	return err
}

func (m *SessionManager) CompatibleModules(ctx context.Context, sid string) ([]string, error) {
	result, err := m.rpc.Call(ctx, SessionCompatibleModules, sid)
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

func (s *MeterpreterSession) RunWithOutput(ctx context.Context, cmd string, endStrings []string, timeout time.Duration) (string, error) {
	if err := s.Write(ctx, cmd); err != nil {
		return "", err
	}

	return s.gatherOutput(ctx, cmd, endStrings, timeout)
}

func (s *MeterpreterSession) gatherOutput(ctx context.Context, cmd string, endStrings []string, timeout time.Duration) (string, error) {
	var output string
	start := time.Now()

	for time.Since(start) < timeout {
		if err := ctx.Err(); err != nil {
			return output, err
		}

		data, err := s.Read(ctx)
		if err != nil {
			return output, err
		}
		output += data

		if endStrings == nil {
			if output != "" {
				return output, nil
			}
		} else {
			for _, endStr := range endStrings {
				if strings.Contains(output, endStr) {
					return output, nil
				}
			}
		}

		if err := waitForPoll(ctx, s.pollInterval); err != nil {
			return output, err
		}
	}

	return output, fmt.Errorf("%w: %s", ErrCommandTimeout, cmd)
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

func (s *ShellSession) RunWithOutput(ctx context.Context, cmd string, endStrings []string, timeout time.Duration) (string, error) {
	if err := s.Write(ctx, cmd); err != nil {
		return "", err
	}

	var output string
	start := time.Now()

	for time.Since(start) < timeout {
		if err := ctx.Err(); err != nil {
			return output, err
		}

		data, err := s.Read(ctx)
		if err != nil {
			return output, err
		}
		output += data

		for _, endStr := range endStrings {
			if strings.Contains(output, endStr) {
				return output, nil
			}
		}

		if err := waitForPoll(ctx, s.pollInterval); err != nil {
			return output, err
		}
	}

	return output, fmt.Errorf("%w: %s", ErrCommandTimeout, cmd)
}
