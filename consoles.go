package gomsf

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ConsoleManager struct {
	rpc RPCCaller
}

func NewConsoleManager(rpc RPCCaller) *ConsoleManager {
	return &ConsoleManager{rpc: rpc}
}

func (m *ConsoleManager) List(ctx context.Context) ([]*Console, error) {
	result, err := m.rpc.Call(ctx, ConsoleList)
	if err != nil {
		return nil, err
	}

	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	consoles, ok := data["consoles"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected consoles list", ErrUnexpectedResponse)
	}

	resultConsoles := make([]*Console, len(consoles))
	for i, c := range consoles {
		var console Console
		if err := decodeResult(c, &console); err != nil {
			return nil, fmt.Errorf("%w: invalid console entry at index %d", ErrUnexpectedResponse, i)
		}
		resultConsoles[i] = &console
	}

	return resultConsoles, nil
}

func (m *ConsoleManager) Create(ctx context.Context) (*Console, error) {
	result, err := m.rpc.Call(ctx, ConsoleCreate)
	if err != nil {
		return nil, err
	}

	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	id, err := responseString(data, "id")
	if err != nil {
		return nil, err
	}

	return &Console{
		ID: id,
	}, nil
}

func (m *ConsoleManager) Destroy(ctx context.Context, cid string) error {
	_, err := m.rpc.Call(ctx, ConsoleDestroy, cid)
	return err
}

func (m *ConsoleManager) GetConsole(ctx context.Context, cid string) (*MsfConsole, error) {
	return NewMsfConsole(m.rpc, cid), nil
}

type MsfConsole struct {
	rpc          RPCCaller
	CID          string
	pollInterval time.Duration
}

func NewMsfConsole(rpc RPCCaller, cid string) *MsfConsole {
	pollInterval := defaultConsolePollInterval
	if provider, ok := rpc.(interface{ consolePollIntervalValue() time.Duration }); ok {
		pollInterval = provider.consolePollIntervalValue()
	}

	return &MsfConsole{rpc: rpc, CID: cid, pollInterval: pollInterval}
}

func (c *MsfConsole) Read(ctx context.Context) (*ConsoleReadResult, error) {
	result, err := c.rpc.Call(ctx, ConsoleRead, c.CID)
	if err != nil {
		return nil, err
	}

	var readResult ConsoleReadResult
	if err := decodeResult(result, &readResult); err != nil {
		return nil, err
	}

	return &readResult, nil
}

func (c *MsfConsole) Write(ctx context.Context, command string) error {
	if !strings.HasSuffix(command, "\n") {
		command += "\n"
	}
	_, err := c.rpc.Call(ctx, ConsoleWrite, c.CID, command)
	return err
}

func (c *MsfConsole) SessionKill(ctx context.Context) error {
	_, err := c.rpc.Call(ctx, ConsoleSessionKill, c.CID)
	return err
}

func (c *MsfConsole) SessionDetach(ctx context.Context) error {
	_, err := c.rpc.Call(ctx, ConsoleSessionDetach, c.CID)
	return err
}

func (c *MsfConsole) Tabs(ctx context.Context, line string) ([]string, error) {
	result, err := c.rpc.Call(ctx, ConsoleTabs, c.CID, line)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "tabs")
}

func (c *MsfConsole) IsBusy(ctx context.Context) (bool, error) {
	consoles, err := NewConsoleManager(c.rpc).List(ctx)
	if err != nil {
		return false, err
	}

	for _, console := range consoles {
		if console.ID == c.CID {
			return console.Busy, nil
		}
	}

	return false, ErrConsoleNotFound
}

func (c *MsfConsole) RunCommand(ctx context.Context, command string, timeout time.Duration) (string, error) {
	if err := c.Write(ctx, command); err != nil {
		return "", err
	}

	start := time.Now()
	var output string

	for time.Since(start) < timeout {
		if err := ctx.Err(); err != nil {
			return output, err
		}

		result, err := c.Read(ctx)
		if err != nil {
			return output, err
		}
		output += result.Data

		if !result.Busy && result.Data != "" {
			return output, nil
		}

		if err := waitForPoll(ctx, c.pollInterval); err != nil {
			return output, err
		}
	}

	return output, fmt.Errorf("%w: %s", ErrCommandTimeout, command)
}
