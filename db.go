package gomsf

import (
	"context"
	"fmt"
)

type DbManager struct {
	rpc RPCCaller
}

func NewDbManager(rpc RPCCaller) *DbManager {
	return &DbManager{rpc: rpc}
}

func (m *DbManager) Status(ctx context.Context) (map[string]interface{}, error) {
	result, err := m.rpc.Call(ctx, DbStatus)
	if err != nil {
		return nil, err
	}

	return responseMap(result)
}

func (m *DbManager) Connect(ctx context.Context, opts map[string]interface{}) error {
	result, err := m.rpc.Call(ctx, DbConnect, opts)
	if err != nil {
		return err
	}

	res, err := responseMap(result)
	if err != nil {
		return err
	}

	status, err := responseString(res, "result")
	if err != nil {
		return err
	}
	if status != "success" {
		return fmt.Errorf("db connect failed: %s", status)
	}

	return nil
}

func (m *DbManager) Disconnect(ctx context.Context) error {
	_, err := m.rpc.Call(ctx, DbDisconnect)
	return err
}

func (m *DbManager) Driver(ctx context.Context) (string, error) {
	result, err := m.rpc.Call(ctx, DbDriver)
	if err != nil {
		return "", err
	}

	data, err := responseMap(result)
	if err != nil {
		return "", err
	}

	return responseString(data, "driver")
}

func (m *DbManager) Workspaces() *WorkspaceManager {
	return NewWorkspaceManager(m.rpc)
}

func (m *DbManager) CurrentWorkspace(ctx context.Context) (string, error) {
	result, err := m.rpc.Call(ctx, DbCurrentWorkspace)
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return "", nil
		}
		return "", err
	}

	data, err := responseMap(result)
	if err != nil {
		return "", err
	}

	return responseString(data, "workspace")
}

func (m *DbManager) SetWorkspace(ctx context.Context, name string) error {
	_, err := m.rpc.Call(ctx, DbSetWorkspace, name)
	return err
}

type WorkspaceManager struct {
	rpc RPCCaller
}

func NewWorkspaceManager(rpc RPCCaller) *WorkspaceManager {
	return &WorkspaceManager{rpc: rpc}
}

func (m *WorkspaceManager) List(ctx context.Context) ([]string, error) {
	result, err := m.rpc.Call(ctx, DbWorkspaces)
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return responseStringSlice(result, "workspaces")
}

func (m *WorkspaceManager) Add(ctx context.Context, name string) error {
	_, err := m.rpc.Call(ctx, DbAddWorkspace, name)
	return err
}

func (m *WorkspaceManager) Remove(ctx context.Context, name string) error {
	_, err := m.rpc.Call(ctx, DbDelWorkspace, name)
	return err
}

func (m *WorkspaceManager) Get(ctx context.Context, name string) (*Workspace, error) {
	result, err := m.rpc.Call(ctx, DbGetWorkspace, name)
	if err != nil {
		return nil, err
	}

	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	workspaceData, ok := data["workspace"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected workspace map", ErrUnexpectedResponse)
	}

	name, err = responseString(workspaceData, "name")
	if err != nil {
		return nil, err
	}

	return &Workspace{Name: name}, nil
}

func (m *WorkspaceManager) Current(ctx context.Context) (*Workspace, error) {
	result, err := m.rpc.Call(ctx, DbCurrentWorkspace)
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	data, err := responseMap(result)
	if err != nil {
		return nil, err
	}

	name, err := responseString(data, "workspace")
	if err != nil {
		return nil, err
	}
	return &Workspace{Name: name}, nil
}
