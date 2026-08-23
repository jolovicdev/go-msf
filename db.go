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
	result, err := m.rpc.Call(ctx, DbDriver, map[string]interface{}{})
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

// The db.* read methods take an options hash. Recognized keys include
// "workspace", "limit" and "offset"; a nil opts queries the current
// workspace. See the Metasploit RPC documentation for per-method filters.
func dbOptions(opts map[string]interface{}) map[string]interface{} {
	if opts == nil {
		return map[string]interface{}{}
	}
	return opts
}

func (m *DbManager) Hosts(ctx context.Context, opts map[string]interface{}) ([]*Host, error) {
	result, err := m.rpc.Call(ctx, DbHosts, dbOptions(opts))
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return decodeList[Host](result, "hosts")
}

func (m *DbManager) Services(ctx context.Context, opts map[string]interface{}) ([]*Service, error) {
	result, err := m.rpc.Call(ctx, DbServices, dbOptions(opts))
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return decodeList[Service](result, "services")
}

func (m *DbManager) Vulns(ctx context.Context, opts map[string]interface{}) ([]*Vuln, error) {
	result, err := m.rpc.Call(ctx, DbVulns, dbOptions(opts))
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return decodeList[Vuln](result, "vulns")
}

func (m *DbManager) Loots(ctx context.Context, opts map[string]interface{}) ([]*Loot, error) {
	result, err := m.rpc.Call(ctx, DbLoots, dbOptions(opts))
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return decodeList[Loot](result, "loots")
}

func (m *DbManager) Creds(ctx context.Context, opts map[string]interface{}) ([]*Credential, error) {
	result, err := m.rpc.Call(ctx, DbCreds, dbOptions(opts))
	if err != nil {
		if rpcErrorMessage(err, "Database Not Loaded") {
			return nil, nil
		}
		return nil, err
	}

	return decodeList[Credential](result, "creds")
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

	workspaces, err := decodeList[Workspace](result, "workspaces")
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(workspaces))
	for _, w := range workspaces {
		names = append(names, w.Name)
	}
	return names, nil
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

	workspaceList, ok := data["workspace"].([]interface{})
	if !ok || len(workspaceList) == 0 {
		return nil, fmt.Errorf("%w: expected workspace list", ErrUnexpectedResponse)
	}

	var workspace Workspace
	if err := decodeResult(workspaceList[0], &workspace); err != nil {
		return nil, err
	}

	return &workspace, nil
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
