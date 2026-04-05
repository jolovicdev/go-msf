package gomsf

import (
	"context"
)

type CoreManager struct {
	rpc RPCCaller
}

func NewCoreManager(rpc RPCCaller) *CoreManager {
	return &CoreManager{rpc: rpc}
}

func (m *CoreManager) Version(ctx context.Context) (*VersionInfo, error) {
	result, err := m.rpc.Call(ctx, CoreVersion)
	if err != nil {
		return nil, err
	}

	var info VersionInfo
	if err := decodeResult(result, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (m *CoreManager) Stop(ctx context.Context) error {
	_, err := m.rpc.Call(ctx, CoreStop)
	return err
}

func (m *CoreManager) SetGlobal(ctx context.Context, key, value string) error {
	_, err := m.rpc.Call(ctx, CoreSetG, key, value)
	return err
}

func (m *CoreManager) UnsetGlobal(ctx context.Context, key string) error {
	_, err := m.rpc.Call(ctx, CoreUnsetG, key)
	return err
}

func (m *CoreManager) Save(ctx context.Context) error {
	_, err := m.rpc.Call(ctx, CoreSave)
	return err
}

func (m *CoreManager) ReloadModules(ctx context.Context) error {
	_, err := m.rpc.Call(ctx, CoreReloadModules)
	return err
}

func (m *CoreManager) ModuleStats(ctx context.Context) (map[string]interface{}, error) {
	result, err := m.rpc.Call(ctx, CoreModuleStats)
	if err != nil {
		return nil, err
	}

	return responseMap(result)
}

func (m *CoreManager) AddModulePath(ctx context.Context, path string) error {
	_, err := m.rpc.Call(ctx, CoreAddModulePath, path)
	return err
}

func (m *CoreManager) ThreadList(ctx context.Context) (map[string]interface{}, error) {
	result, err := m.rpc.Call(ctx, CoreThreadList)
	if err != nil {
		return nil, err
	}

	return responseMap(result)
}

func (m *CoreManager) KillThread(ctx context.Context, threadID string) error {
	_, err := m.rpc.Call(ctx, CoreThreadKill, threadID)
	return err
}
