package gomsf

import (
	"context"
	"fmt"
)

type PluginManager struct {
	rpc RPCCaller
}

func NewPluginManager(rpc RPCCaller) *PluginManager {
	return &PluginManager{rpc: rpc}
}

func (m *PluginManager) List(ctx context.Context) ([]string, error) {
	result, err := m.rpc.Call(ctx, PluginLoaded)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "plugins")
}

func (m *PluginManager) Load(ctx context.Context, plugin string) error {
	result, err := m.rpc.Call(ctx, PluginLoad, plugin)
	if err != nil {
		return err
	}
	if responseResultFailure(result) {
		return fmt.Errorf("failed to load plugin %s", plugin)
	}
	return nil
}

func (m *PluginManager) Unload(ctx context.Context, plugin string) error {
	result, err := m.rpc.Call(ctx, PluginUnload, plugin)
	if err != nil {
		return err
	}
	if responseResultFailure(result) {
		return fmt.Errorf("failed to unload plugin %s", plugin)
	}
	return nil
}
