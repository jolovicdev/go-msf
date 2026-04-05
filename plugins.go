package gomsf

import (
	"context"
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
	_, err := m.rpc.Call(ctx, PluginLoad, plugin)
	return err
}

func (m *PluginManager) Unload(ctx context.Context, plugin string) error {
	_, err := m.rpc.Call(ctx, PluginUnload, plugin)
	return err
}
