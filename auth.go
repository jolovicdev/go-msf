package gomsf

import (
	"context"
	"fmt"
)

type AuthManager struct {
	rpc RPCCaller
}

func NewAuthManager(rpc RPCCaller) *AuthManager {
	return &AuthManager{rpc: rpc}
}

func (m *AuthManager) TokenList(ctx context.Context) ([]string, error) {
	result, err := m.rpc.Call(ctx, AuthTokenList)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "tokens")
}

func (m *AuthManager) TokenAdd(ctx context.Context, token string) error {
	_, err := m.rpc.Call(ctx, AuthTokenAdd, token)
	return err
}

func (m *AuthManager) TokenRemove(ctx context.Context, token string) error {
	_, err := m.rpc.Call(ctx, AuthTokenRemove, token)
	return err
}

func (m *AuthManager) TokenGenerate(ctx context.Context) (string, error) {
	result, err := m.rpc.Call(ctx, AuthTokenGenerate)
	if err != nil {
		return "", err
	}

	tokenData, err := responseMap(result)
	if err != nil {
		return "", fmt.Errorf("%w: expected token response map", err)
	}

	return responseString(tokenData, "token")
}
