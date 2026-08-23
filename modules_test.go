package gomsf

import (
	"context"
	"errors"
	"testing"
)

func TestModuleManager_Exploits(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	exploits, err := client.Modules().Exploits(context.Background())
	if err != nil {
		t.Fatalf("Exploits failed: %v", err)
	}

	if len(exploits) == 0 {
		t.Error("Expected at least one exploit")
	}
}

func TestModuleManager_Payloads(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	payloads, err := client.Modules().Payloads(context.Background())
	if err != nil {
		t.Fatalf("Payloads failed: %v", err)
	}

	if len(payloads) == 0 {
		t.Error("Expected at least one payload")
	}
}

func TestModuleManager_Auxiliary(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	aux, err := client.Modules().Auxiliary(context.Background())
	if err != nil {
		t.Fatalf("Auxiliary failed: %v", err)
	}

	if len(aux) == 0 {
		t.Error("Expected at least one auxiliary module")
	}
}

func TestModuleManager_Post(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	post, err := client.Modules().Post(context.Background())
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	if len(post) == 0 {
		t.Error("Expected at least one post module")
	}
}

func TestModuleManager_Encoders(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	encoders, err := client.Modules().Encoders(context.Background())
	if err != nil {
		t.Fatalf("Encoders failed: %v", err)
	}

	if len(encoders) == 0 {
		t.Error("Expected at least one encoder")
	}
}

func TestModuleManager_Nops(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	nops, err := client.Modules().Nops(context.Background())
	if err != nil {
		t.Fatalf("Nops failed: %v", err)
	}

	if len(nops) == 0 {
		t.Error("Expected at least one nop module")
	}
}

func TestModuleManager_Use(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	if mod.Name != "windows/smb/ms08_067_netapi" {
		t.Errorf("Expected module name to be windows/smb/ms08_067_netapi, got %s", mod.Name)
	}

	if mod.ModuleType != ExploitModuleType {
		t.Errorf("Expected module type to be exploit, got %s", mod.ModuleType)
	}
}

func TestModule_Options(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	options := mod.Options()
	if len(options) == 0 {
		t.Error("Expected at least one option")
	}

	required := mod.RequiredOptions()
	if len(required) == 0 {
		t.Log("Module has no required options (this may be OK)")
	}
}

func TestModule_SetOption(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	err = mod.SetOption("RHOSTS", "192.168.1.1")
	if err != nil {
		t.Errorf("SetOption failed: %v", err)
	}

	val, err := mod.GetOption("RHOSTS")
	if err != nil {
		t.Errorf("GetOption failed: %v", err)
	}

	if val != "192.168.1.1" {
		t.Errorf("Expected RHOSTS to be 192.168.1.1, got %v", val)
	}
}

func TestModule_SetOption_Invalid(t *testing.T) {
	client := getTestClient(t)
	defer client.Logout(context.Background())

	mod, err := client.Modules().Use(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	err = mod.SetOption("INVALID_OPTION", "value")
	if err == nil {
		t.Error("Expected error for invalid option")
	}
}

func TestModuleManager_Info(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"name":        "MS08-067 Microsoft Server Service Relative Path Stack Corruption",
				"description": "This module exploits a parsing flaw...",
				"rank":        "great",
				"authors":     []interface{}{"hdm", "skape"},
				"targets": map[string]interface{}{
					"0": "Automatic",
					"2": "Windows 2003 Universal",
					"1": "Windows 2000 Universal",
				},
				"references": []interface{}{
					[]interface{}{"CVE", "2008-4250"},
					[]interface{}{"MSB", "MS08-067"},
				},
			}, nil
		},
	}

	info, err := NewModuleManager(rpc).Info(context.Background(), ExploitModuleType, "windows/smb/ms08_067_netapi")
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}

	if info.Name == "" || info.Rank != "great" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if len(info.Authors) != 2 || info.Authors[0] != "hdm" {
		t.Fatalf("unexpected authors: %v", info.Authors)
	}
	if len(info.Targets) != 3 || info.Targets[0] != "Automatic" || info.Targets[2] != "Windows 2003 Universal" {
		t.Fatalf("expected targets in index order, got %v", info.Targets)
	}
	if len(info.References) != 2 {
		t.Fatalf("unexpected references: %+v", info.References)
	}
	if info.References[0].Type != "CVE" || info.References[0].Value != "2008-4250" {
		t.Fatalf("unexpected reference: %+v", info.References[0])
	}
}

func TestModuleManager_Info_InvalidReference(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			return map[string]interface{}{
				"references": []interface{}{"CVE-2008-4250"},
			}, nil
		},
	}

	_, err := NewModuleManager(rpc).Info(context.Background(), ExploitModuleType, "test/module")
	if !errors.Is(err, ErrUnexpectedResponse) {
		t.Fatalf("expected ErrUnexpectedResponse, got %v", err)
	}
}

func TestModuleManager_CompatiblePayloadsSessions(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			switch method {
			case ModuleCompatiblePayloads:
				return map[string]interface{}{"payloads": []interface{}{"windows/meterpreter/reverse_tcp"}}, nil
			case ModuleCompatibleSessions:
				return map[string]interface{}{"sessions": []interface{}{"1", "2"}}, nil
			default:
				return nil, nil
			}
		},
	}

	ctx := context.Background()
	mm := NewModuleManager(rpc)

	payloads, err := mm.CompatiblePayloads(ctx, "windows/smb/ms08_067_netapi")
	if err != nil || len(payloads) != 1 || payloads[0] != "windows/meterpreter/reverse_tcp" {
		t.Fatalf("unexpected payloads: %v %v", payloads, err)
	}

	sessions, err := mm.CompatibleSessions(ctx, "post/multi/manage/shell_to_meterpreter")
	if err != nil || len(sessions) != 2 || sessions[1] != "2" {
		t.Fatalf("unexpected sessions: %v %v", sessions, err)
	}
}

func TestNewModuleWithContext_FillsInfo(t *testing.T) {
	rpc := fakeRPCCaller{
		call: func(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error) {
			switch method {
			case ModuleOptions:
				return map[string]interface{}{
					"RHOSTS": map[string]interface{}{"type": "string", "required": true, "desc": "The target address range"},
				}, nil
			case ModuleInfo:
				return map[string]interface{}{
					"name": "TCP Port Scanner",
					"rank": "normal",
				}, nil
			default:
				return nil, nil
			}
		},
	}

	mod, err := NewModuleManager(rpc).Use(context.Background(), AuxiliaryModuleType, "scanner/portscan/tcp")
	if err != nil {
		t.Fatalf("Use failed: %v", err)
	}

	if mod.Info == nil || mod.Info.Name != "TCP Port Scanner" || mod.Info.Rank != "normal" {
		t.Fatalf("expected module info to be filled, got %+v", mod.Info)
	}
}
