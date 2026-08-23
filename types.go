package gomsf

import (
	"context"
	"errors"
)

var (
	ErrNotAuthenticated   = errors.New("not authenticated")
	ErrInvalidOption      = errors.New("invalid module option")
	ErrSessionNotFound    = errors.New("session not found")
	ErrConsoleNotFound    = errors.New("console not found")
	ErrJobNotFound        = errors.New("job not found")
	ErrUnexpectedResponse = errors.New("unexpected rpc response")
	ErrCommandTimeout     = errors.New("command timeout")
	ErrRPC                = errors.New("rpc error")
)

type RPCError struct {
	Class   string
	Message string
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	if e.Class == "" {
		return e.Message
	}
	return e.Class + ": " + e.Message
}

func (e *RPCError) Unwrap() error {
	return ErrRPC
}

type ModuleType string

const (
	ExploitModuleType   ModuleType = "exploit"
	PayloadModuleType   ModuleType = "payload"
	AuxiliaryModuleType ModuleType = "auxiliary"
	PostModuleType      ModuleType = "post"
	EncoderModuleType   ModuleType = "encoder"
	NopModuleType       ModuleType = "nop"
	EvasionModuleType   ModuleType = "evasion"
)

type RPCCaller interface {
	Call(ctx context.Context, method MsfRpcMethod, args ...interface{}) (interface{}, error)
}

type VersionInfo struct {
	Version     string `msgpack:"version" json:"version"`
	RubyVersion string `msgpack:"ruby" json:"ruby"`
	APIVersion  string `msgpack:"api" json:"api"`
}

type Workspace struct {
	Name string `msgpack:"name" json:"name"`
}

type Console struct {
	ID     string `msgpack:"id" json:"id"`
	Prompt string `msgpack:"prompt" json:"prompt"`
	Busy   bool   `msgpack:"busy" json:"busy"`
}

type ConsoleReadResult struct {
	Data   string `msgpack:"data" json:"data"`
	Prompt string `msgpack:"prompt" json:"prompt"`
	Busy   bool   `msgpack:"busy" json:"busy"`
}

type Session struct {
	Type        string `msgpack:"type" json:"type"`
	TunnelLocal string `msgpack:"tunnel_local" json:"tunnel_local"`
	TunnelPeer  string `msgpack:"tunnel_peer" json:"tunnel_peer"`
	ViaExploit  string `msgpack:"via_exploit" json:"via_exploit"`
	ViaPayload  string `msgpack:"via_payload" json:"via_payload"`
	Desc        string `msgpack:"desc" json:"desc"`
	Info        string `msgpack:"info" json:"info"`
	Workspace   string `msgpack:"workspace" json:"workspace"`
	SessionHost string `msgpack:"session_host" json:"session_host"`
	SessionPort int    `msgpack:"session_port" json:"session_port"`
	TargetHost  string `msgpack:"target_host" json:"target_host"`
	Username    string `msgpack:"username" json:"username"`
	UUID        string `msgpack:"uuid" json:"uuid"`
	ExploitUUID string `msgpack:"exploit_uuid" json:"exploit_uuid"`
}

type Job struct {
	ID          string `msgpack:"id" json:"id"`
	Name        string `msgpack:"name" json:"name"`
	Description string `msgpack:"description" json:"description"`
}

type ModuleReference struct {
	Type  string `msgpack:"type" json:"type"`
	Value string `msgpack:"value" json:"value"`
}

type MsfModuleInfo struct {
	Name        string            `msgpack:"name" json:"name"`
	Description string            `msgpack:"description" json:"description"`
	License     string            `msgpack:"license" json:"license"`
	FilePath    string            `msgpack:"filepath" json:"filepath"`
	Version     string            `msgpack:"version" json:"version"`
	Rank        string            `msgpack:"rank" json:"rank"`
	Targets     []string          `msgpack:"targets" json:"targets"`
	References  []ModuleReference `msgpack:"references" json:"references"`
	Authors     []string          `msgpack:"authors" json:"authors"`
}

type MsfModuleOption struct {
	Type     string      `msgpack:"type" json:"type"`
	Required bool        `msgpack:"required" json:"required"`
	Advanced bool        `msgpack:"advanced" json:"advanced"`
	Evasion  bool        `msgpack:"evasion" json:"evasion"`
	Desc     string      `msgpack:"desc" json:"desc"`
	Default  interface{} `msgpack:"default,omitempty" json:"default,omitempty"`
	Enums    []string    `msgpack:"enums,omitempty" json:"enums,omitempty"`
}

type ModuleExecuteResult struct {
	JobID int    `msgpack:"job_id" json:"job_id"`
	UUID  string `msgpack:"uuid" json:"uuid"`
}

type Host struct {
	Address     string `msgpack:"address" json:"address"`
	Mac         string `msgpack:"mac" json:"mac"`
	Name        string `msgpack:"name" json:"name"`
	State       string `msgpack:"state" json:"state"`
	OSName      string `msgpack:"os_name" json:"os_name"`
	OSFlavor    string `msgpack:"os_flavor" json:"os_flavor"`
	OSVersion   string `msgpack:"os_version" json:"os_version"`
	OSSP        string `msgpack:"os_sp" json:"os_sp"`
	OSLang      string `msgpack:"os_lang" json:"os_lang"`
	Purpose     string `msgpack:"purpose" json:"purpose"`
	Info        string `msgpack:"info" json:"info"`
	Comments    string `msgpack:"comments" json:"comments"`
	Scope       string `msgpack:"scope" json:"scope"`
	VirtualHost string `msgpack:"virtual_host" json:"virtual_host"`
	Arch        string `msgpack:"arch" json:"arch"`
}

type Service struct {
	Host  string `msgpack:"host" json:"host"`
	Port  int    `msgpack:"port" json:"port"`
	Proto string `msgpack:"proto" json:"proto"`
	Name  string `msgpack:"name" json:"name"`
	State string `msgpack:"state" json:"state"`
	Info  string `msgpack:"info" json:"info"`
}

type Vuln struct {
	Host  string `msgpack:"host" json:"host"`
	Name  string `msgpack:"name" json:"name"`
	Port  int    `msgpack:"port" json:"port"`
	Proto string `msgpack:"proto" json:"proto"`
	Refs  string `msgpack:"refs" json:"refs"`
}

type Credential struct {
	Host    string `msgpack:"host" json:"host"`
	Port    int    `msgpack:"port" json:"port"`
	Proto   string `msgpack:"proto" json:"proto"`
	Service string `msgpack:"sname" json:"sname"`
	User    string `msgpack:"user" json:"user"`
	Pass    string `msgpack:"pass" json:"pass"`
	Type    string `msgpack:"type" json:"type"`
}

type Loot struct {
	Host string `msgpack:"host" json:"host"`
	Type string `msgpack:"ltype" json:"ltype"`
	Name string `msgpack:"name" json:"name"`
	Data string `msgpack:"data" json:"data"`
	Info string `msgpack:"info" json:"info"`
}
