package gomsf

import (
	"context"
	"fmt"
)

type ModuleManager struct {
	rpc RPCCaller
}

func NewModuleManager(rpc RPCCaller) *ModuleManager {
	return &ModuleManager{rpc: rpc}
}

func (m *ModuleManager) Exploits(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModuleExploits)
}

func (m *ModuleManager) Payloads(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModulePayloads)
}

func (m *ModuleManager) Auxiliary(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModuleAuxiliary)
}

func (m *ModuleManager) Post(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModulePost)
}

func (m *ModuleManager) Encoders(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModuleEncoders)
}

func (m *ModuleManager) Nops(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModuleNops)
}

func (m *ModuleManager) Evasion(ctx context.Context) ([]string, error) {
	return m.listModules(ctx, ModuleEvasion)
}

func (m *ModuleManager) listModules(ctx context.Context, method MsfRpcMethod) ([]string, error) {
	result, err := m.rpc.Call(ctx, method)
	if err != nil {
		return nil, err
	}

	return responseStringSlice(result, "modules")
}

func (m *ModuleManager) Use(ctx context.Context, modType ModuleType, name string) (*Module, error) {
	return NewModuleWithContext(ctx, m.rpc, modType, name)
}

func (m *ModuleManager) Execute(ctx context.Context, modType ModuleType, name string, options map[string]interface{}) (*ModuleExecuteResult, error) {
	result, err := m.rpc.Call(ctx, ModuleExecute, string(modType), name, options)
	if err != nil {
		return nil, err
	}

	var execResult ModuleExecuteResult
	if err := decodeResult(result, &execResult); err != nil {
		return nil, err
	}

	return &execResult, nil
}

type Module struct {
	rpc        RPCCaller
	ModuleType ModuleType
	Name       string
	info       map[string]interface{}
	options    map[string]*MsfModuleOption
	runOptions map[string]interface{}
}

func NewModule(rpc RPCCaller, modType ModuleType, name string) (*Module, error) {
	return NewModuleWithContext(context.Background(), rpc, modType, name)
}

func NewModuleWithContext(ctx context.Context, rpc RPCCaller, modType ModuleType, name string) (*Module, error) {
	mod := &Module{
		rpc:        rpc,
		ModuleType: modType,
		Name:       name,
		runOptions: make(map[string]interface{}),
	}

	info, err := rpc.Call(ctx, ModuleOptions, string(modType), name)
	if err != nil {
		return nil, err
	}

	mod.info, err = responseMap(info)
	if err != nil {
		return nil, err
	}
	if err := mod.parseOptions(); err != nil {
		return nil, err
	}

	return mod, nil
}

func (m *Module) parseOptions() error {
	m.options = make(map[string]*MsfModuleOption)

	for key, val := range m.info {
		optMap, ok := val.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%w: option %s must be a map", ErrUnexpectedResponse, key)
		}

		opt := &MsfModuleOption{}

		if rawType, ok := optMap["type"]; ok {
			t, ok := rawType.(string)
			if !ok {
				return fmt.Errorf("%w: option %s type must be a string", ErrUnexpectedResponse, key)
			}
			opt.Type = t
		}
		if rawRequired, ok := optMap["required"]; ok {
			required, ok := rawRequired.(bool)
			if !ok {
				return fmt.Errorf("%w: option %s required must be a bool", ErrUnexpectedResponse, key)
			}
			opt.Required = required
		}
		if rawAdvanced, ok := optMap["advanced"]; ok {
			advanced, ok := rawAdvanced.(bool)
			if !ok {
				return fmt.Errorf("%w: option %s advanced must be a bool", ErrUnexpectedResponse, key)
			}
			opt.Advanced = advanced
		}
		if rawEvasion, ok := optMap["evasion"]; ok {
			evasion, ok := rawEvasion.(bool)
			if !ok {
				return fmt.Errorf("%w: option %s evasion must be a bool", ErrUnexpectedResponse, key)
			}
			opt.Evasion = evasion
		}
		if rawDesc, ok := optMap["desc"]; ok {
			desc, ok := rawDesc.(string)
			if !ok {
				return fmt.Errorf("%w: option %s desc must be a string", ErrUnexpectedResponse, key)
			}
			opt.Desc = desc
		}
		if def, ok := optMap["default"]; ok {
			opt.Default = def
			m.runOptions[key] = def
		}
		if rawEnums, ok := optMap["enums"]; ok {
			enums, ok := rawEnums.([]interface{})
			if !ok {
				return fmt.Errorf("%w: option %s enums must be a list", ErrUnexpectedResponse, key)
			}
			opt.Enums = make([]string, len(enums))
			for i, e := range enums {
				value, ok := e.(string)
				if !ok {
					return fmt.Errorf("%w: option %s enums[%d] must be a string", ErrUnexpectedResponse, key, i)
				}
				opt.Enums[i] = value
			}
		}

		m.options[key] = opt
	}

	return nil
}

func (m *Module) Options() []string {
	keys := make([]string, 0, len(m.options))
	for k := range m.options {
		keys = append(keys, k)
	}
	return keys
}

func (m *Module) RequiredOptions() []string {
	var required []string
	for k, v := range m.options {
		if v.Required {
			required = append(required, k)
		}
	}
	return required
}

func (m *Module) MissingRequired() []string {
	var missing []string
	for k, v := range m.options {
		if v.Required {
			if _, ok := m.runOptions[k]; !ok {
				missing = append(missing, k)
			}
		}
	}
	return missing
}

func (m *Module) OptionInfo(option string) (*MsfModuleOption, error) {
	opt, ok := m.options[option]
	if !ok {
		return nil, invalidOptionError(option)
	}
	return opt, nil
}

func (m *Module) GetOption(option string) (interface{}, error) {
	if _, ok := m.options[option]; !ok {
		return nil, invalidOptionError(option)
	}
	return m.runOptions[option], nil
}

func (m *Module) SetOption(option string, value interface{}) error {
	opt, ok := m.options[option]
	if !ok {
		return invalidOptionError(option)
	}

	if len(opt.Enums) > 0 {
		found := false
		for _, e := range opt.Enums {
			if e == value {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: %s must be one of %v", ErrInvalidOption, option, opt.Enums)
		}
	}

	m.runOptions[option] = value
	return nil
}

func (m *Module) RunOptions() map[string]interface{} {
	result := make(map[string]interface{}, len(m.runOptions))
	for k, v := range m.runOptions {
		result[k] = v
	}
	return result
}

func (m *Module) Execute(ctx context.Context) (*ModuleExecuteResult, error) {
	return NewModuleManager(m.rpc).Execute(ctx, m.ModuleType, m.Name, m.runOptions)
}

func (m *Module) ExecuteWithPayload(ctx context.Context, payload *Module) (*ModuleExecuteResult, error) {
	options := m.RunOptions()
	options["PAYLOAD"] = payload.Name

	for k, v := range payload.RunOptions() {
		if _, ok := options[k]; !ok {
			options[k] = v
		}
	}

	return NewModuleManager(m.rpc).Execute(ctx, m.ModuleType, m.Name, options)
}

func invalidOptionError(option string) error {
	return fmt.Errorf("%w: %s", ErrInvalidOption, option)
}
