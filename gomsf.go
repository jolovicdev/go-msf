package gomsf

func (c *Client) Core() *CoreManager {
	return NewCoreManager(c)
}

func (c *Client) Auth() *AuthManager {
	return NewAuthManager(c)
}

func (c *Client) Jobs() *JobManager {
	return NewJobManager(c)
}

func (c *Client) Plugins() *PluginManager {
	return NewPluginManager(c)
}

func (c *Client) Modules() *ModuleManager {
	return NewModuleManager(c)
}

func (c *Client) Sessions() *SessionManager {
	return NewSessionManager(c)
}

func (c *Client) Consoles() *ConsoleManager {
	return NewConsoleManager(c)
}

func (c *Client) DB() *DbManager {
	return NewDbManager(c)
}
