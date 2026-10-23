package app

// MountTestModules mounts the modules fn makes in every wiring until restore runs.
func MountTestModules(fn func() []Module) (restore func()) {
	extraModules = func(*wiring) []Module { return fn() }
	return func() { extraModules = nil }
}

// EnabledParts names the optional parts this build and cfg turn on.
func EnabledParts(cfg Config) string { return enabledParts(cfg) }
