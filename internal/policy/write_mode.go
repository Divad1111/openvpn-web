package policy

// WriteEnabled permits write operations only for the exact, lowercase literal
// "true" supplied by the container's environment at process startup.
// It must never be evaluated against request data or database contents.
func WriteEnabled(value string) bool { return value == "true" }

// EffectiveWriteMode requires independent approval from the manager and agent.
func EffectiveWriteMode(manager, agent bool) bool { return manager && agent }
