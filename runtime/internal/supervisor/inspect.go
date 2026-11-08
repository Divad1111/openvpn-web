package supervisor

import (
	"errors"
	"os"
	"path/filepath"
)

// Inspector contains fixed operator-selected paths; HTTP clients cannot set them.
// Phase 1 never starts OpenVPN, including when a config file appears.
type Inspector struct {
	ConfigPath string
	TUNPath    string
	BinaryPath string
}

type Status struct {
	State           string   `json:"state"`
	Phase           string   `json:"phase"`
	Running         bool     `json:"running"`
	ConfigPresent   bool     `json:"configPresent"`
	ConfigSafe      bool     `json:"configSafe"`
	TUNAvailable    bool     `json:"tunAvailable"`
	BinaryAvailable bool     `json:"binaryAvailable"`
	Diagnostics     []string `json:"diagnostics"`
}

func (i Inspector) Inspect() Status {
	result := Status{State: "UNINITIALIZED", Phase: "PHASE_1_AUTHENTICATED_IPC", Diagnostics: []string{}}
	if i.ConfigPath == "" || i.TUNPath == "" || i.BinaryPath == "" {
		result.State = "MISCONFIGURED"
		result.Diagnostics = append(result.Diagnostics, "Supervisor paths not configured")
		return result
	}
	if st, err := os.Stat(i.TUNPath); err == nil && st.Mode()&os.ModeDevice != 0 && st.Mode()&os.ModeCharDevice != 0 {
		result.TUNAvailable = true
	} else {
		result.Diagnostics = append(result.Diagnostics, "TUN character device is unavailable")
	}
	if st, err := os.Stat(i.BinaryPath); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
		result.BinaryAvailable = true
	} else {
		result.Diagnostics = append(result.Diagnostics, "OpenVPN executable is unavailable")
	}
	st, err := os.Lstat(i.ConfigPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		result.Diagnostics = append(result.Diagnostics, "Server configuration has not been provisioned")
	case err != nil:
		result.State = "CONFIG_ERROR"
		result.Diagnostics = append(result.Diagnostics, "Cannot inspect server configuration")
	case !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() == 0 || st.Size() > 256*1024:
		result.ConfigPresent = true
		result.State = "UNSAFE_CONFIG"
		result.Diagnostics = append(result.Diagnostics, "Config is not a safe regular file (or is empty/oversized/writable by group or others)")
	default:
		// A safe regular file is not proof of a VALID OpenVPN configuration.
		// Only Phase 3 may validate it and start a VPN process.
		result.ConfigPresent = true
		result.ConfigSafe = true
		result.State = "CONFIG_PRESENT_UNVALIDATED"
		result.Diagnostics = append(result.Diagnostics, "Phase 1 never starts VPN; certificate and config validation not yet implemented")
	}
	// Protect against directory traversal only via fixed server-side path;
	// this check is defensive and no path input is accepted over HTTP.
	if filepath.Clean(i.ConfigPath) != i.ConfigPath {
		result.ConfigSafe = false
		result.State = "UNSAFE_CONFIG"
		result.Diagnostics = append(result.Diagnostics, "Config path is not canonical")
	}
	return result
}
