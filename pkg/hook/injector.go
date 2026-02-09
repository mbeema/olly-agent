package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"go.uber.org/zap"
)

// Injector helps inject libolly.so into target processes.
type Injector struct {
	libraryPath string
	socketPath  string
	logger      *zap.Logger
}

// NewInjector creates a new process injector.
func NewInjector(libraryPath, socketPath string, logger *zap.Logger) *Injector {
	return &Injector{
		libraryPath: libraryPath,
		socketPath:  socketPath,
		logger:      logger,
	}
}

// FindLibrary locates the libolly shared library.
func (inj *Injector) FindLibrary() (string, error) {
	if inj.libraryPath != "" {
		if _, err := os.Stat(inj.libraryPath); err == nil {
			return inj.libraryPath, nil
		}
	}

	candidates := []string{
		"./lib/libolly.so",
		"/usr/lib/libolly.so",
		"/usr/local/lib/libolly.so",
		"/opt/olly/lib/libolly.so",
	}

	if runtime.GOOS == "darwin" {
		candidates = []string{
			"./lib/libolly.dylib",
			"/usr/local/lib/libolly.dylib",
			"/opt/olly/lib/libolly.dylib",
		}
	}

	for _, path := range candidates {
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs, nil
		}
	}

	return "", fmt.Errorf("libolly library not found; build with 'make hook'")
}

// preloadEnvVar returns the platform-specific preload environment variable name.
func preloadEnvVar() string {
	if runtime.GOOS == "darwin" {
		return "DYLD_INSERT_LIBRARIES"
	}
	return "LD_PRELOAD"
}

// InjectEnv returns environment variables for injecting the hook library.
func (inj *Injector) InjectEnv() ([]string, error) {
	libPath, err := inj.FindLibrary()
	if err != nil {
		return nil, err
	}

	envVar := preloadEnvVar()

	env := []string{
		fmt.Sprintf("%s=%s", envVar, libPath),
		fmt.Sprintf("OLLY_SOCKET=%s", inj.socketPath),
	}

	return env, nil
}

// InjectCommand wraps a command with the hook library injection.
func (inj *Injector) InjectCommand(name string, args ...string) (*exec.Cmd, error) {
	env, err := inj.InjectEnv()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd, nil
}

// WrapperScript generates a shell script that sets up injection.
func (inj *Injector) WrapperScript() (string, error) {
	libPath, err := inj.FindLibrary()
	if err != nil {
		return "", err
	}

	envVar := preloadEnvVar()

	script := fmt.Sprintf(`#!/bin/sh
# Olly hook injection wrapper
export %s="%s"
export OLLY_SOCKET="%s"
exec "$@"
`, envVar, libPath, inj.socketPath)

	return script, nil
}

// SystemdDropIn generates a systemd service drop-in for injection.
func (inj *Injector) SystemdDropIn() (string, error) {
	libPath, err := inj.FindLibrary()
	if err != nil {
		return "", err
	}

	dropin := fmt.Sprintf(`[Service]
Environment="LD_PRELOAD=%s"
Environment="OLLY_SOCKET=%s"
`, libPath, inj.socketPath)

	return dropin, nil
}

// DockerEnv returns Docker CLI flags for injection.
func (inj *Injector) DockerEnv() ([]string, error) {
	libPath, err := inj.FindLibrary()
	if err != nil {
		return nil, err
	}

	flags := []string{
		"-v", fmt.Sprintf("%s:/opt/olly/lib/libolly.so:ro", libPath),
		"-v", fmt.Sprintf("%s:%s", filepath.Dir(inj.socketPath), filepath.Dir(inj.socketPath)),
		"-e", fmt.Sprintf("LD_PRELOAD=/opt/olly/lib/libolly.so"),
		"-e", fmt.Sprintf("OLLY_SOCKET=%s", inj.socketPath),
	}

	return flags, nil
}

// AttachProcess injects the hook library into an already-running process.
// On Linux, uses GDB-based dlopen injection. On macOS, uses DYLD_INSERT_LIBRARIES
// via task_for_pid (requires SIP disabled or entitled binary).
func (inj *Injector) AttachProcess(pid int) error {
	libPath, err := inj.FindLibrary()
	if err != nil {
		return err
	}

	switch runtime.GOOS {
	case "linux":
		return inj.attachLinux(pid, libPath)
	case "darwin":
		return inj.attachDarwin(pid, libPath)
	default:
		return fmt.Errorf("on-demand attach not supported on %s", runtime.GOOS)
	}
}

// attachLinux uses GDB to inject dlopen() into a running process.
// This requires: gdb installed, ptrace permissions (root or Yama LSM disabled).
func (inj *Injector) attachLinux(pid int, libPath string) error {
	// Check if GDB is available
	gdbPath, err := exec.LookPath("gdb")
	if err != nil {
		return fmt.Errorf("gdb not found; install gdb for on-demand attach: %w", err)
	}

	// Set the OLLY_SOCKET env var in the target process via /proc
	// We can't easily set env vars in a running process, so the library
	// falls back to the default socket path if OLLY_SOCKET is not set.

	// GDB commands to inject dlopen
	gdbCommands := fmt.Sprintf(`set pagination off
set confirm off
attach %d
call (void*)dlopen("%s", 2)
call (void*)setenv("OLLY_SOCKET", "%s", 1)
detach
quit
`, pid, libPath, inj.socketPath)

	cmd := exec.Command(gdbPath, "-batch", "-nx", "-ex", "set auto-load safe-path /")
	cmd.Stdin = strings.NewReader(gdbCommands)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gdb attach failed (pid %d): %w\noutput: %s", pid, err, string(output))
	}

	inj.logger.Info("attached to process",
		zap.Int("pid", pid),
		zap.String("library", libPath),
	)

	return nil
}

// attachDarwin uses lldb for macOS injection.
// Requires: SIP disabled or process has get-task-allow entitlement.
func (inj *Injector) attachDarwin(pid int, libPath string) error {
	lldbPath, err := exec.LookPath("lldb")
	if err != nil {
		return fmt.Errorf("lldb not found: %w", err)
	}

	lldbCommands := fmt.Sprintf(`process attach --pid %d
expr (void*)dlopen("%s", 2)
expr (int)setenv("OLLY_SOCKET", "%s", 1)
process detach
quit
`, pid, libPath, inj.socketPath)

	cmd := exec.Command(lldbPath, "--batch", "--one-line-before-file", "settings set auto-confirm true")
	cmd.Stdin = strings.NewReader(lldbCommands)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("lldb attach failed (pid %d): %w\noutput: %s", pid, err, string(output))
	}

	inj.logger.Info("attached to process",
		zap.Int("pid", pid),
		zap.String("library", libPath),
	)

	return nil
}

// DetachProcess removes the hook library from a running process.
// Note: This is best-effort. dlclose may not fully unload if references remain.
func (inj *Injector) DetachProcess(pid int) error {
	switch runtime.GOOS {
	case "linux":
		gdbPath, err := exec.LookPath("gdb")
		if err != nil {
			return fmt.Errorf("gdb not found: %w", err)
		}

		libPath, err := inj.FindLibrary()
		if err != nil {
			return err
		}

		gdbCommands := fmt.Sprintf(`set pagination off
set confirm off
attach %d
call (void*)dlclose(dlopen("%s", 6))
detach
quit
`, pid, libPath)

		cmd := exec.Command(gdbPath, "-batch", "-nx")
		cmd.Stdin = strings.NewReader(gdbCommands)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("gdb detach failed: %w\noutput: %s", err, string(output))
		}
		return nil

	default:
		return fmt.Errorf("detach not supported on %s", runtime.GOOS)
	}
}

// ActiveProcesses returns PIDs of processes with the hook library loaded.
func (inj *Injector) ActiveProcesses() ([]int, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	libPath, err := inj.FindLibrary()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid := 0
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
		data, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}

		if strings.Contains(string(data), libPath) {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}
