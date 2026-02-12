// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package hook

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	controlFileName = "control"
	controlFileSize = 4096
)

// ControlFile manages a shared memory control file for on-demand tracing.
// The agent creates this file and writes a single byte:
//   - 0 = dormant (hooks pass through, zero overhead)
//   - 1 = active (full tracing)
//
// libolly.so mmap's this file read-only. A write here is visible to all
// hooked processes immediately via the kernel page cache — no IPC needed.
type ControlFile struct {
	path string
	file *os.File
}

// CreateControlFile creates a new control file in the given directory.
// The file is initialized to dormant (byte 0 = 0).
func CreateControlFile(dir string) (*ControlFile, error) {
	path := filepath.Join(dir, controlFileName)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("create control file: %w", err)
	}

	// Ensure file is exactly one page (for clean mmap on the C side)
	if err := f.Truncate(controlFileSize); err != nil {
		f.Close()
		return nil, fmt.Errorf("truncate control file: %w", err)
	}

	// Start dormant
	if _, err := f.WriteAt([]byte{0}, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("init control file: %w", err)
	}

	os.Chmod(path, 0666)

	return &ControlFile{path: path, file: f}, nil
}

// OpenControlFile opens an existing control file for read-write access.
// Used by CLI commands (olly trace start/stop/status) to control tracing
// without running the full agent.
func OpenControlFile(dir string) (*ControlFile, error) {
	path := filepath.Join(dir, controlFileName)

	f, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("open control file %s: %w", path, err)
	}

	return &ControlFile{path: path, file: f}, nil
}

// Enable activates tracing. All hooked processes will see this immediately.
func (c *ControlFile) Enable() error {
	_, err := c.file.WriteAt([]byte{1}, 0)
	return err
}

// Disable deactivates tracing. Hooks become pass-through with ~1ns overhead.
func (c *ControlFile) Disable() error {
	_, err := c.file.WriteAt([]byte{0}, 0)
	return err
}

// IsEnabled returns the current tracing state.
func (c *ControlFile) IsEnabled() (bool, error) {
	buf := make([]byte, 1)
	_, err := c.file.ReadAt(buf, 0)
	if err != nil {
		return false, err
	}
	return buf[0] != 0, nil
}

// Close closes the file handle. Does NOT remove the file (agent Stop does that).
func (c *ControlFile) Close() error {
	if c.file != nil {
		return c.file.Close()
	}
	return nil
}

// Remove removes the control file from disk.
func (c *ControlFile) Remove() {
	os.Remove(c.path)
}

// Path returns the control file path.
func (c *ControlFile) Path() string {
	return c.path
}
