// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// sslScanner discovers libssl.so in running processes and attaches uprobes
// for SSL_write, SSL_read, and SSL_set_fd to capture plaintext before
// encryption and after decryption.
type sslScanner struct {
	loader *loader
	logger *zap.Logger

	// Track which libssl paths we've already attached to avoid duplicates.
	mu       sync.Mutex
	attached map[string]bool
}

// newSSLScanner creates a new SSL library scanner.
func newSSLScanner(loader *loader, logger *zap.Logger) *sslScanner {
	return &sslScanner{
		loader:   loader,
		logger:   logger,
		attached: make(map[string]bool),
	}
}

// scanExistingProcesses scans /proc for all running processes and attaches
// SSL uprobes to any that have libssl.so loaded.
func (s *sslScanner) scanExistingProcesses() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.logger.Debug("cannot read /proc for SSL scanning", zap.Error(err))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		s.scanProcess(uint32(pid))
	}
}

// scanProcess reads /proc/<pid>/maps and attaches uprobes to any libssl.so found.
func (s *sslScanner) scanProcess(pid uint32) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return // process may have exited
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		libPath := extractSSLPath(line)
		if libPath == "" {
			continue
		}

		s.mu.Lock()
		if s.attached[libPath] {
			s.mu.Unlock()
			continue
		}
		s.attached[libPath] = true
		s.mu.Unlock()

		if err := s.loader.attachSSLUprobes(libPath); err != nil {
			s.logger.Debug("failed to attach SSL uprobes",
				zap.String("lib", libPath),
				zap.Uint32("pid", pid),
				zap.Error(err),
			)
			// Revert the attached flag so we can retry
			s.mu.Lock()
			delete(s.attached, libPath)
			s.mu.Unlock()
		} else {
			s.logger.Info("attached SSL uprobes",
				zap.String("lib", libPath),
				zap.Uint32("pid", pid),
			)
		}
	}
}

// extractSSLPath extracts the libssl.so path from a /proc/pid/maps line.
// Returns empty string if the line doesn't reference libssl.
func extractSSLPath(line string) string {
	// /proc/pid/maps format:
	// 7f...  r-xp 00000000 ... /usr/lib/x86_64-linux-gnu/libssl.so.3
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return ""
	}

	// Only look at executable mappings (r-xp)
	perms := fields[1]
	if len(perms) < 3 || perms[2] != 'x' {
		return ""
	}

	path := fields[len(fields)-1]
	base := filepath.Base(path)

	// Match libssl.so, libssl.so.1.1, libssl.so.3, etc.
	if strings.HasPrefix(base, "libssl.so") {
		// Verify the file exists (it might be in a container namespace)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// close is a no-op — the uprobes are owned by the loader and closed there.
func (s *sslScanner) close() {
	// Uprobes are tracked as links in the loader and closed by loader.close().
}
