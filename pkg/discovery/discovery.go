// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// ServiceInfo holds information about a discovered service.
type ServiceInfo struct {
	Name         string
	Language     string
	Framework    string
	PID          uint32
	Port         uint16
	Source       string // "environment", "port_mapping", "cmdline", "executable"
	DiscoveredAt time.Time
}

// Discoverer auto-detects service names for processes.
type Discoverer struct {
	logger       *zap.Logger
	envVars      []string
	portMappings map[int]string

	mu    sync.RWMutex
	cache map[uint32]*ServiceInfo

	javaPattern   *regexp.Regexp
	pythonPattern *regexp.Regexp
	nodePattern   *regexp.Regexp
}

// NewDiscoverer creates a new service discoverer.
func NewDiscoverer(envVars []string, portMappings map[int]string, logger *zap.Logger) *Discoverer {
	if len(envVars) == 0 {
		envVars = []string{"OTEL_SERVICE_NAME", "SERVICE_NAME", "DD_SERVICE", "APP_NAME"}
	}

	return &Discoverer{
		logger:       logger,
		envVars:      envVars,
		portMappings: portMappings,
		cache:        make(map[uint32]*ServiceInfo),

		javaPattern:   regexp.MustCompile(`(?:-jar\s+|\.jar\s+)(\S+)`),
		pythonPattern: regexp.MustCompile(`python[23]?\s+(?:-m\s+)?(\S+)`),
		nodePattern:   regexp.MustCompile(`node\s+(\S+)`),
	}
}

// GetServiceName returns the service name for a PID.
func (d *Discoverer) GetServiceName(pid uint32) string {
	info := d.DiscoverService(pid)
	if info != nil {
		return info.Name
	}
	return fmt.Sprintf("pid-%d", pid)
}

// GetServiceNameByPort returns the service name for a known port.
func (d *Discoverer) GetServiceNameByPort(port uint16) string {
	if name, ok := d.portMappings[int(port)]; ok {
		return name
	}
	return fmt.Sprintf("port-%d", port)
}

// DiscoverService discovers service information for a PID.
func (d *Discoverer) DiscoverService(pid uint32) *ServiceInfo {
	// Check cache
	d.mu.RLock()
	info, ok := d.cache[pid]
	d.mu.RUnlock()
	if ok {
		return info
	}

	info = d.discover(pid)
	if info != nil {
		d.mu.Lock()
		d.cache[pid] = info
		d.mu.Unlock()
	}

	return info
}

func (d *Discoverer) discover(pid uint32) *ServiceInfo {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil
	}

	info := &ServiceInfo{
		PID:          pid,
		DiscoveredAt: time.Now(),
	}

	// 1. Environment variables
	if envs, err := proc.Environ(); err == nil {
		for _, env := range envs {
			for _, varName := range d.envVars {
				if strings.HasPrefix(env, varName+"=") {
					info.Name = env[len(varName)+1:]
					info.Source = "environment"
					return info
				}
			}
		}
	}

	// 2. Command line analysis
	cmdline, _ := proc.Cmdline()
	if name := d.analyzeCommandLine(cmdline, info); name != "" {
		info.Name = name
		info.Source = "cmdline"
		return info
	}

	// 3. Executable name
	if name, err := proc.Name(); err == nil {
		cleanName := d.cleanExeName(name)
		if cleanName != "" {
			info.Name = cleanName
			info.Source = "executable"
			return info
		}
	}

	return info
}

func (d *Discoverer) analyzeCommandLine(cmdline string, info *ServiceInfo) string {
	if cmdline == "" {
		return ""
	}

	// Java
	if strings.Contains(cmdline, "java ") || strings.Contains(cmdline, "java.") {
		info.Language = "java"
		if matches := d.javaPattern.FindStringSubmatch(cmdline); len(matches) > 1 {
			jar := filepath.Base(matches[1])
			jar = strings.TrimSuffix(jar, ".jar")
			info.Name = jar

			// Detect framework
			if strings.Contains(cmdline, "spring") || strings.Contains(cmdline, "Spring") {
				info.Framework = "spring"
			} else if strings.Contains(cmdline, "quarkus") {
				info.Framework = "quarkus"
			} else if strings.Contains(cmdline, "micronaut") {
				info.Framework = "micronaut"
			}

			return jar
		}
	}

	// Python
	if strings.Contains(cmdline, "python") {
		info.Language = "python"
		if matches := d.pythonPattern.FindStringSubmatch(cmdline); len(matches) > 1 {
			module := filepath.Base(matches[1])
			module = strings.TrimSuffix(module, ".py")

			if strings.Contains(cmdline, "flask") || strings.Contains(cmdline, "Flask") {
				info.Framework = "flask"
			} else if strings.Contains(cmdline, "django") || strings.Contains(cmdline, "Django") {
				info.Framework = "django"
			} else if strings.Contains(cmdline, "fastapi") || strings.Contains(cmdline, "uvicorn") {
				info.Framework = "fastapi"
			}

			return module
		}
	}

	// Node.js
	if strings.Contains(cmdline, "node ") {
		info.Language = "nodejs"
		if matches := d.nodePattern.FindStringSubmatch(cmdline); len(matches) > 1 {
			script := filepath.Base(matches[1])
			script = strings.TrimSuffix(script, ".js")
			script = strings.TrimSuffix(script, ".mjs")

			if strings.Contains(cmdline, "express") {
				info.Framework = "express"
			} else if strings.Contains(cmdline, "nest") {
				info.Framework = "nestjs"
			} else if strings.Contains(cmdline, "next") {
				info.Framework = "nextjs"
			}

			return script
		}
	}

	// Go binary: typically a single word without extension
	if runtime.GOOS == "linux" {
		parts := strings.Fields(cmdline)
		if len(parts) > 0 {
			exe := parts[0]
			// Check if it looks like a Go binary (no extension, not an interpreter)
			if !strings.Contains(exe, ".") && !isInterpreter(filepath.Base(exe)) {
				info.Language = "go"
				return filepath.Base(exe)
			}
		}
	}

	return ""
}

func (d *Discoverer) cleanExeName(name string) string {
	if isInterpreter(name) {
		return ""
	}

	// Remove common suffixes
	name = strings.TrimSuffix(name, ".exe")
	name = strings.TrimSuffix(name, ".bin")

	return name
}

func isInterpreter(name string) bool {
	interpreters := map[string]bool{
		"python": true, "python2": true, "python3": true,
		"node": true, "nodejs": true,
		"ruby": true, "java": true, "php": true,
		"perl": true, "bash": true, "sh": true, "zsh": true,
	}
	return interpreters[name]
}

// InvalidateCache removes a PID from the cache.
func (d *Discoverer) InvalidateCache(pid uint32) {
	d.mu.Lock()
	delete(d.cache, pid)
	d.mu.Unlock()
}

// ClearCache removes all entries from the cache.
func (d *Discoverer) ClearCache() {
	d.mu.Lock()
	d.cache = make(map[uint32]*ServiceInfo)
	d.mu.Unlock()
}

// CleanDeadProcesses removes cached entries for processes that no longer exist.
func (d *Discoverer) CleanDeadProcesses() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	removed := 0
	for pid := range d.cache {
		if !processExists(pid) {
			delete(d.cache, pid)
			removed++
		}
	}
	return removed
}

func processExists(pid uint32) bool {
	if runtime.GOOS == "linux" {
		_, err := os.Stat("/proc/" + strconv.Itoa(int(pid)))
		return err == nil
	}
	// Cross-platform fallback
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	running, _ := p.IsRunning()
	return running
}
