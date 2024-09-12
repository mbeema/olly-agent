//go:build linux

package profiling

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	maxELFCacheSize = 256
	mapsCacheTTL    = 60 * time.Second
)

type symbolResolver struct {
	mu     sync.RWMutex
	cache  map[string]*elfSymbols // binary path → symbol table
	maps   map[uint32]*pidMaps   // PID → parsed /proc/pid/maps
	logger *zap.Logger
}

type pidMaps struct {
	mappings []*mapping
	loaded   time.Time
}

type mapping struct {
	StartAddr uint64
	EndAddr   uint64
	Offset    uint64
	File      string
}

type elfSymbols struct {
	symbols []elfSym // sorted by addr for binary search
	loaded  time.Time
}

type elfSym struct {
	Addr uint64
	Size uint64
	Name string
}

func newSymbolResolver(logger *zap.Logger) *symbolResolver {
	return &symbolResolver{
		cache:  make(map[string]*elfSymbols),
		maps:   make(map[uint32]*pidMaps),
		logger: logger,
	}
}

// Resolve translates a PID + instruction pointer address to a function name.
func (r *symbolResolver) Resolve(pid uint32, addr uint64) (funcName string) {
	mappings := r.getMappings(pid)
	if mappings == nil {
		return fmt.Sprintf("0x%x", addr)
	}

	// Find the mapping containing this address
	for _, m := range mappings {
		if addr >= m.StartAddr && addr < m.EndAddr {
			if m.File == "" || m.File == "[vdso]" || m.File == "[vsyscall]" {
				return fmt.Sprintf("0x%x", addr)
			}

			syms := r.getELFSymbols(m.File)
			if syms == nil {
				return fmt.Sprintf("0x%x", addr)
			}

			// Calculate file offset: addr - mapping start + file offset
			fileAddr := addr - m.StartAddr + m.Offset
			name := findSymbol(syms.symbols, fileAddr)
			if name != "" {
				return name
			}

			// Try with raw address (for non-PIE executables)
			name = findSymbol(syms.symbols, addr)
			if name != "" {
				return name
			}

			return fmt.Sprintf("0x%x", addr)
		}
	}

	return fmt.Sprintf("0x%x", addr)
}

func (r *symbolResolver) getMappings(pid uint32) []*mapping {
	r.mu.RLock()
	pm, ok := r.maps[pid]
	r.mu.RUnlock()

	if ok && time.Since(pm.loaded) < mapsCacheTTL {
		return pm.mappings
	}

	mappings := r.loadMaps(pid)
	if mappings == nil {
		return nil
	}

	r.mu.Lock()
	r.maps[pid] = &pidMaps{
		mappings: mappings,
		loaded:   time.Now(),
	}
	r.mu.Unlock()

	return mappings
}

func (r *symbolResolver) loadMaps(pid uint32) []*mapping {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()

	var mappings []*mapping
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := parseMapsLine(line)
		if m != nil {
			mappings = append(mappings, m)
		}
	}

	return mappings
}

// parseMapsLine parses a line from /proc/pid/maps.
// Format: start-end perms offset dev inode pathname
func parseMapsLine(line string) *mapping {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	// Only care about executable mappings
	if len(fields[1]) < 3 || fields[1][2] != 'x' {
		return nil
	}

	addrs := strings.SplitN(fields[0], "-", 2)
	if len(addrs) != 2 {
		return nil
	}

	start, err := strconv.ParseUint(addrs[0], 16, 64)
	if err != nil {
		return nil
	}
	end, err := strconv.ParseUint(addrs[1], 16, 64)
	if err != nil {
		return nil
	}
	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return nil
	}

	file := ""
	if len(fields) >= 6 {
		file = fields[5]
	}

	return &mapping{
		StartAddr: start,
		EndAddr:   end,
		Offset:    offset,
		File:      file,
	}
}

func (r *symbolResolver) getELFSymbols(path string) *elfSymbols {
	r.mu.RLock()
	syms, ok := r.cache[path]
	r.mu.RUnlock()

	if ok {
		return syms
	}

	syms = r.loadELF(path)
	if syms == nil {
		return nil
	}

	r.mu.Lock()
	// Evict oldest if cache is full
	if len(r.cache) >= maxELFCacheSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range r.cache {
			if oldestKey == "" || v.loaded.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.loaded
			}
		}
		if oldestKey != "" {
			delete(r.cache, oldestKey)
		}
	}
	r.cache[path] = syms
	r.mu.Unlock()

	return syms
}

func (r *symbolResolver) loadELF(path string) *elfSymbols {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var allSyms []elfSym

	// Read .symtab
	symbols, err := f.Symbols()
	if err == nil {
		for _, s := range symbols {
			if s.Value != 0 && s.Name != "" && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
				allSyms = append(allSyms, elfSym{
					Addr: s.Value,
					Size: s.Size,
					Name: s.Name,
				})
			}
		}
	}

	// Read .dynsym
	dynSyms, err := f.DynamicSymbols()
	if err == nil {
		for _, s := range dynSyms {
			if s.Value != 0 && s.Name != "" && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
				allSyms = append(allSyms, elfSym{
					Addr: s.Value,
					Size: s.Size,
					Name: s.Name,
				})
			}
		}
	}

	if len(allSyms) == 0 {
		return nil
	}

	// Sort by address for binary search
	sort.Slice(allSyms, func(i, j int) bool {
		return allSyms[i].Addr < allSyms[j].Addr
	})

	return &elfSymbols{
		symbols: allSyms,
		loaded:  time.Now(),
	}
}

// findSymbol does a binary search for the function containing addr.
func findSymbol(symbols []elfSym, addr uint64) string {
	if len(symbols) == 0 {
		return ""
	}

	// Binary search for the last symbol with Addr <= addr
	idx := sort.Search(len(symbols), func(i int) bool {
		return symbols[i].Addr > addr
	})

	if idx == 0 {
		return ""
	}

	sym := symbols[idx-1]
	// If the symbol has a size, check that addr falls within it
	if sym.Size > 0 && addr >= sym.Addr+sym.Size {
		return ""
	}

	return sym.Name
}

// cleanup removes stale PID entries from the maps cache.
func (r *symbolResolver) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for pid, pm := range r.maps {
		if now.Sub(pm.loaded) > 2*mapsCacheTTL {
			delete(r.maps, pid)
		}
	}
}
