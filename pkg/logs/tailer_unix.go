//go:build !windows

package logs

import (
	"os"
	"syscall"
)

func fileInodeImpl(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
