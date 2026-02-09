//go:build windows

package logs

import "os"

func fileInodeImpl(info os.FileInfo) uint64 {
	// Windows doesn't have inodes; use size as a proxy
	return uint64(info.Size())
}
