// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build windows

package logs

import "os"

func fileInodeImpl(info os.FileInfo) uint64 {
	// Windows doesn't have inodes; use size as a proxy
	return uint64(info.Size())
}
