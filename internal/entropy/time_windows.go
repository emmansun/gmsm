// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build windows

package entropy

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procQueryPerformanceCounter = kernel32.NewProc("QueryPerformanceCounter")
)

// highResolutionTime returns the raw QueryPerformanceCounter value.
// On Windows, runtime.nanotime() has poor resolution (~500µs) due to
// integer conversion. QPC provides ~100ns resolution directly.
func highResolutionTime() int64 {
	var count int64
	procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&count)))
	return count
}
