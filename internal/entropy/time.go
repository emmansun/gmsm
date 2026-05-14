// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !windows

package entropy

import _ "unsafe" // for go:linkname

// highResolutionTime returns a high-precision monotonic time value.
// On Unix-like systems, runtime.nanotime uses clock_gettime(CLOCK_MONOTONIC)
// which provides nanosecond resolution.
//
//go:linkname highResolutionTime runtime.nanotime
func highResolutionTime() int64
