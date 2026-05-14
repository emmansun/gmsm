//go:build !windows

package entropy

import _ "unsafe" // for go:linkname

// highResolutionTime returns a high-precision monotonic time value.
// On Unix-like systems, runtime.nanotime uses clock_gettime(CLOCK_MONOTONIC)
// which provides nanosecond resolution.
//
//go:linkname highResolutionTime runtime.nanotime
func highResolutionTime() int64
