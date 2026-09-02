//go:build arm64 && darwin && !ios

package cpuid

import "github.com/emmansun/gmsm/internal/deps/cpu"

// There are no hw.optional sysctl values for the below features on Mac OS 11.0
// to detect their supported state dynamically. Assume the CPU features that
// Apple Silicon M1 supports to be available as a minimal set of features
// to all Go programs running on darwin/arm64.
var (
	HasSM4     = cpu.ARM64.HasSM4
	HasAES     = true
	HasGFMUL   = true
	HasGFNI    = false
	HasVPMSUMD = false
)
