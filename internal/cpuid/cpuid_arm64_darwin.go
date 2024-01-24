//go:build arm64 && darwin && !ios

package cpuid

// There are no hw.optional sysctl values for the below features on Mac OS 11.0
// to detect their supported state dynamically. Assume the CPU features that
// Apple Silicon M1 supports to be available as a minimal set of features
// to all Go programs running on darwin/arm64.
var HasAES = true
var HasGFMUL = true
