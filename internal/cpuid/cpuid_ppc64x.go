//go:build (ppc64 || ppc64le)

package cpuid

var (
	HasAES = true
	HasGFMUL = false
	HasVPMSUMD = true
)
