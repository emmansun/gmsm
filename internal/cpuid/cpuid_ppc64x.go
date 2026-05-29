//go:build (ppc64 || ppc64le)

package cpuid

var (
	HasAES = true
	HasGFMUL = false
	HasGFNI = false
	HasVPMSUMD = true
)
