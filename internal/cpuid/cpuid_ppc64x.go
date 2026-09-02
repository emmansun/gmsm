//go:build ppc64 || ppc64le

package cpuid

var (
	HasSM4     = false
	HasAES     = true
	HasGFMUL   = false
	HasGFNI    = false
	HasVPMSUMD = true
)
