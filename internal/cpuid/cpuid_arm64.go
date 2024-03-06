package cpuid

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

var HasAES = false
var HasGFMUL = false

func init() {
	if runtime.GOOS == "darwin/arm64" {
		HasAES = true
		HasGFMUL = true
	} else {
		HasAES = cpu.ARM64.HasAES
		HasGFMUL = cpu.ARM64.HasPMULL
	}
}
