//go:build !purego

package sm3

import (
	"os"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2
var useSSSE3 = cpu.X86.HasSSSE3
var useSM3NI = cpu.X86.HasAVX2 && cpu.X86.HasSM3 && os.Getenv("DISABLE_SM3NI") != "1"

//go:noescape
func blockSIMD(dig *digest, p []byte)

//go:noescape
func blockAVX2(dig *digest, p []byte)

//go:noescape
func blockSM3NI(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	switch {
	case useSM3NI:
		blockSM3NI(dig, p)
	case useAVX2:
		blockAVX2(dig, p)
	case useSSSE3:
		blockSIMD(dig, p)
	default:
		blockGeneric(dig, p)
	}
}
