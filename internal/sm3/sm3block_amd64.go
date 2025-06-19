//go:build !purego

package sm3

import "github.com/emmansun/gmsm/internal/deps/cpu"

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2
var useAVX = cpu.X86.HasAVX
var useSSSE3 = cpu.X86.HasSSSE3

//go:noescape
func blockAMD64(dig *digest, p []byte)

//go:noescape
func blockSIMD(dig *digest, p []byte)

//go:noescape
func blockAVX2(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	switch {
	case useAVX2:
		blockAVX2(dig, p)
	case useSSSE3, useAVX: // useSSSE3 or useAVX
		blockSIMD(dig, p)
	default:
		blockAMD64(dig, p)
	}
}
