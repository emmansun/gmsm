//go:build !purego

package sm3

import (
	"math/bits"
	"os"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

var useSM3NI = cpu.ARM64.HasSM3 && os.Getenv("DISABLE_SM3NI") != "1"

var t = initRoundT()

func initRoundT() [64]uint32 {
	var roundT [64]uint32
	for i := 0; i < 16; i++ {
		roundT[i] = bits.RotateLeft32(0x79cc4519, i)
	}
	for i := 16; i < 64; i++ {
		roundT[i] = bits.RotateLeft32(0x7a879d8a, i&31)
	}
	return roundT
}

//go:noescape
func blockARM64(dig *digest, p []byte)

//go:noescape
func blockSM3NI(h []uint32, p []byte, t *uint32)

func block(dig *digest, p []byte) {
	if !useSM3NI {
		blockARM64(dig, p)
	} else {
		h := dig.h[:]
		blockSM3NI(h, p, &t[0])
	}
}
