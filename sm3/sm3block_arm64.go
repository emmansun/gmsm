//go:build !purego

package sm3

import (
	"os"
	"golang.org/x/sys/cpu"
)

var useSM3NI = cpu.ARM64.HasSM3 && os.Getenv("DISABLE_SM3NI") != "1"

var t = []uint32{
	0x79cc4519,
	0x9d8a7a87,
}

//go:noescape
func blockARM64(dig *digest, p []byte)

//go:noescape
func blockSM3NI(h []uint32, p []byte, t []uint32)

func block(dig *digest, p []byte) {
	if !useSM3NI {
		blockARM64(dig, p)
	} else {
		h := dig.h[:]
		blockSM3NI(h, p, t)
	}
}
