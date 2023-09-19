//go:build amd64 && !purego
// +build amd64,!purego

package sm3

import "golang.org/x/sys/cpu"

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2
var useAVX = cpu.X86.HasAVX

//go:noescape
func blockAMD64(dig *digest, p []byte)

//go:noescape
func blockAVX(dig *digest, p []byte)

//go:noescape
func blockAVX2(dig *digest, p []byte)

func block(dig *digest, p []byte) {
	if useAVX2 {
		blockAVX2(dig, p)
	} else if useAVX {
		blockAVX(dig, p)
	} else {
		blockAMD64(dig, p)
	}
}
