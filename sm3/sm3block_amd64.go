//go:build amd64 && !purego && !plugin
// +build amd64,!purego,!plugin

package sm3

import "golang.org/x/sys/cpu"

var useAVX2 = cpu.X86.HasAVX2 && cpu.X86.HasBMI2

//go:noescape
func block(dig *digest, p []byte)
