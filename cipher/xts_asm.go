//go:build (amd64 && !purego) || (arm64 && !purego)
// +build amd64,!purego arm64,!purego

package cipher

//go:noescape
func mul2(tweak *[blockSize]byte, isGB bool)

//go:noescape
func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
