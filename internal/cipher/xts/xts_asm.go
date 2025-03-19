//go:build (amd64 || arm64 || s390x || ppc64 || ppc64le) && !purego

package xts

//go:noescape
func mul2(tweak *[blockSize]byte, isGB bool)

//go:noescape
func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool)
