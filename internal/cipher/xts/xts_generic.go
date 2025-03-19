//go:build purego || !(amd64 || arm64 || s390x || ppc64 || ppc64le)

package xts

func mul2(tweak *[blockSize]byte, isGB bool) {
	mul2Generic(tweak, isGB)
}

func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool) {
	count := len(tweaks) >> 4
	for i := range count {
		copy(tweaks[blockSize*i:], tweak[:])
		mul2(tweak, isGB)
	}
}
