//go:build purego || !(amd64 || arm64)

package cipher

func mul2(tweak *[blockSize]byte, isGB bool) {
	mul2Generic(tweak, isGB)
}

func doubleTweaks(tweak *[blockSize]byte, tweaks []byte, isGB bool) {
	count := len(tweaks) >> 4
	for i := 0; i < count; i++ {
		copy(tweaks[blockSize*i:], tweak[:])
		mul2(tweak, isGB)
	}
}
