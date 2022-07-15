//go:build (amd64 && !generic) || (arm64 && !generic)
// +build amd64,!generic arm64,!generic

package zuc

import (
	"github.com/emmansun/gmsm/internal/xor"
)

//go:noescape
func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)

func xorKeyStream(c *zucState32, dst, src []byte) {
	if supportsAES {
		words := len(src) / 4
		// handle complete words first
		if words > 0 {
			dstWords := dst[:words*4]
			genKeyStreamRev32Asm(dstWords, c)
			xor.XorBytes(dst, src, dstWords)
		}
		// handle remain bytes
		if words*4 < len(src) {
			var singleWord [4]byte
			genKeyStreamRev32Asm(singleWord[:], c)
			xor.XorBytes(dst[words*4:], src[words*4:], singleWord[:])
		}
	} else {
		xorKeyStreamGeneric(c, dst, src)
	}
}
