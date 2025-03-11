//go:build (amd64 || arm64 || ppc64 || ppc64le) && !purego

package zuc

//go:noescape
func genKeyStreamRev32Asm(keyStream []byte, pState *zucState32)

func genKeyStreamRev32(keyStream []byte, pState *zucState32) {
	if supportsAES {
		genKeyStreamRev32Asm(keyStream, pState)
	} else {
		genKeyStreamRev32Generic(keyStream, pState)
	}
}
