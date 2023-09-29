//go:build (amd64 && !purego) || (arm64 && !purego)
// +build amd64,!purego arm64,!purego

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
