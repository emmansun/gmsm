//go:build purego || !(amd64 || arm64)

package zuc

func genKeyStreamRev32(keyStream []byte, pState *zucState32) {
	genKeyStreamRev32Generic(keyStream, pState)
}
