//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le)

package zuc

func genKeyStreamRev32(keyStream []byte, pState *zucState32) {
	genKeyStreamRev32Generic(keyStream, pState)
}
