//go:build !amd64 && !arm64 || purego
// +build !amd64,!arm64 purego

package zuc

func genKeyStreamRev32(keyStream []byte, pState *zucState32) {
	genKeyStreamRev32Generic(keyStream, pState)
}
