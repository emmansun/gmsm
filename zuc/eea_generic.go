//go:build !amd64 && !arm64 || purego
// +build !amd64,!arm64 purego

package zuc

func xorKeyStream(c *zucState32, dst, src []byte) {
	xorKeyStreamGeneric(c, dst, src)
}
