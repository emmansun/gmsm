//go:build !amd64 && !arm64 || generic
// +build !amd64,!arm64 generic

package zuc

func xorKeyStream(c *zucState32, dst, src []byte) {
	xorKeyStreamGeneric(c, dst, src)
}
