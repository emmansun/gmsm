//go:build !amd64 && !arm64 || purego || plugin
// +build !amd64,!arm64 purego plugin

package zuc

func xorKeyStream(c *zucState32, dst, src []byte) {
	xorKeyStreamGeneric(c, dst, src)
}
