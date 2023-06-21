//go:build (!amd64 && !arm64) || purego
// +build !amd64,!arm64 purego

package bn256

func gfP12MovCond(res, a, b *gfP12, cond int) {
	res.Select(a, b, cond)
}

func curvePointMovCond(res, a, b *curvePoint, cond int) {
	res.Select(a, b, cond)
}

func twistPointMovCond(res, a, b *twistPoint, cond int) {
	res.Select(a, b, cond)
}
