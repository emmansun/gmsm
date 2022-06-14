//go:build !amd64 && !arm64 || generic
// +build !amd64,!arm64 generic

package sm2

var (
	p256 p256Curve
)

func initP256Arch() {
	// Use pure Go implementation.
	p256 = p256Curve{p256Params}
}
