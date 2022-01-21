//go:build !amd64 && !arm64
// +build !amd64,!arm64

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
