//go:build !amd64 && !arm64 || generic
// +build !amd64,!arm64 generic

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
