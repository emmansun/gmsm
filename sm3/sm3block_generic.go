//go:build !amd64
// +build !amd64

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
