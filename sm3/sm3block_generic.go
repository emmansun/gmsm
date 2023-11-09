//go:build !amd64 && !arm64 || purego

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
