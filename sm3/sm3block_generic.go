//go:build !amd64 && !arm64 || purego || plugin
// +build !amd64,!arm64 purego plugin

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
