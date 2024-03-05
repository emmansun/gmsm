//go:build purego || !(amd64 || arm64)

package sm3

func block(dig *digest, p []byte) {
	blockGeneric(dig, p)
}
