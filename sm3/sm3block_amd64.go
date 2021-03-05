//go:build amd64
// +build amd64

package sm3

//go:noescape

func block(dig *digest, p []byte)
