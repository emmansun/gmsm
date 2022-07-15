//go:build !amd64 && !arm64 || generic
// +build !amd64,!arm64 generic

package zuc

func block(m *ZUC128Mac, p []byte) {
	blockGeneric(m, p)
}
