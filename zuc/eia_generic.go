//go:build !amd64 && !arm64 || purego
// +build !amd64,!arm64 purego

package zuc

func block(m *ZUC128Mac, p []byte) {
	blockGeneric(m, p)
}
