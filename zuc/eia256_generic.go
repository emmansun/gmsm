//go:build !amd64 && !arm64 || purego

package zuc

func block256(m *ZUC256Mac, p []byte) {
	block256Generic(m, p)
}
