//go:build purego || !(amd64 || arm64)

package zuc

func block(m *ZUC128Mac, p []byte) {
	blockGeneric(m, p)
}
