//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le)

package zuc

func block(m *ZUC128Mac, p []byte) {
	blockGeneric(m, p)
}
