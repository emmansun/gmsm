//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le)

package zuc

func block256(m *ZUC256Mac, p []byte) {
	block256Generic(m, p)
}
