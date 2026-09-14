//go:build purego || !(amd64 || arm64 || ppc64 || ppc64le || (riscv64 && go1.27))

package zuc

func block(m *ZUC128Mac, p []byte) {
	blockGeneric(m, p)
}
