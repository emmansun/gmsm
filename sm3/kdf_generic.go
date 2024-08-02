//go:build purego || !(amd64 || arm64)

package sm3

func kdf(baseMD *digest, keyLen int, limit int) []byte {
	return kdfGeneric(baseMD, keyLen, limit)
}
