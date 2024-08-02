//go:build !purego

package sm3

func kdf(baseMD *digest, keyLen int, limit int) []byte {
	if useSM3NI || limit < 4 {
		return kdfGeneric(baseMD, keyLen, limit)
	}
	return kdfBy4(baseMD, keyLen, limit)
}
