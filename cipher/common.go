package cipher

import "crypto/cipher"

// blockSize is the block size that the underlying cipher must have.
const blockSize = 16

type concurrentBlocks interface {
	Concurrency() int
	EncryptBlocks(dst, src []byte)
	DecryptBlocks(dst, src []byte)
}

type CipherCreator func([]byte) (cipher.Block, error)
