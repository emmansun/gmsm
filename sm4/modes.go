package sm4

import "crypto/cipher"

// ecbcEncAble is implemented by cipher.Blocks that can provide an optimized
// implementation of ECB encryption through the cipher.BlockMode interface.
// See crypto/ecb.go.
type ecbEncAble interface {
	NewECBEncrypter() cipher.BlockMode
}

// ecbDecAble is implemented by cipher.Blocks that can provide an optimized
// implementation of ECB decryption through the cipher.BlockMode interface.
// See crypto/ecb.go.
type ecbDecAble interface {
	NewECBDecrypter() cipher.BlockMode
}

// cbcEncAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC encryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) cipher.BlockMode
}

// cbcDecAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CBC decryption through the cipher.BlockMode interface.
// See crypto/cipher/cbc.go.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) cipher.BlockMode
}

// ctrAble is implemented by cipher.Blocks that can provide an optimized
// implementation of CTR through the cipher.Stream interface.
// See crypto/cipher/ctr.go.
type ctrAble interface {
	NewCTR(iv []byte) cipher.Stream
}

// gcmAble is implemented by cipher.Blocks that can provide an optimized
// implementation of GCM through the AEAD interface.
// See crypto/cipher/gcm.go.
type gcmAble interface {
	NewGCM(nonceSize, tagSize int) (cipher.AEAD, error)
}

// xtsEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of XTS encryption, like sm4.
// NewXTSEncrypter will check for this interface and return the specific
// BlockMode if found.
type xtsEncAble interface {
	NewXTSEncrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode
}

// xtsDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of XTS encryption, like sm4.
// NewXTSDecrypter will check for this interface and return the specific
// BlockMode if found.
type xtsDecAble interface {
	NewXTSDecrypter(encryptedTweak *[BlockSize]byte, isGB bool) cipher.BlockMode
}
