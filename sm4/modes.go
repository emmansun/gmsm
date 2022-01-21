package sm4

import "crypto/cipher"

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
