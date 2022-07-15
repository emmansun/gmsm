package pkcs8

import (
	"encoding/asn1"

	"github.com/emmansun/gmsm/sm4"
)

var (
	oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	oidSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
)

func init() {
	RegisterCipher(oidSM4CBC, func() Cipher {
		return &SM4CBC
	})
	RegisterCipher(oidSM4GCM, func() Cipher {
		return &SM4GCM
	})
}

// SM4CBC is the 128-bit key SM4 cipher in CBC mode.
var SM4CBC = cipherWithBlock{
	ivSize:   sm4.BlockSize,
	keySize:  16,
	newBlock: sm4.NewCipher,
	oid:      oidSM4CBC,
}

// SM4GCM is the 128-bit key SM4 cipher in GCM mode.
var SM4GCM = cipherWithGCM{
	nonceSize: 12,
	keySize:   16,
	newBlock:  sm4.NewCipher,
	oid:       oidSM4GCM,
}
