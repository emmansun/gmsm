package pkcs8

import (
	"crypto/des"
	"encoding/asn1"
)

var (
	oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

func init() {
	RegisterCipher(oidDESCBC, func() Cipher {
		return &DESCBC
	})

	RegisterCipher(oidDESEDE3CBC, func() Cipher {
		return &TripleDESCBC
	})
}

var DESCBC = cbcBlockCipher{
	ivSize:   des.BlockSize,
	keySize:  8,
	newBlock: des.NewCipher,
	oid:      oidDESCBC,
}

// TripleDESCBC is the 168-bit key 3DES cipher in CBC mode.
var TripleDESCBC = cbcBlockCipher{
	ivSize:   des.BlockSize,
	keySize:  24,
	newBlock: des.NewTripleDESCipher,
	oid:      oidDESEDE3CBC,
}
