package pkcs

import (
	"encoding/asn1"

	"github.com/emmansun/gmsm/sm4"
)

var (
	oidSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	oidSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
	oidSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
	oidSM4    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
)

func init() {
	RegisterCipher(oidSM4CBC, func() Cipher {
		return SM4CBC
	})
	RegisterCipher(oidSM4GCM, func() Cipher {
		return SM4GCM
	})
	RegisterCipher(oidSM4ECB, func() Cipher {
		return SM4ECB
	})
}

// SM4ECB is the 128-bit key SM4 cipher in ECB mode.
var SM4ECB = &ecbBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4ECB,
	},
}

// SM4CBC is the 128-bit key SM4 cipher in CBC mode.
var SM4CBC = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4CBC,
	},
	ivSize: sm4.BlockSize,
}

// SM4GCM is the 128-bit key SM4 cipher in GCM mode.
var SM4GCM = &gcmBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4GCM,
	},
	nonceSize: 12,
}

// SM4 is the 128-bit key SM4 cipher in CBC mode, it's just for CFCA.
var SM4 = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      oidSM4,
	},
	ivSize: sm4.BlockSize,
}
