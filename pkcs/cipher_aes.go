package pkcs

import (
	"crypto/aes"
	"encoding/asn1"
)

var (
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

func init() {
	RegisterCipher(oidAES128CBC, func() Cipher {
		return AES128CBC
	})
	RegisterCipher(oidAES128GCM, func() Cipher {
		return AES128GCM
	})
	RegisterCipher(oidAES192CBC, func() Cipher {
		return AES192CBC
	})
	RegisterCipher(oidAES192GCM, func() Cipher {
		return AES192GCM
	})
	RegisterCipher(oidAES256CBC, func() Cipher {
		return AES256CBC
	})
	RegisterCipher(oidAES256GCM, func() Cipher {
		return AES256GCM
	})
}

// AES128CBC is the 128-bit key AES cipher in CBC mode.
var AES128CBC = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: aes.NewCipher,
		oid:      oidAES128CBC,
	},
	ivSize: aes.BlockSize,
}

// AES128GCM is the 128-bit key AES cipher in GCM mode.
var AES128GCM = &gcmBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: aes.NewCipher,
		oid:      oidAES128GCM,
	},
	nonceSize: 12,
}

// AES192CBC is the 192-bit key AES cipher in CBC mode.
var AES192CBC = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  24,
		newBlock: aes.NewCipher,
		oid:      oidAES192CBC,
	},
	ivSize:   aes.BlockSize,
}

// AES192GCM is the 912-bit key AES cipher in GCM mode.
var AES192GCM = &gcmBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  24,
		newBlock: aes.NewCipher,
		oid:      oidAES192GCM,
	},
	nonceSize: 12,
}

// AES256CBC is the 256-bit key AES cipher in CBC mode.
var AES256CBC = &cbcBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  32,
		newBlock: aes.NewCipher,
		oid:      oidAES256CBC,
	},
	ivSize:   aes.BlockSize,
}

// AES256GCM is the 256-bit key AES cipher in GCM mode.
var AES256GCM = &gcmBlockCipher{
	baseBlockCipher: baseBlockCipher{
		keySize:  32,
		newBlock: aes.NewCipher,
		oid:      oidAES256GCM,
	},
	nonceSize: 12,
}
