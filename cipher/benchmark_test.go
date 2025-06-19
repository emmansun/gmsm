package cipher_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
)

func BenchmarkSM4BCEncrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkBCEncrypt(b, c, make([]byte, 1024))
}

func benchmarkBCEncrypt(b *testing.B, block cipher.Block, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var iv [16]byte
	bc := smcipher.NewBCEncrypter(block, iv[:])
	for i := 0; i < b.N; i++ {
		bc.CryptBlocks(buf, buf)
	}
}

func BenchmarkSM4BCDecrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkBCDecrypt(b, c, make([]byte, 1024))
}

func benchmarkBCDecrypt(b *testing.B, block cipher.Block, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var iv [16]byte
	bc := smcipher.NewBCDecrypter(block, iv[:])
	for i := 0; i < b.N; i++ {
		bc.CryptBlocks(buf, buf)
	}
}

func BenchmarkSM4HCTREncrypt1K(b *testing.B) {
	var key [16]byte
	var tweak [32]byte
	c, _ := sm4.NewCipher(key[:])
	io.ReadFull(rand.Reader, tweak[:])
	hctr, _ := smcipher.NewHCTR(c, tweak[:16], tweak[16:])
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hctr.EncryptBytes(buf, buf)
	}
}

func benchmarkECBEncrypt(b *testing.B, block cipher.Block, buf []byte) {
	b.SetBytes(int64(len(buf)))

	ecb := smcipher.NewECBEncrypter(block)
	for i := 0; i < b.N; i++ {
		ecb.CryptBlocks(buf, buf)
	}
}

func BenchmarkSM4ECBEncrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkECBEncrypt(b, c, make([]byte, 1024))
}

func BenchmarkAES128ECBEncrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	benchmarkECBEncrypt(b, c, make([]byte, 1024))
}

func benchmarkCBCEncrypt(b *testing.B, block cipher.Block, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var iv [16]byte
	cbc := cipher.NewCBCEncrypter(block, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkAESCBCEncrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	benchmarkCBCEncrypt(b, c, make([]byte, 1024))
}

func BenchmarkSM4CBCEncrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkCBCEncrypt(b, c, make([]byte, 1024))
}

func BenchmarkSM4CBCEncrypt8K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkCBCEncrypt(b, c, make([]byte, 8*1024))
}

func benchmarkCBCDecrypt(b *testing.B, block cipher.Block, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var iv [16]byte
	cbc := cipher.NewCBCDecrypter(block, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkAESCBCDecrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	benchmarkCBCDecrypt(b, c, make([]byte, 1024))
}

func BenchmarkSM4CBCDecrypt1K(b *testing.B) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkCBCDecrypt(b, c, make([]byte, 1024))
}

func benchmarkStream(b *testing.B, block cipher.Block, mode func(cipher.Block, []byte) cipher.Stream, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var iv [16]byte
	stream := mode(block, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.XORKeyStream(buf, buf)
	}
}

func benchmarkSM4Stream(b *testing.B, mode func(cipher.Block, []byte) cipher.Stream, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	benchmarkStream(b, c, mode, buf)
}

func benchmarkAESStream(b *testing.B, mode func(cipher.Block, []byte) cipher.Stream, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	benchmarkStream(b, c, mode, buf)
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5
const almost8K = 8*1024 - 5

func BenchmarkAESCFBEncrypt1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBEncrypter, make([]byte, almost1K))
}

func BenchmarkSM4CFBEncrypt1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBEncrypter, make([]byte, almost1K))
}

func BenchmarkAESCFBDecrypt1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBDecrypter, make([]byte, almost1K))
}

func BenchmarkSM4CFBDecrypt1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBDecrypter, make([]byte, almost1K))
}

func BenchmarkAESCFBDecrypt8K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCFBDecrypter, make([]byte, almost8K))
}

func BenchmarkSM4CFBDecrypt8K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBDecrypter, make([]byte, almost8K))
}

func BenchmarkAESOFB1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewOFB, make([]byte, almost1K))
}

func BenchmarkSM4OFB1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewOFB, make([]byte, almost1K))
}

func BenchmarkAESCTR1K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCTR, make([]byte, almost1K))
}

func BenchmarkSM4CTR1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCTR, make([]byte, almost1K))
}

func BenchmarkAESCTR8K(b *testing.B) {
	benchmarkAESStream(b, cipher.NewCTR, make([]byte, almost8K))
}

func BenchmarkSM4CTR8K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCTR, make([]byte, almost8K))
}

func benchmarkGCMSign(b *testing.B, aead cipher.AEAD, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var nonce [12]byte
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], nil, buf)
	}
}

func benchmarkAESGCMSign(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	aesgcm, _ := cipher.NewGCM(c)
	benchmarkGCMSign(b, aesgcm, buf)
}

func benchmarkSM4GCMSign(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	benchmarkGCMSign(b, sm4gcm, buf)
}

func benchmarkGCMSeal(b *testing.B, aead cipher.AEAD, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var nonce [12]byte
	var ad [13]byte
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkAESGCMSeal(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	benchmarkGCMSeal(b, sm4gcm, buf)
}

func benchmarkSM4GCMSeal(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	benchmarkGCMSeal(b, sm4gcm, buf)
}

func benchmarkGCMOpen(b *testing.B, aead cipher.AEAD, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var nonce [12]byte
	var ad [13]byte
	var out []byte
	out = aead.Seal(out[:0], nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := aead.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func benchmarkAESGCMOpen(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	benchmarkGCMOpen(b, sm4gcm, buf)
}

func benchmarkSM4GCMOpen(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	benchmarkGCMOpen(b, sm4gcm, buf)
}

func BenchmarkAESGCMSeal1K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 1024))
}

func BenchmarkSM4GCMSeal1K(b *testing.B) {
	benchmarkSM4GCMSeal(b, make([]byte, 1024))
}

func BenchmarkAESGCMOpen1K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 1024))
}

func BenchmarkSM4GCMOpen1K(b *testing.B) {
	benchmarkSM4GCMOpen(b, make([]byte, 1024))
}

func BenchmarkAESGCMSign1K(b *testing.B) {
	benchmarkAESGCMSign(b, make([]byte, 1024))
}

func BenchmarkSM4GCMSign1K(b *testing.B) {
	benchmarkSM4GCMSign(b, make([]byte, 1024))
}

func BenchmarkAESGCMSign8K(b *testing.B) {
	benchmarkAESGCMSign(b, make([]byte, 8*1024))
}

func BenchmarkSM4GCMSign8K(b *testing.B) {
	benchmarkSM4GCMSign(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMSeal8K(b *testing.B) {
	benchmarkAESGCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkSM4GCMSeal8K(b *testing.B) {
	benchmarkSM4GCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkAESGCMOpen8K(b *testing.B) {
	benchmarkAESGCMOpen(b, make([]byte, 8*1024))
}

func BenchmarkSM4GCMOpen8K(b *testing.B) {
	benchmarkSM4GCMOpen(b, make([]byte, 8*1024))
}

func benchmarkAESCCMSign(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	aesccm, _ := smcipher.NewCCM(c)
	benchmarkGCMSign(b, aesccm, buf)
}

func benchmarkSM4CCMSign(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4ccm, _ := smcipher.NewCCM(c)
	benchmarkGCMSign(b, sm4ccm, buf)
}

func BenchmarkAESCCMSign1K(b *testing.B) {
	benchmarkAESCCMSign(b, make([]byte, 1024))
}

func BenchmarkSM4CCMSign1K(b *testing.B) {
	benchmarkSM4CCMSign(b, make([]byte, 1024))
}

func BenchmarkAESCCMSeal1K(b *testing.B) {
	benchmarkAESCCMSeal(b, make([]byte, 1024))
}

func BenchmarkSM4CCMSeal1K(b *testing.B) {
	benchmarkSM4CCMSeal(b, make([]byte, 1024))
}

func BenchmarkAESCCMOpen1K(b *testing.B) {
	benchmarkAESCCMOpen(b, make([]byte, 1024))
}

func BenchmarkSM4CCMOpen1K(b *testing.B) {
	benchmarkSM4CCMOpen(b, make([]byte, 1024))
}

func BenchmarkAESCCMSign8K(b *testing.B) {
	benchmarkAESCCMSign(b, make([]byte, 8*1024))
}

func BenchmarkSM4CCMSign8K(b *testing.B) {
	benchmarkSM4CCMSign(b, make([]byte, 8*1024))
}

func BenchmarkAESCCMSeal8K(b *testing.B) {
	benchmarkAESCCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkSM4CCMSeal8K(b *testing.B) {
	benchmarkSM4CCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkAESCCMOpen8K(b *testing.B) {
	benchmarkAESCCMOpen(b, make([]byte, 8*1024))
}

func BenchmarkSM4CCMOpen8K(b *testing.B) {
	benchmarkSM4CCMOpen(b, make([]byte, 8*1024))
}

func benchmarkAESCCMSeal(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	sm4gcm, _ := smcipher.NewCCM(c)
	benchmarkGCMSeal(b, sm4gcm, buf)
}

func benchmarkSM4CCMSeal(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := smcipher.NewCCM(c)
	benchmarkGCMSeal(b, sm4gcm, buf)
}

func benchmarkAESCCMOpen(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := aes.NewCipher(key[:])
	sm4gcm, _ := smcipher.NewCCM(c)
	benchmarkGCMOpen(b, sm4gcm, buf)
}

func benchmarkSM4CCMOpen(b *testing.B, buf []byte) {
	var key [16]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := smcipher.NewCCM(c)
	benchmarkGCMOpen(b, sm4gcm, buf)
}

func benchmarkXTS(b *testing.B, isGB bool, cipherFunc func([]byte) (cipher.Block, error), length, keylen int64) {
	plaintext := make([]byte, length)
	encrypted := make([]byte, length)
	var c cipher.BlockMode
	var err error
	if !isGB {
		c, err = smcipher.NewXTSEncrypterWithSector(cipherFunc, make([]byte, keylen), make([]byte, keylen), 0)
		if err != nil {
			b.Fatalf("NewCipher failed: %s", err)
		}
	} else {
		c, err = smcipher.NewGBXTSEncrypterWithSector(cipherFunc, make([]byte, keylen), make([]byte, keylen), 0)
		if err != nil {
			b.Fatalf("NewCipher failed: %s", err)
		}
	}

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.CryptBlocks(encrypted, plaintext)
	}
}

func BenchmarkAES128XTSEncrypt512(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 512, 16)
}

func BenchmarkAES128XTSEncrypt1K(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 1024, 16)
}

func BenchmarkAES128XTSEncrypt4K(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 4096, 16)
}

func BenchmarkAES256XTSEncrypt512(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 512, 32)
}

func BenchmarkAES256XTSEncrypt1K(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 1024, 32)
}

func BenchmarkAES256XTSEncrypt4K(b *testing.B) {
	benchmarkXTS(b, false, aes.NewCipher, 4096, 32)
}

func BenchmarkSM4XTSEncrypt512(b *testing.B) {
	benchmarkXTS(b, false, sm4.NewCipher, 512, 16)
}

func BenchmarkSM4XTSEncrypt1K(b *testing.B) {
	benchmarkXTS(b, false, sm4.NewCipher, 1024, 16)
}

func BenchmarkSM4XTSEncrypt4K(b *testing.B) {
	benchmarkXTS(b, false, sm4.NewCipher, 4096, 16)
}

func BenchmarkSM4XTSEncrypt512_GB(b *testing.B) {
	benchmarkXTS(b, true, sm4.NewCipher, 512, 16)
}

func BenchmarkSM4XTSEncrypt1K_GB(b *testing.B) {
	benchmarkXTS(b, true, sm4.NewCipher, 1024, 16)
}

func BenchmarkSM4XTSEncrypt4K_GB(b *testing.B) {
	benchmarkXTS(b, true, sm4.NewCipher, 4096, 16)
}

func benchmarkXTS_Decrypt(b *testing.B, isGB bool, cipherFunc func([]byte) (cipher.Block, error), length, keylen int64) {
	plaintext := make([]byte, length)
	encrypted := make([]byte, length)
	var c cipher.BlockMode
	var err error
	if !isGB {
		c, err = smcipher.NewXTSDecrypterWithSector(cipherFunc, make([]byte, keylen), make([]byte, keylen), 0)
		if err != nil {
			b.Fatalf("NewCipher failed: %s", err)
		}
	} else {
		c, err = smcipher.NewGBXTSDecrypterWithSector(cipherFunc, make([]byte, keylen), make([]byte, keylen), 0)
		if err != nil {
			b.Fatalf("NewCipher failed: %s", err)
		}
	}

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.CryptBlocks(plaintext, encrypted)
	}
}

func BenchmarkAES128XTSDecrypt512(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 512, 16)
}

func BenchmarkAES128XTSDecrypt1K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 1024, 16)
}

func BenchmarkAES128XTSDecrypt4K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 4096, 16)
}

func BenchmarkAES256XTSDecrypt512(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 512, 32)
}

func BenchmarkAES256XTSDecrypt1K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 1024, 32)
}

func BenchmarkAES256XTSDecrypt4K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, aes.NewCipher, 4096, 32)
}

func BenchmarkSM4XTSDecrypt512(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, sm4.NewCipher, 512, 16)
}

func BenchmarkSM4XTSDecrypt1K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, sm4.NewCipher, 1024, 16)
}

func BenchmarkSM4XTSDecrypt4K(b *testing.B) {
	benchmarkXTS_Decrypt(b, false, sm4.NewCipher, 4096, 16)
}

func BenchmarkSM4XTSDecrypt512_GB(b *testing.B) {
	benchmarkXTS_Decrypt(b, true, sm4.NewCipher, 512, 16)
}

func BenchmarkSM4XTSDecrypt1K_GB(b *testing.B) {
	benchmarkXTS_Decrypt(b, true, sm4.NewCipher, 1024, 16)
}

func BenchmarkSM4XTSDecrypt4K_GB(b *testing.B) {
	benchmarkXTS_Decrypt(b, true, sm4.NewCipher, 4096, 16)
}
