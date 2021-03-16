package sm4_test

import (
	"crypto/cipher"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

func BenchmarkSM4CBCEncrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	c, _ := sm4.NewCipher(key[:])
	cbc := cipher.NewCBCEncrypter(c, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func BenchmarkSM4CBCDecrypt1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	c, _ := sm4.NewCipher(key[:])
	cbc := cipher.NewCBCDecrypter(c, iv[:])
	for i := 0; i < b.N; i++ {
		cbc.CryptBlocks(buf, buf)
	}
}

func benchmarkSM4Stream(b *testing.B, mode func(cipher.Block, []byte) cipher.Stream, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	c, _ := sm4.NewCipher(key[:])
	stream := mode(c, iv[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.XORKeyStream(buf, buf)
	}
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5
const almost8K = 8*1024 - 5

func BenchmarkSM4CFBEncrypt1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBEncrypter, make([]byte, almost1K))
}

func BenchmarkSM4CFBDecrypt1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBDecrypter, make([]byte, almost1K))
}

func BenchmarkSM4CFBDecrypt8K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCFBDecrypter, make([]byte, almost8K))
}

func BenchmarkSM4OFB1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewOFB, make([]byte, almost1K))
}

func BenchmarkSM4CTR1K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCTR, make([]byte, almost1K))
}

func BenchmarkSM4CTR8K(b *testing.B) {
	benchmarkSM4Stream(b, cipher.NewCTR, make([]byte, almost8K))
}

func benchmarkSM4GCMSign(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = sm4gcm.Seal(out[:0], nonce[:], nil, buf)
	}
}

func benchmarkSM4GCMSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	var out []byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = sm4gcm.Seal(out[:0], nonce[:], buf, ad[:])
	}
}

func benchmarkSM4GCMOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var nonce [12]byte
	var ad [13]byte
	c, _ := sm4.NewCipher(key[:])
	sm4gcm, _ := cipher.NewGCM(c)
	var out []byte
	out = sm4gcm.Seal(out[:0], nonce[:], buf, ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm4gcm.Open(buf[:0], nonce[:], out, ad[:])
		if err != nil {
			b.Errorf("Open: %v", err)
		}
	}
}

func BenchmarkSM4GCMSeal1K(b *testing.B) {
	benchmarkSM4GCMSeal(b, make([]byte, 1024))
}

func BenchmarkSM4GCMOpen1K(b *testing.B) {
	benchmarkSM4GCMOpen(b, make([]byte, 1024))
}

func BenchmarkSM4GCMSign1K(b *testing.B) {
	benchmarkSM4GCMSign(b, make([]byte, 1024))
}

func BenchmarkSM4GCMSign8K(b *testing.B) {
	benchmarkSM4GCMSign(b, make([]byte, 8*1024))
}

func BenchmarkSM4GCMSeal8K(b *testing.B) {
	benchmarkSM4GCMSeal(b, make([]byte, 8*1024))
}

func BenchmarkSM4GCMOpen8K(b *testing.B) {
	benchmarkSM4GCMOpen(b, make([]byte, 8*1024))
}
