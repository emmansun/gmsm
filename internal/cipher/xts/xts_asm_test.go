//go:build (amd64 || arm64 || s390x || ppc64 || ppc64le || riscv64) && !purego

package xts

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

var testTweakVector = []string{
	"00000000000000000000000000000000",
	"ffffffffffffffffffffffffffffffff",
	"00000000000000000000000000000080",
	"00000000000000000000000000000001",
	"80000000000000000000000000000000",
	"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
	"66e94bd4ef8a2c3b884cfa59ca342b2e",
	"3f803bcd0d7fd2b37558419f59d5cda6",
	"6dcfba212f5d82bf525ee9793cfa505a",
	"c172964cd58be2b8d8e09d9c5e9cfe36",
	"1a267577a90caad6ae988e22714a2b8b",
	"33fab707493702e77ff8d66ba9e6c6fe",
	"23fb188b0f87f6ee2ec0803a99771341",
	"e8de0a4188b7efbc1ac3979eb906cf36",
}

func testDoubleTweak(t *testing.T, isGB bool) {
	for _, tk := range testTweakVector {
		tweak, _ := hex.DecodeString(tk)

		var t1, t2 [16]byte
		copy(t1[:], tweak)
		copy(t2[:], tweak)
		for step := 0; step < 256; step++ {
			mul2(&t1, isGB)
			mul2Generic(&t2, isGB)
			if t1 != t2 {
				t.Fatalf("isGB %v tweak %v step %d, expected %x, got %x", isGB, tk, step, t2, t1)
			}
		}
	}
}

func TestDoubleTweak(t *testing.T) {
	testDoubleTweak(t, false)
}

func TestDoubleTweakGB(t *testing.T) {
	testDoubleTweak(t, true)
}

func testDoubleTweakRandomly(t *testing.T, isGB bool) {
	var tweak, t1, t2 [16]byte
	io.ReadFull(rand.Reader, tweak[:])
	copy(t1[:], tweak[:])
	copy(t2[:], tweak[:])
	mul2(&t1, isGB)
	mul2Generic(&t2, isGB)

	if !bytes.Equal(t1[:], t2[:]) {
		t.Errorf("tweak %x, expected %x, got %x", tweak[:], t2[:], t1[:])
	}
}

func TestDoubleTweakRandomly(t *testing.T) {
	for i := 0; i < 10; i++ {
		testDoubleTweakRandomly(t, false)
	}
}

func TestDoubleTweakGBRandomly(t *testing.T) {
	for i := 0; i < 10; i++ {
		testDoubleTweakRandomly(t, true)
	}
}

func testDoubleTweaks(t *testing.T, isGB bool) {
	for _, tk := range testTweakVector {
		tweak, _ := hex.DecodeString(tk)

		for _, count := range []int{1, 2, 3, 4, 7, 8} {
			var t1, t2 [blockSize]byte
			copy(t1[:], tweak)
			copy(t2[:], tweak)
			for batch := 0; batch < 4; batch++ {
				var got, want [10 * blockSize]byte
				for i := range got {
					got[i], want[i] = 0xa5, 0xa5
				}
				end := blockSize + count*blockSize
				for i := 0; i < count; i++ {
					copy(want[blockSize+i*blockSize:], t2[:])
					mul2Generic(&t2, isGB)
				}
				doubleTweaks(&t1, got[blockSize:end:end], isGB)
				if t1 != t2 {
					t.Fatalf("isGB %v tweak %v count %d batch %d, expected final %x, got %x", isGB, tk, count, batch, t2, t1)
				}
				if got != want {
					t.Fatalf("isGB %v tweak %v count %d batch %d, output or guard mismatch: expected %x, got %x", isGB, tk, count, batch, want, got)
				}
			}
		}
	}
}

func TestDoubleTweaks(t *testing.T) {
	testDoubleTweaks(t, false)
}

func TestDoubleTweaksGB(t *testing.T) {
	testDoubleTweaks(t, true)
}

type concurrentTestBlock struct {
	cipher.Block
}

func (b *concurrentTestBlock) Concurrency() int { return 4 }

func (b *concurrentTestBlock) EncryptBlocks(dst, src []byte) {
	if len(dst) != b.Concurrency()*blockSize || len(src) != b.Concurrency()*blockSize {
		panic("unexpected concurrent encryption batch size")
	}
	for range b.Concurrency() {
		b.Encrypt(dst, src)
		dst = dst[blockSize:]
		src = src[blockSize:]
	}
}

func (b *concurrentTestBlock) DecryptBlocks(dst, src []byte) {
	if len(dst) != b.Concurrency()*blockSize || len(src) != b.Concurrency()*blockSize {
		panic("unexpected concurrent decryption batch size")
	}
	for range b.Concurrency() {
		b.Decrypt(dst, src)
		dst = dst[blockSize:]
		src = src[blockSize:]
	}
}

func newConcurrentTestBlock(key []byte) (cipher.Block, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &concurrentTestBlock{Block: b}, nil
}

func TestConcurrentDecryptCTSBoundary(t *testing.T) {
	key := make([]byte, 16)
	tweakKey := make([]byte, 16)
	tweak := make([]byte, 16)
	lengths := []int{64, 65, 79, 80, 81, 127, 128, 129, 143, 144, 145}
	for _, isGB := range []bool{false, true} {
		for _, length := range lengths {
			plaintext := make([]byte, length)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}
			encrypter, err := NewXTSEncrypter(newConcurrentTestBlock, key, tweakKey, tweak, isGB)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := make([]byte, length)
			encrypter.CryptBlocks(ciphertext, plaintext)

			decrypter, err := NewXTSDecrypter(newConcurrentTestBlock, key, tweakKey, tweak, isGB)
			if err != nil {
				t.Fatal(err)
			}
			decrypted := make([]byte, length)
			decrypter.CryptBlocks(decrypted, ciphertext)
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("isGB %v, length %d: decryption mismatch", isGB, length)
			}
		}
	}
}
