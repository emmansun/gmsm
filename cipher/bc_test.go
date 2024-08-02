package cipher_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/internal/cryptotest"
	"github.com/emmansun/gmsm/sm4"
)

var bcSM4TestVectors = []struct {
	key        string
	iv         string
	plaintext  string
	ciphertext string
}{
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
		"AC529AF989A62FCE9CDDC5FFB84125CAFB8CDE77339FFE481D113C40BBD5B6786FFC9916F98F94FF12D78319707E240428718707605BC1EAC503153EBAA0FB1D",
	},
}

func TestBC(t *testing.T) {
	for i, test := range bcSM4TestVectors {
		key, _ := hex.DecodeString(test.key)
		iv, _ := hex.DecodeString(test.iv)
		plaintext, _ := hex.DecodeString(test.plaintext)
		ciphertext, _ := hex.DecodeString(test.ciphertext)
		got := make([]byte, len(plaintext))
		c, err := sm4.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		encrypter := cipher.NewBCEncrypter(c, iv)
		encrypter.CryptBlocks(got, plaintext)
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("%v case encrypt failed, got %x\n", i+1, got)
		}

		decrypter := cipher.NewBCDecrypter(c, iv)
		decrypter.CryptBlocks(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%v case decrypt failed, got %x\n", i+1, got)
		}
	}
}

func TestSM4BCRandom(t *testing.T) {
	key, _ := hex.DecodeString(bcSM4TestVectors[0].key)
	iv := []byte("0123456789ABCDEF")
	c, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypter := cipher.NewBCEncrypter(c, iv)
	decrypter := cipher.NewBCDecrypter(c, iv)
	for i := 1; i <= 50; i++ {
		plaintext := make([]byte, i*16)
		ciphertext := make([]byte, i*16)
		got := make([]byte, i*16)
		io.ReadFull(rand.Reader, plaintext)
		encrypter.CryptBlocks(ciphertext, plaintext)
		decrypter.CryptBlocks(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Errorf("test %v blocks failed", i)
		}
	}
}

// Test BC Blockmode against the general cipher.BlockMode interface tester
func TestBCBlockMode(t *testing.T) {
	t.Run("SM4", func(t *testing.T) {
		rng := newRandReader(t)

		key := make([]byte, 16)
		rng.Read(key)

		block, err := sm4.NewCipher(key)
		if err != nil {
			panic(err)
		}

		cryptotest.TestBlockMode(t, block, cipher.NewBCEncrypter, cipher.NewBCDecrypter)
	})
}

func newRandReader(t *testing.T) io.Reader {
	seed := time.Now().UnixNano()
	t.Logf("Deterministic RNG seed: 0x%x", seed)
	return mrand.New(mrand.NewSource(seed))
}
