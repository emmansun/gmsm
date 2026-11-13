package sm9

import (
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/internal/sm9/bn256"
)

func TestMasterPrivateKeyAllowsOrderMinusOne(t *testing.T) {
	key := append([]byte(nil), bn256.OrderMinus1Bytes...)
	if _, err := NewSignMasterPrivateKey(key); err != nil {
		t.Fatalf("NewSignMasterPrivateKey(N-1): %v", err)
	}
	if _, err := NewEncryptMasterPrivateKey(key); err != nil {
		t.Fatalf("NewEncryptMasterPrivateKey(N-1): %v", err)
	}
}

func BenchmarkGenerateSignPrivKey(b *testing.B) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := masterKey.GenerateUserKey(uid, hid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateEncryptPrivKey(b *testing.B) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := masterKey.GenerateUserKey(uid, hid); err != nil {
			b.Fatal(err)
		}
	}
}
