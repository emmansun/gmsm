//go:build !purego && (amd64 || arm64)

package sm2

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestSignVerifyLegacy(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashed := sm3.Sum([]byte(tt.plainText))
			r, s, err := Sign(rand.Reader, priv, hashed[:])
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := Verify(&priv.PublicKey, hashed[:], r, s)
			if !result {
				t.Fatal("verify failed")
			}
			hashed[0] ^= 0xff
			if Verify(&priv.PublicKey, hashed[:], r, s) {
				t.Errorf("VerifyASN1 always works!")
			}
		})
	}
}

func TestSignVerifyWithSM2Legacy(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tests := []struct {
		name      string
		plainText string
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard"},
		{"equals 32", "encryption standard encryption "},
		{"long than 32", "encryption standard encryption standard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, s, err := SignWithSM2(rand.Reader, priv, nil, []byte(tt.plainText))
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := VerifyWithSM2(&priv.PublicKey, nil, []byte(tt.plainText), r, s)
			if !result {
				t.Fatal("verify failed")
			}
		})
	}
}

func BenchmarkGenerateKey_P256(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.GenerateKey(elliptic.P256(), r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_P256(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := ecdsa.SignASN1(rand.Reader, priv, hashed)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkVerify_P256(b *testing.B) {
	rd := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rd)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := ecdsa.Sign(rand.Reader, priv, hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ecdsa.Verify(&priv.PublicKey, hashed, r, s) {
			b.Fatal("verify failed")
		}
	}
}
