package ecdh_test

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/emmansun/gmsm/ecdh"
	"golang.org/x/crypto/chacha20"
)

// Check that PublicKey and PrivateKey implement the interfaces documented in
// crypto.PublicKey and crypto.PrivateKey.
var _ interface {
	Equal(x crypto.PublicKey) bool
} = &ecdh.PublicKey{}
var _ interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
} = &ecdh.PrivateKey{}

func TestECDH(t *testing.T) {
	aliceKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	alicePubKey, err := ecdh.P256().NewPublicKey(aliceKey.PublicKey().Bytes())
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(aliceKey.PublicKey().Bytes(), alicePubKey.Bytes()) {
		t.Error("encoded and decoded public keys are different")
	}
	if !aliceKey.PublicKey().Equal(alicePubKey) {
		t.Error("encoded and decoded public keys are different")
	}

	alicePrivKey, err := ecdh.P256().NewPrivateKey(aliceKey.Bytes())
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(aliceKey.Bytes(), alicePrivKey.Bytes()) {
		t.Error("encoded and decoded private keys are different")
	}
	if !aliceKey.Equal(alicePrivKey) {
		t.Error("encoded and decoded private keys are different")
	}

	bobSecret, err := ecdh.P256().ECDH(bobKey, aliceKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	aliceSecret, err := ecdh.P256().ECDH(aliceKey, bobKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bobSecret, aliceSecret) {
		t.Error("two ECDH computations came out different")
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func TestGenerateKey(t *testing.T) {
	r := &countingReader{r: rand.Reader}
	k, err := ecdh.P256().GenerateKey(r)
	if err != nil {
		t.Fatal(err)
	}

	// GenerateKey does rejection sampling. If the masking works correctly,
	// the probability of a rejection is 1-ord(G)/2^ceil(log2(ord(G))),
	// which for all curves is small enough (at most 2^-32, for P-256) that
	// a bit flip is more likely to make this test fail than bad luck.
	// Account for the extra MaybeReadByte byte, too.
	if got, expected := r.n, len(k.Bytes())+1; got > expected {
		t.Errorf("expected GenerateKey to consume at most %v bytes, got %v", expected, got)
	}
}

func TestString(t *testing.T) {
	s := fmt.Sprintf("%s", ecdh.P256())
	if s != "sm2p256v1" {
		t.Errorf("unexpected Curve string encoding: %q", s)
	}
}

func BenchmarkECDH(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve ecdh.Curve) {
		c, err := chacha20.NewUnauthenticatedCipher(make([]byte, 32), make([]byte, 12))
		if err != nil {
			b.Fatal(err)
		}
		rand := cipher.StreamReader{
			S: c, R: zeroReader,
		}

		peerKey, err := curve.GenerateKey(rand)
		if err != nil {
			b.Fatal(err)
		}
		peerShare := peerKey.PublicKey().Bytes()
		b.ResetTimer()
		b.ReportAllocs()

		var allocationsSink byte

		for i := 0; i < b.N; i++ {
			key, err := curve.GenerateKey(rand)
			if err != nil {
				b.Fatal(err)
			}
			share := key.PublicKey().Bytes()
			peerPubKey, err := curve.NewPublicKey(peerShare)
			if err != nil {
				b.Fatal(err)
			}
			secret, err := curve.ECDH(key, peerPubKey)
			if err != nil {
				b.Fatal(err)
			}
			allocationsSink ^= secret[0] ^ share[0]
		}
	})
}

func benchmarkAllCurves(b *testing.B, f func(b *testing.B, curve ecdh.Curve)) {
	b.Run("SM2P256", func(b *testing.B) { f(b, ecdh.P256()) })
}

type zr struct{}

// Read replaces the contents of dst with zeros. It is safe for concurrent use.
func (zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = zr{}
