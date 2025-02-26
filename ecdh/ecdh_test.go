package ecdh_test

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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

func hexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid hex string:", s)
	}
	return b
}

func TestNewPrivateKey(t *testing.T) {
	_, err := ecdh.P256().NewPrivateKey(nil)
	if err == nil || err.Error() != "ecdh: invalid private key size" {
		t.Errorf("ecdh: invalid private key size")
	}
	_, err = ecdh.P256().NewPrivateKey([]byte{
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41})
	if err == nil || err.Error() != "ecdh: invalid private key size" {
		t.Errorf("ecdh: invalid private key size")
	}
	allzero := make([]byte, 32)
	_, err = ecdh.P256().NewPrivateKey(allzero)
	if err == nil || err.Error() != "ecdh: invalid private key" {
		t.Errorf("expected invalid private key")
	}
	_, err = ecdh.P256().NewPrivateKey([]byte{
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x22})
	if err == nil || err.Error() != "ecdh: invalid private key" {
		t.Errorf("expected invalid private key")
	}
}

func TestNewPublicKey(t *testing.T) {
	_, err := ecdh.P256().NewPublicKey(nil)
	if err == nil || err.Error() != "ecdh: invalid public key" {
		t.Errorf("ecdh: invalid public key")
	}
	keydata := make([]byte, 65)
	_, err = ecdh.P256().NewPublicKey(keydata)
	if err == nil || err.Error() != "ecdh: invalid public key" {
		t.Errorf("ecdh: invalid public key")
	}
}

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

	bobSecret, err := bobKey.ECDH(aliceKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	aliceSecret, err := aliceKey.ECDH(bobKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bobSecret, aliceSecret) {
		t.Error("two ECDH computations came out different")
	}
}

func TestSM2MQV(t *testing.T) {
	aliceSKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceEKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bobSKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bobSecret, err := bobSKey.SM2MQV(bobEKey, aliceSKey.PublicKey(), aliceEKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	aliceSecret, err := aliceSKey.SM2MQV(aliceEKey, bobSKey.PublicKey(), bobEKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !aliceSecret.Equal(bobSecret) {
		t.Error("two SM2MQV computations came out different")
	}
}

func TestSM2SharedKey(t *testing.T) {
	aliceSKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceEKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bobSKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobEKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	bobSecret, err := bobSKey.SM2MQV(bobEKey, aliceSKey.PublicKey(), aliceEKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	aliceSecret, err := aliceSKey.SM2MQV(aliceEKey, bobSKey.PublicKey(), bobEKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !aliceSecret.Equal(bobSecret) {
		t.Error("two SM2MQV computations came out different")
	}

	bobKey, err := bobSecret.SM2SharedKey(true, 48, bobSKey.PublicKey(), aliceSKey.PublicKey(), []byte("Bob"), []byte("Alice"))
	if err != nil {
		t.Fatal(err)
	}

	aliceKey, err := aliceSecret.SM2SharedKey(false, 48, aliceSKey.PublicKey(), bobSKey.PublicKey(), []byte("Alice"), []byte("Bob"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(bobKey, aliceKey) {
		t.Error("two SM2SharedKey computations came out different")
	}
}

var vectors = []struct {
	LocalStaticPriv, LocalEphemeralPriv   string
	RemoteStaticPriv, RemoteEphemeralPriv string
	SharedSecret, Key                     string
}{
	{
		"e04c3fd77408b56a648ad439f673511a2ae248def3bab26bdfc9cdbd0ae9607e",
		"6fe0bac5b09d3ab10f724638811c34464790520e4604e71e6cb0e5310623b5b1",
		"7a1136f60d2c5531447e5a3093078c2a505abf74f33aefed927ac0a5b27e7dd7",
		"d0233bdbb0b8a7bfe1aab66132ef06fc4efaedd5d5000692bc21185242a31f6f",
		"046ab5c9709277837cedc515730d04751ef81c71e81e0e52357a98cf41796ab560508da6e858b40c6264f17943037434174284a847f32c4f54104a98af5148d89f",
		"1ad809ebc56ddda532020c352e1e60b121ebeb7b4e632db4dd90a362cf844f8bba85140e30984ddb581199bf5a9dda22",
	},
	{
		"cb5ac204b38d0e5c9fc38a467075986754018f7dbb7cbbc5b4c78d56a88a8ad8",
		"1681a66c02b67fdadfc53cba9b417b9499d0159435c86bb8760c3a03ae157539",
		"4f54b10e0d8e9e2fe5cc79893e37fd0fd990762d1372197ed92dde464b2773ef",
		"a2fe43dea141e9acc88226eaba8908ad17e81376c92102cb8186e8fef61a8700",
		"04677d055355a1dcc9de4df00d3a80b6daa76bdf54ff7e0a3a6359fcd0c6f1e4b4697fffc41bbbcc3a28ea3aa1c6c380d1e92f142233afa4b430d02ab4cebc43b2",
		"7a103ae61a30ed9df573a5febb35a9609cbed5681bcb98a8545351bf7d6824cc4635df5203712ea506e2e3c4ec9b12e7",
	},
	{
		"ee690a34a779ab48227a2f68b062a80f92e26d82835608dd01b7452f1e4fb296",
		"2046c6cee085665e9f3abeba41fd38e17a26c08f2f5e8f0e1007afc0bf6a2a5d",
		"8ef49ea427b13cc31151e1c96ae8a48cb7919063f2d342560fb7eaaffb93d8fe",
		"9baf8d602e43fbae83fedb7368f98c969d378b8a647318f8cafb265296ae37de",
		"04f7e9f1447968b284ff43548fcec3752063ea386b48bfabb9baf2f9c1caa05c2fb12c2cca37326ce27e68f8cc6414c2554895519c28da1ca21e61890d0bc525c4",
		"b18e78e5072f301399dc1f4baf2956c0ed2d5f52f19abb1705131b0865b079031259ee6c629b4faed528bcfa1c5d2cbc",
	},
}

func TestSM2SharedKeyVectors(t *testing.T) {
	initiator := []byte("Alice")
	responder := []byte("Bob")
	kenLen := 48

	for i, v := range vectors {
		aliceSKey, err := ecdh.P256().NewPrivateKey(hexDecode(t, v.LocalStaticPriv))
		if err != nil {
			t.Fatal(err)
		}
		aliceEKey, err := ecdh.P256().NewPrivateKey(hexDecode(t, v.LocalEphemeralPriv))
		if err != nil {
			t.Fatal(err)
		}
		bobSKey, err := ecdh.P256().NewPrivateKey(hexDecode(t, v.RemoteStaticPriv))
		if err != nil {
			t.Fatal(err)
		}
		bobEKey, err := ecdh.P256().NewPrivateKey(hexDecode(t, v.RemoteEphemeralPriv))
		if err != nil {
			t.Fatal(err)
		}

		bobSecret, err := bobSKey.SM2MQV(bobEKey, aliceSKey.PublicKey(), aliceEKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		aliceSecret, err := aliceSKey.SM2MQV(aliceEKey, bobSKey.PublicKey(), bobEKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		if !aliceSecret.Equal(bobSecret) {
			t.Error("two SM2MQV computations came out different")
		}

		if !bytes.Equal(aliceSecret.Bytes(), hexDecode(t, v.SharedSecret)) {
			t.Errorf("%v shared secret is not expected.", i)
		}

		bobKey, err := bobSecret.SM2SharedKey(true, kenLen, bobSKey.PublicKey(), aliceSKey.PublicKey(), responder, initiator)
		if err != nil {
			t.Fatal(err)
		}

		aliceKey, err := aliceSecret.SM2SharedKey(false, kenLen, aliceSKey.PublicKey(), bobSKey.PublicKey(), initiator, responder)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(bobKey, aliceKey) {
			t.Error("two SM2SharedKey computations came out different")
		}

		if !bytes.Equal(bobKey, hexDecode(t, v.Key)) {
			t.Errorf("%v keying data is not expected.", i)
		}
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
			secret, err := key.ECDH(peerPubKey)
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
	clear(dst)
	return len(dst), nil
}

var zeroReader = zr{}
