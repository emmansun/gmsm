package smx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/mldsa"
	"github.com/emmansun/gmsm/slhdsa"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
)

func TestPKCS8RoundTripGMSMECDHPrivateKey(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}
	ecdhKey, err := sm2Key.ECDH()
	if err != nil {
		t.Fatalf("failed to convert SM2 key to ECDH key: %v", err)
	}

	der, err := MarshalPKCS8PrivateKey(ecdhKey)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 for gmsm ECDH key: %v", err)
	}

	parsed, err := ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("failed to parse PKCS#8 for gmsm ECDH key: %v", err)
	}
	parsedSM2, ok := parsed.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("unexpected parsed key type: %T", parsed)
	}
	parsedECDH, err := parsedSM2.ECDH()
	if err != nil {
		t.Fatalf("failed to convert parsed key to ECDH: %v", err)
	}
	if !bytes.Equal(parsedECDH.Bytes(), ecdhKey.Bytes()) {
		t.Fatal("parsed ECDH private key bytes do not match original")
	}
}

func TestPKCS8RoundTripSM9PrivateKeys(t *testing.T) {
	t.Run("SM9SignPrivateKey", func(t *testing.T) {
		master, err := sm9.GenerateSignMasterKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate SM9 sign master key: %v", err)
		}
		key, err := master.GenerateUserKey([]byte("alice"), 1)
		if err != nil {
			t.Fatalf("failed to generate SM9 sign user key: %v", err)
		}

		der, err := MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("failed to marshal SM9 sign private key: %v", err)
		}
		parsed, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("failed to parse SM9 sign private key: %v", err)
		}
		parsedKey, ok := parsed.(*sm9.SignPrivateKey)
		if !ok {
			t.Fatalf("unexpected parsed SM9 sign key type: %T", parsed)
		}

		want, err := key.MarshalASN1()
		if err != nil {
			t.Fatalf("failed to marshal original SM9 sign key ASN.1: %v", err)
		}
		got, err := parsedKey.MarshalASN1()
		if err != nil {
			t.Fatalf("failed to marshal parsed SM9 sign key ASN.1: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("parsed SM9 sign key does not match original")
		}
	})

	t.Run("SM9EncryptPrivateKey", func(t *testing.T) {
		master, err := sm9.GenerateEncryptMasterKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate SM9 encrypt master key: %v", err)
		}
		key, err := master.GenerateUserKey([]byte("alice"), 1)
		if err != nil {
			t.Fatalf("failed to generate SM9 encrypt user key: %v", err)
		}

		der, err := MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("failed to marshal SM9 encrypt private key: %v", err)
		}
		parsed, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("failed to parse SM9 encrypt private key: %v", err)
		}
		parsedKey, ok := parsed.(*sm9.EncryptPrivateKey)
		if !ok {
			t.Fatalf("unexpected parsed SM9 encrypt key type: %T", parsed)
		}

		want, err := key.MarshalASN1()
		if err != nil {
			t.Fatalf("failed to marshal original SM9 encrypt key ASN.1: %v", err)
		}
		got, err := parsedKey.MarshalASN1()
		if err != nil {
			t.Fatalf("failed to marshal parsed SM9 encrypt key ASN.1: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("parsed SM9 encrypt key does not match original")
		}
	})
}

func TestPKIXPublicKeyRoundTripMLDSAAndSLHDSA(t *testing.T) {
	t.Run("MLDSA44", func(t *testing.T) {
		key, err := mldsa.GenerateKey44(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate MLDSA44 key: %v", err)
		}
		pub := key.Public()
		der, err := MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("failed to marshal MLDSA44 public key: %v", err)
		}
		parsed, err := ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("failed to parse MLDSA44 public key: %v", err)
		}
		parsedPub, ok := parsed.(*mldsa.PublicKey44)
		if !ok {
			t.Fatalf("unexpected parsed MLDSA44 public key type: %T", parsed)
		}
		if !parsedPub.Equal(pub) {
			t.Fatal("parsed MLDSA44 public key does not match original")
		}
	})

	t.Run("SLHDSA", func(t *testing.T) {
		params, ok := slhdsa.GetParameterSet("SLH-DSA-SHA2-128s")
		if !ok {
			t.Fatal("failed to get SLH-DSA parameter set")
		}
		sk, err := slhdsa.GenerateKey(rand.Reader, params)
		if err != nil {
			t.Fatalf("failed to generate SLH-DSA key: %v", err)
		}
		pub := sk.Public().(*slhdsa.PublicKey)

		der, err := MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("failed to marshal SLH-DSA public key: %v", err)
		}
		parsed, err := ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("failed to parse SLH-DSA public key: %v", err)
		}
		parsedPub, ok := parsed.(*slhdsa.PublicKey)
		if !ok {
			t.Fatalf("unexpected parsed SLH-DSA public key type: %T", parsed)
		}
		if !bytes.Equal(parsedPub.Bytes(), pub.Bytes()) {
			t.Fatal("parsed SLH-DSA public key does not match original")
		}
	})
}

func TestPKCS8RoundTripMLDSAAndSLHDSA(t *testing.T) {
	t.Run("MLDSA44", func(t *testing.T) {
		key, err := mldsa.GenerateKey44(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate MLDSA44 key: %v", err)
		}
		der, err := MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("failed to marshal MLDSA44 private key: %v", err)
		}
		parsed, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("failed to parse MLDSA44 private key: %v", err)
		}
		parsedKey, ok := parsed.(*mldsa.Key44)
		if !ok {
			t.Fatalf("unexpected parsed MLDSA44 private key type: %T", parsed)
		}
		if !bytes.Equal(parsedKey.Bytes(), key.Bytes()) {
			t.Fatal("parsed MLDSA44 private key does not match original")
		}
	})

	t.Run("SLHDSA", func(t *testing.T) {
		params, ok := slhdsa.GetParameterSet("SLH-DSA-SHA2-128s")
		if !ok {
			t.Fatal("failed to get SLH-DSA parameter set")
		}
		sk, err := slhdsa.GenerateKey(rand.Reader, params)
		if err != nil {
			t.Fatalf("failed to generate SLH-DSA key: %v", err)
		}
		der, err := MarshalPKCS8PrivateKey(sk)
		if err != nil {
			t.Fatalf("failed to marshal SLH-DSA private key: %v", err)
		}
		parsed, err := ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatalf("failed to parse SLH-DSA private key: %v", err)
		}
		parsedKey, ok := parsed.(*slhdsa.PrivateKey)
		if !ok {
			t.Fatalf("unexpected parsed SLH-DSA private key type: %T", parsed)
		}
		if !bytes.Equal(parsedKey.Bytes(), sk.Bytes()) {
			t.Fatal("parsed SLH-DSA private key does not match original")
		}
	})
}

func TestParsePKIXPublicKeySM2ReturnsECDSA(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}
	der, err := MarshalPKIXPublicKey(&sm2Key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal SM2 public key: %v", err)
	}
	parsed, err := ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("failed to parse SM2 public key: %v", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected parsed public key type: %T", parsed)
	}
	if pub.Curve != sm2.P256() || pub.X.Cmp(sm2Key.X) != 0 || pub.Y.Cmp(sm2Key.Y) != 0 {
		t.Fatal("parsed SM2 public key does not match original")
	}
}
