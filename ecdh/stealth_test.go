package ecdh

import (
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

// https://eips.ethereum.org/EIPS/eip-5564, but uses SM3 instead of Keccak256

// Generation - Generate stealth address from stealth meta-address
func generateStealthAddress(spendPub, viewPub *PublicKey) (ephemeralPub *PublicKey, stealth *PublicKey, err error) {
	// generate ephemeral key pair
	ephemeralPriv, err := P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ephemeralPub = ephemeralPriv.PublicKey()

	// compute shared secret key
	R, err := ephemeralPriv.SecretKey(viewPub)
	if err != nil {
		return nil, nil, err
	}

	// the secret key is hashed
	sh := sm3.Sum(R[1:])

	// multiply the hashed shared secret with the generator point
	shPriv, err := P256().GenerateKeyFromScalar(sh[:])
	if err != nil {
		return nil, nil, err
	}
	shPublic := shPriv.PublicKey()

	// compute the recipient's stealth public key
	stealth, err = shPublic.Add(spendPub)
	if err != nil {
		return nil, nil, err
	}
	return ephemeralPub, stealth, nil
}

// Parsing - Locate one’s own stealth address
func checkStealthAddress(viewPriv *PrivateKey, spendPub, ephemeralPub, stealth *PublicKey) (bool, error) {
	// compute shared secret key
	R, err := viewPriv.SecretKey(ephemeralPub)
	if err != nil {
		return false, err
	}
	// the secret key is hashed
	sh := sm3.Sum(R[1:])
	// multiply the hashed shared secret with the generator point
	shPriv, err := P256().GenerateKeyFromScalar(sh[:])
	if err != nil {
		return false, err
	}
	shPublic := shPriv.PublicKey()
	// compute the derived stealth address
	goStealth, err := shPublic.Add(spendPub)
	if err != nil {
		return false, err
	}
	// compare the derived stealth address with the provided stealth address
	return stealth.Equal(goStealth), nil
}

// Private key derivation - Generate the stealth address private key from the hashed shared secret and the spending private key.
func computeStealthKey(spendPriv, viewPriv *PrivateKey, ephemeralPub *PublicKey) (*PrivateKey, error) {
	// compute shared secret key
	R, err := viewPriv.SecretKey(ephemeralPub)
	if err != nil {
		return nil, err
	}
	// the secret key is hashed
	sh := sm3.Sum(R[1:])
	// multiply the hashed shared secret with the generator point
	shPriv, err := P256().GenerateKeyFromScalar(sh[:])
	if err != nil {
		return nil, err
	}
	return spendPriv.Add(shPriv)
}

func testEIP5564StealthAddress(t *testing.T, spendPriv, viewPriv *PrivateKey) {
	t.Helper()

	ephemeralPub, expectedStealth, err := generateStealthAddress(spendPriv.PublicKey(), viewPriv.PublicKey())

	if err != nil {
		t.Fatalf("the recipient's stealth public key: failed to add public keys: %v", err)
	}

	passed, err := checkStealthAddress(viewPriv, spendPriv.PublicKey(), ephemeralPub, expectedStealth)
	if err != nil {
		t.Fatal(err)
	}
	if !passed {
		t.Fatal("mismatched stealth address")
	}

	privStealth, err := computeStealthKey(spendPriv, viewPriv, ephemeralPub)
	if err != nil {
		t.Fatalf("failed to compute stealth key: %v", err)
	}
	if !privStealth.PublicKey().Equal(expectedStealth) {
		t.Fatal("mismatched stealth key")
	}
}

func TestEIP5564StealthAddress(t *testing.T) {
	privSpend, err := P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	privView, err := P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	testEIP5564StealthAddress(t, privSpend, privView)
}
