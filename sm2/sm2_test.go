package sm2

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestNewPrivateKey(t *testing.T) {
	c := p256()
	// test nil
	_, err := NewPrivateKey(nil)
	if err == nil || err.Error() != "sm2: invalid private key size" {
		t.Errorf("should throw sm2: invalid private key size")
	}
	// test all zero
	key := make([]byte, c.N.Size())
	_, err = NewPrivateKey(key)
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test N-1
	_, err = NewPrivateKey(c.nMinus1.Bytes(c.N))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test N
	_, err = NewPrivateKey(P256().Params().N.Bytes())
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
	// test 1
	key[31] = 1
	_, err = NewPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// test N-2
	_, err = NewPrivateKey(c.nMinus2)
	if err != nil {
		t.Error(err)
	}
}

func TestNewPrivateKeyFromInt(t *testing.T) {
	// test nil
	_, err := NewPrivateKeyFromInt(nil)
	if err == nil || err.Error() != "sm2: invalid private key size" {
		t.Errorf("should throw sm2: invalid private key size")
	}
	// test 1
	_, err = NewPrivateKeyFromInt(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	// test N
	_, err = NewPrivateKeyFromInt(P256().Params().N)
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}

	// test N + 1
	_, err = NewPrivateKeyFromInt(new(big.Int).Add(P256().Params().N, big.NewInt(1)))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}

	c := p256()
	// test N - 1
	_, err = NewPrivateKeyFromInt(new(big.Int).SetBytes(c.nMinus1.Bytes(c.N)))
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("should throw errInvalidPrivateKey")
	}
}

func TestNewPublicKey(t *testing.T) {
	// test nil
	_, err := NewPublicKey(nil)
	if err == nil || err.Error() != "sm2: invalid public key" {
		t.Errorf("should throw sm2: invalid public key")
	}
	// test without point format prefix byte
	keypoints, _ := hex.DecodeString("8356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	_, err = NewPublicKey(keypoints)
	if err == nil || err.Error() != "sm2: invalid public key" {
		t.Errorf("should throw sm2: invalid public key")
	}
	// test correct point
	keypoints, _ = hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
	_, err = NewPublicKey(keypoints)
	if err != nil {
		t.Fatal(err)
	}
	// test point not on curve
	keypoints, _ = hex.DecodeString("048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba2")
	_, err = NewPublicKey(keypoints)
	if err == nil || err.Error() != "point not on SM2 P256 curve" {
		t.Errorf("should throw point not on SM2 P256 curve, got %v", err)
	}
}

func TestSplicingOrder(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name      string
		plainText string
		from      ciphertextSplicingOrder
		to        ciphertextSplicingOrder
	}{
		// TODO: Add test cases.
		{"less than 32 1", "encryption standard", C1C2C3, C1C3C2},
		{"less than 32 2", "encryption standard", C1C3C2, C1C2C3},
		{"equals 32 1", "encryption standard encryption ", C1C2C3, C1C3C2},
		{"equals 32 2", "encryption standard encryption ", C1C3C2, C1C2C3},
		{"long than 32 1", "encryption standard encryption standard", C1C2C3, C1C3C2},
		{"long than 32 2", "encryption standard encryption standard", C1C3C2, C1C2C3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), NewPlainEncrypterOpts(MarshalUncompressed, tt.from))
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, NewPlainDecrypterOpts(tt.from))
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			//Adjust splicing order
			ciphertext, err = AdjustCiphertextSplicingOrder(ciphertext, tt.from, tt.to)
			if err != nil {
				t.Fatalf("adjust splicing order failed %v", err)
			}
			plaintext, err = priv.Decrypt(rand.Reader, ciphertext, NewPlainDecrypterOpts(tt.to))
			if err != nil {
				t.Fatalf("decrypt failed after adjust splicing order %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func TestEncryptDecryptASN1(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2 := new(PrivateKey)
	key2.PrivateKey = *priv2
	tests := []struct {
		name      string
		plainText string
		priv      *PrivateKey
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard", priv},
		{"equals 32", "encryption standard encryption ", priv},
		{"long than 32", "encryption standard encryption standard", priv},
		{"less than 32", "encryption standard", key2},
		{"equals 32", "encryption standard encryption ", key2},
		{"long than 32", "encryption standard encryption standard", key2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypterOpts := ASN1EncrypterOpts
			ciphertext, err := Encrypt(rand.Reader, &tt.priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("%v encrypt failed %v", tt.priv.Curve.Params().Name, err)
			}
			plaintext, err := tt.priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("%v decrypt 1 failed %v", tt.priv.Curve.Params().Name, err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
			plaintext, err = tt.priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("%v decrypt 2 failed %v", tt.priv.Curve.Params().Name, err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func TestPlainCiphertext2ASN1(t *testing.T) {
	ciphertext, _ := hex.DecodeString("047928e22045eec8dc00e95639dd0c1c8dfb75cf8cedcf496731a6a6f423baa54c5014c60b73495886d8d7bc996a4a716cb58e6bfc8e03078b24e7b0f5cba0efd5b9272c27fc263bb59eaca6eabc97c0323bf1de953aeabaf59700b3bf49c9a1056decc08dd18544960541a2239afa7b1512df05")
	_, err := PlainCiphertext2ASN1(append([]byte{0x30}, ciphertext...), C1C3C2)
	if err == nil {
		t.Fatalf("expected error")
	}
	_, err = PlainCiphertext2ASN1(ciphertext[:65], C1C3C2)
	if err == nil {
		t.Fatalf("expected error")
	}
	ciphertext[0] = 0x10
	_, err = PlainCiphertext2ASN1(ciphertext, C1C3C2)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestAdjustCiphertextSplicingOrder(t *testing.T) {
	ciphertext, _ := hex.DecodeString("047928e22045eec8dc00e95639dd0c1c8dfb75cf8cedcf496731a6a6f423baa54c5014c60b73495886d8d7bc996a4a716cb58e6bfc8e03078b24e7b0f5cba0efd5b9272c27fc263bb59eaca6eabc97c0323bf1de953aeabaf59700b3bf49c9a1056decc08dd18544960541a2239afa7b1512df05")
	res, err := AdjustCiphertextSplicingOrder(ciphertext, C1C3C2, C1C3C2)
	if err != nil || &res[0] != &ciphertext[0] {
		t.Fatalf("should be same one")
	}
	_, err = AdjustCiphertextSplicingOrder(ciphertext[:65], C1C3C2, C1C2C3)
	if err == nil {
		t.Fatalf("expected error")
	}
	ciphertext[0] = 0x10
	_, err = AdjustCiphertextSplicingOrder(ciphertext, C1C3C2, C1C2C3)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCiphertext2ASN1(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
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
			ciphertext1, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}

			ciphertext, err := PlainCiphertext2ASN1(ciphertext1, C1C3C2)
			if err != nil {
				t.Fatalf("convert to ASN.1 failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			ciphertext2, err := AdjustCiphertextSplicingOrder(ciphertext1, C1C3C2, C1C2C3)
			if err != nil {
				t.Fatalf("adjust order failed %v", err)
			}
			ciphertext, err = PlainCiphertext2ASN1(ciphertext2, C1C2C3)
			if err != nil {
				t.Fatalf("convert to ASN.1 failed %v", err)
			}
			plaintext, err = priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func TestCiphertextASN12Plain(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
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
			ciphertext, err := EncryptASN1(rand.Reader, &priv.PublicKey, []byte(tt.plainText))
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			ciphertext, err = ASN1Ciphertext2Plain(ciphertext, nil)
			if err != nil {
				t.Fatalf("convert to plain failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, nil)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func TestEncryptWithInfinitePublicKey(t *testing.T) {
	pub := new(ecdsa.PublicKey)
	pub.Curve = P256()
	pub.X = big.NewInt(0)
	pub.Y = big.NewInt(0)

	_, err := Encrypt(rand.Reader, pub, []byte("sm2 encryption standard"), nil)
	if err == nil {
		t.Fatalf("should be failed")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, nil, nil)
	if err != nil || ciphertext != nil {
		t.Fatalf("nil plaintext should return nil")
	}
	ciphertext, err = Encrypt(rand.Reader, &priv.PublicKey, []byte{}, nil)
	if err != nil || ciphertext != nil {
		t.Fatalf("empty plaintext should return nil")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2 := new(PrivateKey)
	key2.PrivateKey = *priv2
	tests := []struct {
		name      string
		plainText string
		priv      *PrivateKey
	}{
		// TODO: Add test cases.
		{"less than 32", "encryption standard", priv},
		{"equals 32", "encryption standard encryption ", priv},
		{"long than 32", "encryption standard encryption standard", priv},
		{"less than 32", "encryption standard", key2},
		{"equals 32", "encryption standard encryption ", key2},
		{"long than 32", "encryption standard encryption standard", key2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(rand.Reader, &tt.priv.PublicKey, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := Decrypt(tt.priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
			// compress mode
			encrypterOpts := NewPlainEncrypterOpts(MarshalCompressed, C1C3C2)
			ciphertext, err = Encrypt(rand.Reader, &tt.priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(tt.priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			// hybrid mode
			encrypterOpts = NewPlainEncrypterOpts(MarshalHybrid, C1C3C2)
			ciphertext, err = Encrypt(rand.Reader, &tt.priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(tt.priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
			plaintext, err = Decrypt(tt.priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func TestInvalidCiphertext(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	tests := []struct {
		name       string
		ciphertext []byte
	}{
		// TODO: Add test cases.
		{errCiphertextTooShort.Error(), make([]byte, 65)},
		{ErrDecryption.Error(), append([]byte{0x04}, make([]byte, 96)...)},
		{ErrDecryption.Error(), append([]byte{0x04}, make([]byte, 97)...)},
		{ErrDecryption.Error(), append([]byte{0x02}, make([]byte, 65)...)},
		{ErrDecryption.Error(), append([]byte{0x30}, make([]byte, 97)...)},
		{ErrDecryption.Error(), make([]byte, 97)},
	}
	for i, tt := range tests {
		_, err := Decrypt(priv, tt.ciphertext)
		if err.Error() != tt.name {
			t.Fatalf("case %v, expected %v, got %v\n", i, tt.name, err.Error())
		}
	}
}

func TestPrivateKeyPlus1WithOrderMinus1(t *testing.T) {
	priv := new(PrivateKey)
	priv.D = new(big.Int).Sub(P256().Params().N, big.NewInt(1))
	priv.Curve = P256()
	priv.PublicKey.X, priv.PublicKey.Y = P256().ScalarBaseMult(priv.D.Bytes())

	_, err := priv.inverseOfPrivateKeyPlus1(p256())
	if err == nil || err != errInvalidPrivateKey {
		t.Errorf("expected invalid private key error")
	}
}

func TestSignVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
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
			signature, err := priv.Sign(rand.Reader, hashed[:], nil)
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := VerifyASN1(&priv.PublicKey, hashed[:], signature)
			if !result {
				t.Fatal("verify failed")
			}
			hashed[0] ^= 0xff
			if VerifyASN1(&priv.PublicKey, hashed[:], signature) {
				t.Errorf("VerifyASN1 always works!")
			}
		})
	}
}

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

// Check that signatures remain non-deterministic with a functional entropy source.
func TestINDCCA(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key")
	}

	hashed := []byte("testing")
	r0, s0, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	r1, s1, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same result")
	}

	if r0.Cmp(r1) == 0 {
		t.Error("SM2: two signatures of the same message produced the same nonce")
	}
}

func TestNegativeInputs(t *testing.T) {
	key, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key")
	}

	var hash [32]byte
	r := new(big.Int).SetInt64(1)
	r.Lsh(r, 550 /* larger than any supported curve */)
	r.Neg(r)

	if Verify(&key.PublicKey, hash[:], r, r) {
		t.Errorf("bogus signature accepted")
	}
}

func TestZeroHashSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Sign a hash consisting of all zeros.
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	// Confirm that it can be verified.
	if !Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Errorf("zero hash signature verify failed")
	}
}

func TestZeroSignature(t *testing.T) {
	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if Verify(&privKey.PublicKey, make([]byte, 64), big.NewInt(0), big.NewInt(0)) {
		t.Error("Verify with r,s=0 succeeded")
	}
}

func TestNegtativeSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Neg(r)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=-r succeeded")
	}
}

func TestRPlusNSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Add(r, P256().Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=r+n succeeded")
	}
}

func TestRMinusNSignature(t *testing.T) {
	zeroHash := make([]byte, 64)

	privKey, err := GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r, s, err := Sign(rand.Reader, &privKey.PrivateKey, zeroHash)
	if err != nil {
		panic(err)
	}

	r = r.Sub(r, P256().Params().N)
	if Verify(&privKey.PublicKey, zeroHash, r, s) {
		t.Error("Verify with r=r-n succeeded")
	}
}

func TestEqual(t *testing.T) {
	private, _ := GenerateKey(rand.Reader)
	public := &private.PublicKey

	if !public.Equal(public) {
		t.Errorf("public key is not equal to itself: %q", public)
	}
	if !public.Equal(crypto.Signer(private).Public()) {
		t.Errorf("private.Public() is not Equal to public: %q", public)
	}
	if !private.Equal(private) {
		t.Errorf("private key is not equal to itself")
	}

	otherPriv, _ := GenerateKey(rand.Reader)
	otherPub := &otherPriv.PublicKey
	if public.Equal(otherPub) {
		t.Errorf("different public keys are Equal")
	}
	if private.Equal(otherPriv) {
		t.Errorf("different private keys are Equal")
	}
}

func TestPublicKeyToECDH(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	_, err := PublicKeyToECDH(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = PublicKeyToECDH(&p256.PublicKey)
	if err == nil {
		t.Fatal("should be error")
	}
}

func TestRandomPoint(t *testing.T) {
	c := p256()
	t.Cleanup(func() { testingOnlyRejectionSamplingLooped = nil })
	var loopCount int
	testingOnlyRejectionSamplingLooped = func() { loopCount++ }

	// A sequence of all ones will generate 2^N-1, which should be rejected.
	// (Unless, for example, we are masking too many bits.)
	r := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0xff}, 100)), rand.Reader)
	if k, p, err := randomPoint(c, r, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("overflow was not rejected")
	}
	loopCount = 0

	// A sequence of all zeroes will generate zero, which should be rejected.
	r = io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0}, 100)), rand.Reader)
	if k, p, err := randomPoint(c, r, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("zero was not rejected")
	}
}

func BenchmarkGenerateKey_SM2(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(r); err != nil {
			b.Fatal(err)
		}
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

func BenchmarkSign_SM2(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}
	hashed := sm3.Sum([]byte("testing"))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignASN1(rand.Reader, priv, hashed[:], nil)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkSign_SM2Specific(b *testing.B) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(r)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtestingtesting")
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			_, err := priv.SignWithSM2(rand.Reader, nil, hashed)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
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

func BenchmarkVerify_SM2(b *testing.B) {
	rd := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := GenerateKey(rd)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, &priv.PrivateKey, hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(&priv.PublicKey, hashed, r, s) {
			b.Fatal("verify failed")
		}
	}
}

func benchmarkEncrypt(b *testing.B, curve elliptic.Curve, plaintext string) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := ecdsa.GenerateKey(curve, r)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(rand.Reader, &priv.PublicKey, []byte(plaintext), nil)
	}
}

func BenchmarkLessThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), "encryption standard")
}

func BenchmarkLessThan32_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), "encryption standard")
}

func BenchmarkMoreThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}

func BenchmarkMoreThan32_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}
