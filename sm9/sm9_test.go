package sm9

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestSignASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	hashed := []byte("Chinese IBS standard")
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := userKey.Sign(rand.Reader, hashed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Public().Verify(uid, hid, hashed, sig) {
		t.Errorf("Verify failed")
	}
	sig[0] = 0xff
	if masterKey.Public().Verify(uid, hid, hashed, sig) {
		t.Errorf("Verify with invalid asn1 format successed")
	}
}

func TestParseInvalidASN1(t *testing.T) {
	tests := []struct {
		name   string
		sigHex string
	}{
		// TODO: Add test cases.
		{"invalid point format", "30660420723a8b38dd2441c2aa1c3ec092eaa34996c53bf9ca7515272395c012ab6e6e070342000C389fc45b711d9dfd9d91958f64d89d3528cf577c6dc2bc792c2969188e76865e16c2d85419f8f923a0e77c7f269c0eeb97b6c4d7e2735189180ec719a380fe1d"},
		{"invalid point encoding length", "30660420723a8b38dd2441c2aa1c3ec092eaa34996c53bf9ca7515272395c012ab6e6e0703420004389fc45b711d9dfd9d91958f64d89d3528cf577c6dc2bc792c2969188e76865e16c2d85419f8f923a0e77c7f269c0eeb97b6c4d7e2735189180ec719a380fe"},
	}
	for _, tt := range tests {
		sig, err := hex.DecodeString(tt.sigHex)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = parseSignature(sig)
		if err == nil {
			t.Errorf("%s should be failed", tt.name)
		}
	}
}

func TestWrapKey(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	key, cipher, err := masterKey.Public().WrapKey(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := userKey.UnwrapKey(uid, cipher, 16)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key, key2) {
		t.Errorf("expected %x, got %x", key, key2)
	}
}

func TestWrapKeyASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := masterKey.Public().WrapKeyASN1(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key1, cipher, err := UnmarshalSM9KeyPackage(keyPackage)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := UnwrapKey(userKey, uid, cipher, 16)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("expected %x, got %x", key1, key2)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	encTypes := []EncrypterOpts{
		DefaultEncrypterOpts, SM4ECBEncrypterOpts, SM4CBCEncrypterOpts, SM4CFBEncrypterOpts, SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext, opts)
		if err != nil {
			t.Fatal(err)
		}

		got, err := Decrypt(userKey, uid, cipher, opts)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}

		got, err = userKey.Decrypt(uid, cipher, opts)
		if err != nil {
			t.Fatalf("encType %v, first byte %x, %v", opts.GetEncryptType(), cipher[0], err)
		}

		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	encTypes := []EncrypterOpts{
		DefaultEncrypterOpts, SM4ECBEncrypterOpts, SM4CBCEncrypterOpts, SM4CFBEncrypterOpts, SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		_, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, nil, opts)
		if err != ErrEmptyPlaintext {
			t.Fatalf("should be ErrEmptyPlaintext")
		}
	}
}

func TestEncryptDecryptASN1(t *testing.T) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	encTypes := []EncrypterOpts{
		DefaultEncrypterOpts, SM4ECBEncrypterOpts, SM4CBCEncrypterOpts, SM4CFBEncrypterOpts, SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		cipher, err := EncryptASN1(rand.Reader, masterKey.Public(), uid, hid, plaintext, opts)
		if err != nil {
			t.Fatal(err)
		}

		got, err := DecryptASN1(userKey, uid, cipher)
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}

		got, err = userKey.DecryptASN1(uid, cipher)
		if err != nil {
			t.Fatal(err)
		}

		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}

func TestUnmarshalSM9KeyPackage(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	p, err := masterKey.Public().WrapKeyASN1(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key, cipher, err := UnmarshalSM9KeyPackage(p)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := UnwrapKey(userKey, uid, cipher, 16)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key) != hex.EncodeToString(key2) {
		t.Errorf("expected %v, got %v\n", hex.EncodeToString(key), hex.EncodeToString(key2))
	}
}

func TestKeyExchange(t *testing.T) {
	hid := byte(0x02)
	userA := []byte("Alice")
	userB := []byte("Bob")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	userKey, err := masterKey.GenerateUserKey(userA, hid)
	if err != nil {
		t.Fatal(err)
	}
	initiator := userKey.NewKeyExchange(userA, userB, 16, true)

	userKey, err = masterKey.GenerateUserKey(userB, hid)
	if err != nil {
		t.Fatal(err)
	}
	responder := userKey.NewKeyExchange(userB, userA, 16, true)
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	// A1-A4
	rA, err := initiator.InitKeyExchange(rand.Reader, hid)
	if err != nil {
		t.Fatal(err)
	}

	// B1 - B7
	rB, sigB, err := responder.RespondKeyExchange(rand.Reader, hid, rA)
	if err != nil {
		t.Fatal(err)
	}

	// A5 -A8
	key1, sigA, err := initiator.ConfirmResponder(rB, sigB)
	if err != nil {
		t.Fatal(err)
	}

	// B8
	key2, err := responder.ConfirmInitiator(sigA)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func TestKeyExchangeWithoutSignature(t *testing.T) {
	hid := byte(0x02)
	userA := []byte("Alice")
	userB := []byte("Bob")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	userKey, err := masterKey.GenerateUserKey(userA, hid)
	if err != nil {
		t.Fatal(err)
	}
	initiator := userKey.NewKeyExchange(userA, userB, 16, false)

	userKey, err = masterKey.GenerateUserKey(userB, hid)
	if err != nil {
		t.Fatal(err)
	}
	responder := userKey.NewKeyExchange(userB, userA, 16, false)
	defer func() {
		initiator.Destroy()
		responder.Destroy()
	}()
	// A1-A4
	rA, err := initiator.InitKeyExchange(rand.Reader, hid)
	if err != nil {
		t.Fatal(err)
	}

	// B1 - B7
	rB, sigB, err := responder.RespondKeyExchange(rand.Reader, hid, rA)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigB) != 0 {
		t.Errorf("should no signature")
	}

	// A5 -A8
	key1, sigA, err := initiator.ConfirmResponder(rB, sigB)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigA) != 0 {
		t.Errorf("should no signature")
	}

	key2, err := responder.ConfirmInitiator(nil)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Errorf("got different key")
	}
}

func BenchmarkSign(b *testing.B) {
	hashed := []byte("Chinese IBS standard")
	uid := []byte("emmansun")
	hid := byte(0x01)

	masterKey, err := GenerateSignMasterKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	SignASN1(rand.Reader, userKey, hashed) // fire precompute

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignASN1(rand.Reader, userKey, hashed)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkVerify(b *testing.B) {
	hashed := []byte("Chinese IBS standard")
	uid := []byte("emmansun")
	hid := byte(0x01)

	masterKey, err := GenerateSignMasterKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	sig, err := SignASN1(rand.Reader, userKey, hashed)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyASN1(masterKey.Public(), uid, hid, hashed, sig) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		plaintext[0] = cipher[0]
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := Decrypt(userKey, uid, cipher, nil)
		if err != nil {
			b.Fatal(err)
		}
		if string(got) != string(plaintext) {
			b.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}

func BenchmarkDecryptASN1(b *testing.B) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	cipher, err := EncryptASN1(rand.Reader, masterKey.Public(), uid, hid, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := DecryptASN1(userKey, uid, cipher)
		if err != nil {
			b.Fatal(err)
		}
		if string(got) != string(plaintext) {
			b.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}
