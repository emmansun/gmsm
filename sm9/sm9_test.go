package sm9_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm9"
)

func TestSignASN1(t *testing.T) {
	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
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
	// Test Marshal and Unmarshal
	userKeyBytes := userKey.Bytes()
	userKey, err = sm9.UnmarshalSignPrivateKeyRaw(userKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	userKey.SetMasterPublic(masterKey.PublicKey())
	sig, err := userKey.Sign(rand.Reader, hashed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.PublicKey().Verify(uid, hid, hashed, sig) {
		t.Errorf("Verify failed")
	}
	sig[0] = 0xff
	if masterKey.PublicKey().Verify(uid, hid, hashed, sig) {
		t.Errorf("Verify with invalid asn1 format successed")
	}
}

func TestWrapKey(t *testing.T) {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	key, cipher, err := masterKey.PublicKey().WrapKey(rand.Reader, uid, hid, 16)
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
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := masterKey.PublicKey().WrapKeyASN1(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key1, cipher, err := sm9.UnmarshalSM9KeyPackage(keyPackage)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := sm9.UnwrapKey(userKey, uid, cipher, 16)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("expected %x, got %x", key1, key2)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	// Test Marshal and Unmarshal
	userKeyBytes := userKey.Bytes()
	userKey, err = sm9.UnmarshalEncryptPrivateKeyRaw(userKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	userKey.SetMasterPublic(masterKey.PublicKey())
	encTypes := []sm9.EncrypterOpts{
		sm9.DefaultEncrypterOpts, sm9.SM4ECBEncrypterOpts, sm9.SM4CBCEncrypterOpts, sm9.SM4CFBEncrypterOpts, sm9.SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		cipher, err := sm9.Encrypt(rand.Reader, masterKey.PublicKey(), uid, hid, plaintext, opts)
		if err != nil {
			t.Fatal(err)
		}

		got, err := sm9.Decrypt(userKey, uid, cipher, opts)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}

		opts1, err := sm9.NewDecrypterOptsWithUID(opts, uid)
		if err != nil {
			t.Fatal(err)
		}
		got, err = userKey.Decrypt(rand.Reader, cipher, opts1)
		if err != nil {
			t.Fatalf("encType %v, first byte %x, %v", opts.GetEncryptType(), cipher[0], err)
		}

		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}

		opts1.EncrypterOpts = nil
		_, err = userKey.Decrypt(rand.Reader, cipher, opts1)
		if err == nil || err.Error() != "sm9: invalid ciphertext asn.1 data" {
			t.Fatalf("sm9: invalid ciphertext asn.1 data")
		}
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	encTypes := []sm9.EncrypterOpts{
		sm9.DefaultEncrypterOpts, sm9.SM4ECBEncrypterOpts, sm9.SM4CBCEncrypterOpts, sm9.SM4CFBEncrypterOpts, sm9.SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		_, err := sm9.Encrypt(rand.Reader, masterKey.PublicKey(), uid, hid, nil, opts)
		if err != sm9.ErrEmptyPlaintext {
			t.Fatalf("should be ErrEmptyPlaintext")
		}
	}
}

func TestEncryptDecryptASN1(t *testing.T) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	encTypes := []sm9.EncrypterOpts{
		sm9.DefaultEncrypterOpts, sm9.SM4ECBEncrypterOpts, sm9.SM4CBCEncrypterOpts, sm9.SM4CFBEncrypterOpts, sm9.SM4OFBEncrypterOpts,
	}
	for _, opts := range encTypes {
		cipher, err := sm9.EncryptASN1(rand.Reader, masterKey.PublicKey(), uid, hid, plaintext, opts)
		if err != nil {
			t.Fatal(err)
		}

		got, err := sm9.DecryptASN1(userKey, uid, cipher)
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

		got, err = userKey.Decrypt(rand.Reader, cipher, uid)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}

		opts, err := sm9.NewDecrypterOptsWithUID(nil, uid)
		if err != nil {
			t.Fatal(err)
		}
		got, err = userKey.Decrypt(rand.Reader, cipher, opts)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(plaintext) {
			t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}

func TestUnmarshalSM9KeyPackage(t *testing.T) {
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	p, err := masterKey.PublicKey().WrapKeyASN1(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key, cipher, err := sm9.UnmarshalSM9KeyPackage(p)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := sm9.UnwrapKey(userKey, uid, cipher, 16)
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
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
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
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
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

	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	sm9.SignASN1(rand.Reader, userKey, hashed) // fire precompute

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := sm9.SignASN1(rand.Reader, userKey, hashed)
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

	masterKey, err := sm9.GenerateSignMasterKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	sig, err := sm9.SignASN1(rand.Reader, userKey, hashed)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !sm9.VerifyASN1(masterKey.PublicKey(), uid, hid, hashed, sig) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher, err := sm9.Encrypt(rand.Reader, masterKey.PublicKey(), uid, hid, plaintext, nil)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		plaintext[0] = cipher[0]
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plaintext := []byte("Chinese IBE standard")
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	cipher, err := sm9.Encrypt(rand.Reader, masterKey.PublicKey(), uid, hid, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := sm9.Decrypt(userKey, uid, cipher, nil)
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
	masterKey, err := sm9.GenerateEncryptMasterKey(rand.Reader)
	hid := byte(0x01)
	uid := []byte("emmansun")
	if err != nil {
		b.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		b.Fatal(err)
	}
	cipher, err := sm9.EncryptASN1(rand.Reader, masterKey.PublicKey(), uid, hid, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := sm9.DecryptASN1(userKey, uid, cipher)
		if err != nil {
			b.Fatal(err)
		}
		if string(got) != string(plaintext) {
			b.Errorf("expected %v, got %v\n", string(plaintext), string(got))
		}
	}
}
