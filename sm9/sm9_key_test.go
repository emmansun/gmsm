package sm9

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestSignMasterPrivateKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	masterKey2 := new(SignMasterPrivateKey)
	err = masterKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Equal(masterKey2) {
		t.Errorf("expected %v, got %v", hex.EncodeToString(masterKey.Bytes()), hex.EncodeToString(masterKey2.Bytes()))
	}
}

func TestSignMasterPublicKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.Public().MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := new(SignMasterPublicKey)
	err = pub2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Public().Equal(pub2) {
		t.Errorf("not same")
	}
}

func TestSignMasterPublicKeyMarshalCompressedASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.Public().MarshalCompressedASN1()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := new(SignMasterPublicKey)
	err = pub2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Public().Equal(pub2) {
		t.Errorf("not same")
	}
}

func TestSignUserPrivateKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := userKey.MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	userKey2 := new(SignPrivateKey)
	err = userKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !userKey.Equal(userKey2) {
		t.Errorf("not same")
	}
}

func TestSignUserPrivateKeyMarshalCompressedASN1(t *testing.T) {
	masterKey, err := GenerateSignMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := userKey.MarshalCompressedASN1()
	if err != nil {
		t.Fatal(err)
	}
	userKey2 := new(SignPrivateKey)
	err = userKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !userKey.Equal(userKey2) {
		t.Errorf("not same")
	}
}

func TestEncryptMasterPrivateKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	masterKey2 := new(EncryptMasterPrivateKey)
	err = masterKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Equal(masterKey2) {
		t.Errorf("expected %v, got %v", hex.EncodeToString(masterKey.Bytes()), hex.EncodeToString(masterKey2.Bytes()))
	}
}

func TestEncryptMasterPublicKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.Public().MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := new(EncryptMasterPublicKey)
	err = pub2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Public().Equal(pub2) {
		t.Errorf("not same")
	}
}

func TestEncryptMasterPublicKeyMarshalCompressedASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := masterKey.Public().MarshalCompressedASN1()
	if err != nil {
		t.Fatal(err)
	}
	pub2 := new(EncryptMasterPublicKey)
	err = pub2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !masterKey.Public().Equal(pub2) {
		t.Errorf("not same")
	}
}

func TestEncryptUserPrivateKeyMarshalASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := userKey.MarshalASN1()
	if err != nil {
		t.Fatal(err)
	}
	userKey2 := new(EncryptPrivateKey)
	err = userKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !userKey.Equal(userKey2) {
		t.Errorf("not same")
	}
}

func TestEncryptUserPrivateKeyMarshalCompressedASN1(t *testing.T) {
	masterKey, err := GenerateEncryptMasterKey(rand.Reader)
	uid := []byte("emmansun")
	hid := byte(0x01)
	if err != nil {
		t.Fatal(err)
	}
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	der, err := userKey.MarshalCompressedASN1()
	if err != nil {
		t.Fatal(err)
	}
	userKey2 := new(EncryptPrivateKey)
	err = userKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !userKey.Equal(userKey2) {
		t.Errorf("not same")
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

const sm9SignMasterPublicKeyFromGMSSL = `-----BEGIN SM9 SIGN MASTER PUBLIC KEY-----
MIGFA4GCAARvTUvk1ztAlmjlUK0kP3zdFEVHHr8HUL4sUbcnFoQPukP0AjurnySy
f1MY0Plzt4lZ5u0/6GC4zUjYEcjWiYV+bV9YCnOGVQAYfPr/a+4/alewf43qBJuX
Ri1gDhueE6gkoeZ4HHUu1wfhRbKRF8okwSO933f/ZSpLlYu1P7/ckw==
-----END SM9 SIGN MASTER PUBLIC KEY-----
`

func TestParseSM9SignMasterPublicKey(t *testing.T) {
	key := new(SignMasterPublicKey)
	err := key.ParseFromPEM([]byte(sm9SignMasterPublicKeyFromGMSSL))
	if err != nil {
		t.Fatal(err)
	}

	// create sign master public key PEM with cryptobyte
	var b cryptobyte.Builder
	bytes, _ := key.MarshalASN1()
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(bytes)
	})
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: data, Type: "SM9 SIGN MASTER PUBLIC KEY"}
	pemContent := string(pem.EncodeToMemory(block))

	if pemContent != sm9SignMasterPublicKeyFromGMSSL {
		t.Fatalf("failed %s\n", pemContent)
	}
}

const sm9EncMasterPublicKeyFromGMSSL = `-----BEGIN SM9 ENC MASTER PUBLIC KEY-----
MEQDQgAEUWC+GS/3JrpMJqH/ZBItUDROFg62fmY4HuU0kHlnK/trA/GBX/P+MH0P
tYwoUdCETdYJwxiKXlI1jytVTuuT2Q==
-----END SM9 ENC MASTER PUBLIC KEY-----
`

func TestParseSM9EncryptMasterPublicKey(t *testing.T) {
	key := new(EncryptMasterPublicKey)
	err := key.ParseFromPEM([]byte(sm9EncMasterPublicKeyFromGMSSL))
	if err != nil {
		t.Fatal(err)
	}

	// create encrypt master public key PEM with asn1
	var b cryptobyte.Builder

	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BitString(key.Bytes())
	})
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: data, Type: "SM9 ENC MASTER PUBLIC KEY"}
	pemContent := string(pem.EncodeToMemory(block))

	if pemContent != sm9EncMasterPublicKeyFromGMSSL {
		t.Fatalf("failed %s\n", pemContent)
	}
}
