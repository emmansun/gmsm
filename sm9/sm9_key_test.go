package sm9

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
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
	if masterKey.D.Cmp(masterKey2.D) != 0 {
		t.Errorf("expected %v, got %v", hex.EncodeToString(masterKey.D.Bytes()), hex.EncodeToString(masterKey2.D.Bytes()))
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
	if masterKey.MasterPublicKey.p.x != pub2.MasterPublicKey.p.x ||
		masterKey.MasterPublicKey.p.y != pub2.MasterPublicKey.p.y ||
		masterKey.MasterPublicKey.p.z != pub2.MasterPublicKey.p.z {
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
	if userKey.PrivateKey.p.x != userKey2.PrivateKey.p.x ||
		userKey.PrivateKey.p.y != userKey2.PrivateKey.p.y {
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
	masterKey2 := new(SignMasterPrivateKey)
	err = masterKey2.UnmarshalASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if masterKey.D.Cmp(masterKey2.D) != 0 {
		t.Errorf("expected %v, got %v", hex.EncodeToString(masterKey.D.Bytes()), hex.EncodeToString(masterKey2.D.Bytes()))
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
	if masterKey.MasterPublicKey.p.x != pub2.MasterPublicKey.p.x ||
		masterKey.MasterPublicKey.p.y != pub2.MasterPublicKey.p.y {
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
	if userKey.PrivateKey.p.x != userKey2.PrivateKey.p.x ||
		userKey.PrivateKey.p.y != userKey2.PrivateKey.p.y ||
		userKey.PrivateKey.p.z != userKey2.PrivateKey.p.z {
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
