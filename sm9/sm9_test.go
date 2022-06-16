package sm9

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/emmansun/gmsm/internal/xor"
	"github.com/emmansun/gmsm/sm3"
)

func TestHashH1(t *testing.T) {
	expected := "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab"
	h := hashH1([]byte{0x41, 0x6c, 0x69, 0x63, 0x65, 0x01})
	if hex.EncodeToString(h.Bytes()) != expected {
		t.Errorf("got %v, expected %v", hex.EncodeToString(h.Bytes()), expected)
	}
}

func TestHashH2(t *testing.T) {
	expected := "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb"
	zStr := "4368696E65736520494253207374616E6461726481377B8FDBC2839B4FA2D0E0F8AA6853BBBE9E9C4099608F8612C6078ACD7563815AEBA217AD502DA0F48704CC73CABB3C06209BD87142E14CBD99E8BCA1680F30DADC5CD9E207AEE32209F6C3CA3EC0D800A1A42D33C73153DED47C70A39D2E8EAF5D179A1836B359A9D1D9BFC19F2EFCDB829328620962BD3FDF15F2567F58A543D25609AE943920679194ED30328BB33FD15660BDE485C6B79A7B32B013983F012DB04BA59FE88DB889321CC2373D4C0C35E84F7AB1FF33679BCA575D67654F8624EB435B838CCA77B2D0347E65D5E46964412A096F4150D8C5EDE5440DDF0656FCB663D24731E80292188A2471B8B68AA993899268499D23C89755A1A89744643CEAD40F0965F28E1CD2895C3D118E4F65C9A0E3E741B6DD52C0EE2D25F5898D60848026B7EFB8FCC1B2442ECF0795F8A81CEE99A6248F294C82C90D26BD6A814AAF475F128AEF43A128E37F80154AE6CB92CAD7D1501BAE30F750B3A9BD1F96B08E97997363911314705BFB9A9DBB97F75553EC90FBB2DDAE53C8F68E42"
	z, err := hex.DecodeString(zStr)
	if err != nil {
		t.Fatal(err)
	}
	h := hashH2(z)
	if hex.EncodeToString(h.Bytes()) != expected {
		t.Errorf("got %v, expected %v", hex.EncodeToString(h.Bytes()), expected)
	}
}

func TestSign(t *testing.T) {
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
	h, s, err := Sign(rand.Reader, userKey, hashed)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(masterKey.Public(), uid, hid, hashed, h, s) {
		t.Errorf("Verify failed")
	}
	hashed[0] ^= 0xff
	if Verify(masterKey.Public(), uid, hid, hashed, h, s) {
		t.Errorf("Verify always works!")
	}
}

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
	sig, err := SignASN1(rand.Reader, userKey, hashed)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyASN1(masterKey.Public(), uid, hid, hashed, sig) {
		t.Errorf("Verify failed")
	}
}

// SM9 Appendix A
func TestSignSM9Sample(t *testing.T) {
	expectedH := bigFromHex("823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb")
	expectedS := "0473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
	hash := []byte("Chinese IBS standard")
	hid := byte(0x01)
	uid := []byte("Alice")
	r := bigFromHex("033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe")
	masterKey := new(SignMasterPrivateKey)
	masterKey.D = bigFromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
	masterKey.MasterPublicKey = new(G2).ScalarBaseMult(masterKey.D)
	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	w := userKey.SignMasterPublicKey.ScalarBaseMult(r)

	var buffer []byte
	buffer = append(buffer, hash...)
	buffer = append(buffer, w.Marshal()...)

	h := hashH2(buffer)
	if h.Cmp(expectedH) != 0 {
		t.Fatal("not same h")
	}

	l := new(big.Int).Sub(r, h)

	if l.Sign() < 0 {
		l.Add(l, Order)
	}

	s := new(G1).ScalarMult(userKey.PrivateKey, l)

	if hex.EncodeToString(s.MarshalUncompressed()) != expectedS {
		t.Fatal("not same S")
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
	key, cipher, err := WrapKey(rand.Reader, masterKey.Public(), uid, hid, 16)
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
	key, cipher, err := masterKey.Public().WrapKey(rand.Reader, uid, hid, 16)
	if err != nil {
		t.Fatal(err)
	}

	key2, err := userKey.UnwrapKey(uid, cipher, 16)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(key) != hex.EncodeToString(key2) {
		t.Errorf("expected %v, got %v\n", hex.EncodeToString(key), hex.EncodeToString(key2))
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

// SM9 Appendix C
func TestWrapKeySM9Sample(t *testing.T) {
	expectedKey := "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480"
	masterKey := new(EncryptMasterPrivateKey)
	masterKey.D = bigFromHex("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
	masterKey.MasterPublicKey = new(G1).ScalarBaseMult(masterKey.D)
	fmt.Printf("Pub-e=%v\n", hex.EncodeToString(masterKey.MasterPublicKey.Marshal()))

	uid := []byte("Bob")
	hid := byte(0x03)

	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("UserPrivKey=%v\n", hex.EncodeToString(userKey.PrivateKey.Marshal()))

	q := masterKey.Public().GenerateUserPublicKey(uid, hid)
	fmt.Printf("Qb=%v\n", hex.EncodeToString(q.Marshal()))
	var r *big.Int = bigFromHex("74015F8489C01EF4270456F9E6475BFB602BDE7F33FD482AB4E3684A6722")

	cipher := new(G1).ScalarMult(q, r)
	fmt.Printf("C=%v\n", hex.EncodeToString(cipher.Marshal()))

	g := Pair(masterKey.Public().MasterPublicKey, Gen2)
	w := new(GT).ScalarMult(g, r)

	var buffer []byte
	buffer = append(buffer, cipher.Marshal()...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)

	key, ok := sm3.Kdf(buffer, 32)
	if !ok {
		t.Failed()
	}
	if hex.EncodeToString(key) != expectedKey {
		t.Errorf("expected %v, got %v\n", expectedKey, hex.EncodeToString(key))
	}

	key2, err := UnwrapKey(userKey, uid, cipher, 32)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key2) != expectedKey {
		t.Errorf("expected %v, got %v\n", expectedKey, hex.EncodeToString(key2))
	}
}

// SM9 Appendix D
func TestEncryptSM9Sample(t *testing.T) {
	plaintext := []byte("Chinese IBE standard")
	expectedCiphertext := "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3671b5f5b0e951489682f3e64e1378cdd5da9513b1c"
	masterKey := new(EncryptMasterPrivateKey)
	masterKey.D = bigFromHex("01EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
	masterKey.MasterPublicKey = new(G1).ScalarBaseMult(masterKey.D)
	fmt.Printf("Pub-e=%v\n", hex.EncodeToString(masterKey.MasterPublicKey.Marshal()))

	uid := []byte("Bob")
	hid := byte(0x03)

	userKey, err := masterKey.GenerateUserKey(uid, hid)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("UserPrivKey=%v\n", hex.EncodeToString(userKey.PrivateKey.Marshal()))

	q := masterKey.Public().GenerateUserPublicKey(uid, hid)
	fmt.Printf("Qb=%v\n", hex.EncodeToString(q.Marshal()))
	var r *big.Int = bigFromHex("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C")

	cipher := new(G1).ScalarMult(q, r)
	fmt.Printf("C=%v\n", hex.EncodeToString(cipher.Marshal()))

	g := Pair(masterKey.Public().MasterPublicKey, Gen2)
	w := new(GT).ScalarMult(g, r)

	var buffer []byte
	buffer = append(buffer, cipher.Marshal()...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)

	key, ok := sm3.Kdf(buffer, len(plaintext)+32)
	if !ok {
		t.Failed()
	}

	fmt.Printf("key=%v\n", hex.EncodeToString(key))
	xor.XorBytes(key, key[:len(plaintext)], plaintext)

	hash := sm3.New()
	hash.Write(key)
	c3 := hash.Sum(nil)

	ciphertext := append(cipher.Marshal(), c3...)
	ciphertext = append(ciphertext, key[:len(plaintext)]...)
	if hex.EncodeToString(ciphertext) != expectedCiphertext {
		t.Errorf("expected %v, got %v\n", expectedCiphertext, hex.EncodeToString(ciphertext))
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
	cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decrypt(userKey, uid, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
	}

	got, err = Decrypt(userKey, uid, cipher)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
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
	cipher, err := EncryptASN1(rand.Reader, masterKey.Public(), uid, hid, plaintext)
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

	got, err = DecryptASN1(userKey, uid, cipher)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(plaintext) {
		t.Errorf("expected %v, got %v\n", string(plaintext), string(got))
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
		cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext)
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
	cipher, err := Encrypt(rand.Reader, masterKey.Public(), uid, hid, plaintext)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := Decrypt(userKey, uid, cipher)
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
	cipher, err := EncryptASN1(rand.Reader, masterKey.Public(), uid, hid, plaintext)
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
