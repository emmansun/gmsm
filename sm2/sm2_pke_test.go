package sm2

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

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
		{errCiphertextTooShort.Error(), nil},
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

func benchmarkEncrypt(b *testing.B, curve elliptic.Curve, plaintext []byte) {
	r := bufio.NewReaderSize(rand.Reader, 1<<15)
	priv, err := ecdsa.GenerateKey(curve, r)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(rand.Reader, &priv.PublicKey, []byte(plaintext), nil)
	}
}

func BenchmarkEncryptNoMoreThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), make([]byte, 31))
}

func BenchmarkEncryptNoMoreThan32_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), make([]byte, 31))
}

func BenchmarkEncrypt128_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), make([]byte, 128))
}

func BenchmarkEncrypt128_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), make([]byte, 128))
}

func BenchmarkEncrypt512_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), make([]byte, 512))
}

func BenchmarkEncrypt1K_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), make([]byte, 1024))
}

func BenchmarkEncrypt8K_SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), make([]byte, 8*1024))
}
