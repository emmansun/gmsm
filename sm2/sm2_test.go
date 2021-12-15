package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func Test_kdf(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result, success := kdf(append(x2.Bytes(), y2.Bytes()...), 19)
	if !success {
		t.Fatalf("failed")
	}

	resultStr := hex.EncodeToString(result)

	if expected != resultStr {
		t.Fatalf("expected %s, real value %s", expected, resultStr)
	}
}

func Test_SplicingOrder(t *testing.T) {
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

func Test_encryptDecrypt_ASN1(t *testing.T) {
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
			encrypterOpts := ASN1EncrypterOpts
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := priv.Decrypt(rand.Reader, ciphertext, ASN1DecrypterOpts)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_Ciphertext2ASN1(t *testing.T) {
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
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			ciphertext, err = PlainCiphertext2ASN1(ciphertext, C1C3C2)
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
		})
	}
}

func Test_ASN1Ciphertext2Plain(t *testing.T) {
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

func Test_encryptDecrypt(t *testing.T) {
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
			ciphertext, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), nil)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err := Decrypt(priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
			// compress mode
			encrypterOpts := NewPlainEncrypterOpts(MarshalCompressed, C1C3C2)
			ciphertext, err = Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}

			// mixed mode
			encrypterOpts = NewPlainEncrypterOpts(MarshalMixed, C1C3C2)
			ciphertext, err = Encrypt(rand.Reader, &priv.PublicKey, []byte(tt.plainText), encrypterOpts)
			if err != nil {
				t.Fatalf("encrypt failed %v", err)
			}
			plaintext, err = Decrypt(priv, ciphertext)
			if err != nil {
				t.Fatalf("decrypt failed %v", err)
			}
			if !reflect.DeepEqual(string(plaintext), tt.plainText) {
				t.Errorf("Decrypt() = %v, want %v", string(plaintext), tt.plainText)
			}
		})
	}
}

func Test_signVerify(t *testing.T) {
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
			hash := sm3.Sum([]byte(tt.plainText))
			signature, err := priv.Sign(rand.Reader, hash[:], nil)
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := VerifyASN1(&priv.PublicKey, hash[:], signature)
			if !result {
				t.Fatal("verify failed")
			}
		})
	}
}

func TestNonceSafety(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(zeroReader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	hashed = []byte("testing...")
	r1, s1, err := Sign(zeroReader, &priv.PrivateKey, hashed)
	if err != nil {
		t.Errorf("SM2: error signing: %s", err)
		return
	}

	if s0.Cmp(s1) == 0 {
		// This should never happen.
		t.Error("SM2: the signatures on two different messages were the same")
	}

	if r0.Cmp(r1) == 0 {
		t.Error("SM2: the nonce used for two diferent messages was the same")
	}
}

func TestINDCCA(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

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

func benchmarkEncrypt(b *testing.B, curve elliptic.Curve, plaintext string) {
	for i := 0; i < b.N; i++ {
		priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
		Encrypt(rand.Reader, &priv.PublicKey, []byte(plaintext), nil)
	}
}

func BenchmarkLessThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), "encryption standard")
}

func BenchmarkLessThan32_P256SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), "encryption standard")
}

func BenchmarkMoreThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}

func BenchmarkMoreThan32_P256SM2(b *testing.B) {
	benchmarkEncrypt(b, P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}
