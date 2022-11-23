package sm2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

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

func Test_signVerifyLegacy(t *testing.T) {
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
			hash := sm3.Sum([]byte(tt.plainText))
			r, s, err := Sign(rand.Reader, priv, hash[:])
			if err != nil {
				t.Fatalf("sign failed %v", err)
			}
			result := Verify(&priv.PublicKey, hash[:], r, s)
			if !result {
				t.Fatal("verify failed")
			}
		})
	}
}

// Check that signatures are safe even with a broken entropy source.
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
		t.Error("SM2: the nonce used for two different messages was the same")
	}
}

// Check that signatures remain non-deterministic with a functional entropy source.
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
		t.Errorf("private key is not equal to itself: %q", private)
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

// a sample method to get frist ASN1 SEQUENCE data
func getFirstASN1Sequence(ciphertext []byte) ([]byte, []byte, error) {
	input := cryptobyte.String(ciphertext)
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, nil, errors.New("there are no sequence tag")
	}
	if len(input) == 0 {
		return ciphertext, nil, nil
	}
	return ciphertext[:len(ciphertext)-len(input)], input, nil
}

func TestCipherASN1WithInvalidBytes(t *testing.T) {
	ciphertext, _ := hex.DecodeString("3081980220298ED52AE2A0EBA8B7567D54DF41C5F9B310EDFA4A8E15ECCB44EDA94F9F1FC20220116BE33B0833C95D8E5FF9483CD2D7EFF7033C92FE5DEAB6197D809FF1EEE05F042097A90979A6FCEBDE883C2E07E9C286818E694EDE37C3CDAA70E4CD481BE883E00430D62160BB179CB20CE3B5ECA0F5A535BEB6E221566C78FEA92105F71BD37F3F850AD2F86F2D1E35F15E9356557DAC026A")
	_, rest, err := getFirstASN1Sequence(ciphertext)
	if err != nil || len(rest) != 0 {
		t.FailNow()
	}

	ciphertext, _ = hex.DecodeString("3081980220298ED52AE2A0EBA8B7567D54DF41C5F9B310EDFA4A8E15ECCB44EDA94F9F1FC20220116BE33B0833C95D8E5FF9483CD2D7EFF7033C92FE5DEAB6197D809FF1EEE05F042097A90979A6FCEBDE883C2E07E9C286818E694EDE37C3CDAA70E4CD481BE883E00430D62160BB179CB20CE3B5ECA0F5A535BEB6E221566C78FEA92105F71BD37F3F850AD2F86F2D1E35F15E9356557DAC026A0000")
	seq, rest, err := getFirstASN1Sequence(ciphertext)
	if err != nil || len(rest) != 2 {
		t.FailNow()
	}

	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)

	input := cryptobyte.String(seq)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		t.Fatalf("invalid cipher text")
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
	if k, p, err := randomPoint(c, r); err != nil {
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
	if k, p, err := randomPoint(c, r); err != nil {
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
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateKey_P256(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_SM2(b *testing.B) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	hashed := []byte("testing")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig, err := SignASN1(rand.Reader, priv, hashed, nil)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent the compiler from optimizing out the operation.
		hashed[0] = sig[0]
	}
}

func BenchmarkSign_SM2Specific(b *testing.B) {
	priv, err := GenerateKey(rand.Reader)
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	priv, err := GenerateKey(rand.Reader)
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
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
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
	benchmarkEncrypt(b, sm2ec.P256(), "encryption standard")
}

func BenchmarkMoreThan32_P256(b *testing.B) {
	benchmarkEncrypt(b, elliptic.P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}

func BenchmarkMoreThan32_SM2(b *testing.B) {
	benchmarkEncrypt(b, sm2ec.P256(), "encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard encryption standard")
}
