package pkcs

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func TestGetCipher(t *testing.T) {
	marshalledIV, err := asn1.Marshal([]byte("0123456789ABCDEF"))
	if err != nil {
		t.Fatal(err)
	}
	sm4Scheme := pkix.AlgorithmIdentifier{
		Algorithm:  oidSM4,
		Parameters: asn1.RawValue{FullBytes: marshalledIV},
	}
	cipher, err := GetCipher(sm4Scheme)
	if err != nil {
		t.Fatal(err)
	}
	if !cipher.OID().Equal(oidSM4CBC) {
		t.Errorf("not expected CBC")
	}

	_, err = GetCipher(pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 2}})
	if err == nil || err.Error() != "pkcs: unsupported cipher (OID: 1.2.156.10197.1.401.2)" {
		t.Fatal(err)
	}
}

func TestInvalidKeyLen(t *testing.T) {
	plaintext := []byte("Hello World")
	invalidKey := []byte("123456")
	_, _, err := SM4ECB.Encrypt(invalidKey, plaintext)
	if err == nil {
		t.Errorf("should be error")
	}
	_, err = SM4ECB.Decrypt(invalidKey, nil, nil)
	if err == nil {
		t.Errorf("should be error")
	}
	_, _, err = SM4CBC.Encrypt(invalidKey, plaintext)
	if err == nil {
		t.Errorf("should be error")
	}
	_, err = SM4CBC.Decrypt(invalidKey, nil, nil)
	if err == nil {
		t.Errorf("should be error")
	}
	_, _, err = SM4GCM.Encrypt(invalidKey, plaintext)
	if err == nil {
		t.Errorf("should be error")
	}
	_, err = SM4GCM.Decrypt(invalidKey, nil, nil)
	if err == nil {
		t.Errorf("should be error")
	}
}

func TestGcmParameters(t *testing.T) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString([]byte("123456789012"))
	})
	pb1, _ := b.Bytes()
	params := gcmParameters{}
	_, err := asn1.Unmarshal(pb1, &params)
	if err != nil {
		t.Fatal(err)
	}
	if params.ICVLen != 12 {
		t.Errorf("should be 12, but got %v", params.ICVLen)
	}
	if !bytes.Equal([]byte("123456789012"), params.Nonce) {
		t.Errorf("not expected nonce")
	}

	pb2, _ := asn1.Marshal(params)
	if !bytes.Equal(pb1, pb2) {
		t.Errorf("not consistent result")
	}
}
