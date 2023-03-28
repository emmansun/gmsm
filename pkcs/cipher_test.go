package pkcs

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
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
