package pkcs7

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestRecipientInfo(t *testing.T) {
	recipientInfo := recipientInfo{
		Version:               1,
		IssuerAndSerialNumber: issuerAndSerial{},
		SubjectKeyIdentifier:  asn1.RawValue{},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  OIDEncryptionAlgorithmRSA,
			Parameters: asn1.NullRawValue,
		},
		EncryptedKey: []byte("encrypted key"),
	}

	bytes, err := asn1.Marshal(recipientInfo)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bytes) != "3021020101300d06092a864886f70d0101010500040d656e63727970746564206b6579" {
		t.Fatal("failed to marshal recipient info, expected: 3021020101300d06092a864886f70d0101010500040d656e63727970746564206b6579, got:", hex.EncodeToString(bytes))
	}

	recipientInfo.IssuerAndSerialNumber = issuerAndSerial{
		IssuerName: asn1.RawValue{},
		SerialNumber: big.NewInt(123456),
	}
	bytes, err = asn1.Marshal(recipientInfo)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bytes) != "302a02010130070000020301e240300d06092a864886f70d0101010500040d656e63727970746564206b6579" {
		t.Fatal("failed to marshal recipient info, expected: 302a02010130070000020301e240300d06092a864886f70d0101010500040d656e63727970746564206b6579, got:", hex.EncodeToString(bytes))
	}

	recipientInfo.SubjectKeyIdentifier = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: false,
		Bytes:      []byte("subject key identifier"),
	}
	recipientInfo.IssuerAndSerialNumber.SerialNumber = nil
	bytes, err = asn1.Marshal(recipientInfo)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bytes) != "303902010180167375626a656374206b6579206964656e746966696572300d06092a864886f70d0101010500040d656e63727970746564206b6579" {
		t.Fatal("failed to marshal recipient info, expected: 303902010180167375626a656374206b6579206964656e746966696572300d06092a864886f70d0101010500040d656e63727970746564206b6579, got:", hex.EncodeToString(bytes))
	}
}

func TestEncrypt(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.DESCBC,
		pkcs.TripleDESCBC,
		pkcs.SM4CBC,
		pkcs.SM4GCM,
		pkcs.AES128CBC,
		pkcs.AES192CBC,
		pkcs.AES256CBC,
		pkcs.AES128GCM,
		pkcs.AES192GCM,
		pkcs.AES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg, false)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptSM(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4CBC,
		pkcs.SM4GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg, false)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := EncryptSM(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptCFCA(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4,
		pkcs.SM4CBC,
		pkcs.SM4GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg, false)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := EncryptCFCA(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.DecryptCFCA(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestOpenEnvelopedMessageWithSubjectKeyID(t *testing.T) {
	cases := []struct {
		cert, pk, envelopedMsg string
	}{
		{ // case with recipient_policy_requiredSubjectKeyId
			cert: `
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIFAJFSEacwCgYIKoEcz1UBg3UwKTEQMA4GA1UEChMHQWNt
ZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTI0MTExODA3MzE0NVoXDTI1
MTExODA3MzE0NlowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNu
b3cwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASghjdohTwJilIskjwM8cCujIxc
aZ4t1PdRE3TSihbfnifJF+q55qR88pC+SJwl6U2Wpr5sz4TOmmrPp6437oazo3gw
djAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwQwDwYDVR0TAQH/
BAUwAwEB/zAdBgNVHQ4EFgQU0M8ZE1AABLJjOnDM8sjQ/Z8dsPYwHwYDVR0jBBgw
FoAUZOzkEm2S511/1i/JnKEe7DrX1U0wCgYIKoEcz1UBg3UDRwAwRAIgGvXkxK+X
Hv1BCzwKwmR598C8TL3ocRWawh3AroRj9eACIAW6aRyqEsv44if5qO9vlfgreODv
heM60r948JI2OvMW
-----END CERTIFICATE-----
	`,
			pk: "f043481ce3ba1332cc266ae795f2a41f100e52e47ee560de15d9e014acab35c9",
			envelopedMsg: `
-----BEGIN PKCS7-----
MIH9BgoqgRzPVQYBBAIDoIHuMIHrAgECMYGoMIGlAgECgBTQzxkTUAAEsmM6cMzy
yND9nx2w9jANBgkqgRzPVQGCLQMFAAR7MHkCIBKzH9XkTn+cOb8SGcXPk//8pRFC
n13W+AQiZyb9/R53AiEA5U4c+efh30mWd2sXtE1+MrvUUSg8X4nu+VKRze5Oq3gE
IFi6CF7AXjFgt4t7TVxpn0uLMrz3HljWDKkIqsYNOCzsBBB2NSP32EJPrw+rCzO2
z408MDsGCiqBHM9VBgEEAgEwGwYHKoEcz1UBaAQQb88RbJjqyynzqbSgUpQMaYAQ
rwVyRbByCMGE5zrbo6EwAg==
-----END PKCS7-----
	`,
		},
		{ // case with recipient_policy_useSubjectKeyIdExt
			cert: `
-----BEGIN CERTIFICATE-----
MIIBiDCCAS6gAwIBAgIENWipfDAKBggqgRzPVQGDdTApMRAwDgYDVQQKEwdBY21l
IENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmswHhcNMjQxMTE5MDIyNzE4WhcNMjUx
MTE5MDIyNzE5WjAlMRAwDgYDVQQKEwdBY21lIENvMREwDwYDVQQDEwhKb24gU25v
dzBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJFW5KAFkKFMMdCnRg7B6ntwSqRR
rmcyelmENz3ZXGDj0TcGCuScOCgtMQOFZTwGeu7TlLd1L6tRrh6rFStuv+2jSDBG
MA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDBDAfBgNVHSMEGDAW
gBQVt+9uB19T4yA+R34KmqNXHI4SLTAKBggqgRzPVQGDdQNIADBFAiEA+cvUlTDE
Ydqxaqvj1LNNxGpoYBEfAuQlKoK+xuSTVToCIHg8dnm7FTB79Gx4qGK/nCgGNqK4
Bz90uNf5gvRXF0mU
-----END CERTIFICATE-----
	`,
			pk: "8f3d7f612401b9fa80ababb603e8e2ae977cc171c75e97b0b103b9db1d7d190e",
			envelopedMsg: `
-----BEGIN PKCS7-----
MIH8BgoqgRzPVQYBBAIDoIHtMIHqAgECMYGnMIGkAgECgBS2m2LapHwibk3oObGg
5+JRDnDKPDANBgkqgRzPVQGCLQMFAAR6MHgCIFQQZYPJVXnSibUq87DKTMoHcLLM
brCBPz3RF/3Vp9AZAiAkETF7Gbyv3cg7vt48qPoPs4HH4TDRjpgiQk+8oPCmqAQg
ImgG5JOVBU3aoxeSCotYs3cUwAzWZyEi9pxQY2+3znIEEF0zrswN4wdXae/SelQU
RmgwOwYKKoEcz1UGAQQCATAbBgcqgRzPVQFoBBAZJrpOlPlWo4VvWEpHkGfDgBAV
4QgsbZcB/rIV1btrG0yq
-----END PKCS7-----
	`,
		},
	}

	for _, c := range cases {
		msgBytes, _ := pem.Decode([]byte(c.envelopedMsg))
		p7, err := Parse(msgBytes.Bytes)
		if err != nil {
			t.Fatalf("cannot Parse encrypted result: %s", err)
		}
		certificate, err := smx509.ParseCertificatePEM([]byte(c.cert))
		if err != nil {
			t.Fatalf("cannot Parse certificate: %s", err)
		}
		sm2pkBytes, _ := hex.DecodeString(c.pk)
		sm2pk, err := sm2.NewPrivateKeyFromInt(new(big.Int).SetBytes(sm2pkBytes))
		if err != nil {
			t.Fatalf("cannot Parse private key: %s", err)
		}
		result, err := p7.Decrypt(certificate, sm2pk)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		expected := []byte("Hello World!")
		if !bytes.Equal(expected, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", expected, result)
		}
	}
}

func TestEnvelopeMessageCFCA(t *testing.T) {
	ciphers := []pkcs.Cipher{
		pkcs.SM4,
		pkcs.SM4CBC,
	}
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	for _, cipher := range ciphers {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg, true)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := EnvelopeMessageCFCA(cipher, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}
