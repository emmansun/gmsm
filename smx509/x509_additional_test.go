package smx509

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

const publicKeyPemFromAliKms = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELfjZP28bYfGSvbODYlXiB5bcoXE+
2LRjjpIH3DcCCct9FuVhi9cm60nDFrbW49k2D3GJco2iWPlr0+5LV+t4AQ==
-----END PUBLIC KEY-----
`
const publicKeyPemFromHuaweiKms = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEP3JLMIBPGUx88KChOY3WhjNVKOsk
RzYP5lpimwVS9CAK6MzL4kqudI7Pqi6hcir35zH8/BHMXzQ4fM2Ojp+59w==
-----END PUBLIC KEY-----
`

const publicKeyPemFromHuaweiKmsForSign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAENpoOih+9ASfmKYx5lK5mLsrUK3Am
B6kLUsqHlVyglXgoMEwo8Sr8xb/Q3gDMNnd7Wyp2bJE9ksb60ansO4QaKg==
-----END PUBLIC KEY-----
`

const publicKeyPemFromAliKmsForSign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX
6TCKAmQJArAO7VOtZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEA==
-----END PUBLIC KEY-----
`

const hashBase64 = `Zsfw9GLu7dnR8tRr3BDk4kFnxIdc8veiKX2gK49LqOA=`
const signature = `MEUCIHV5hOCgYzlO4HkrUhct1Cc8BeKmbXNP+ASje5rGOcCYAiEA2XOajXo3/IihtCEJmNpImtWw3uHIy5CX5TIxit7V0gQ=`
const signatureFromHuawei = `MEQCIGK8rWDJw5K7a6RZP5pDii8iqY3yLmavaXpkl7aDLORqAiAlMiiSvp7OJYBCJmzmwadBiBhdBnCCfIdjiWhXHX9xcw==`

const csrFromAli = `-----BEGIN CERTIFICATE REQUEST-----
MIIBYjCCAQkCAQAwRzELMAkGA1UEBhMCQ04xEzARBgNVBAMMCkNhcmdvU21hcnQx
DzANBgNVBAcMBlpodWhhaTESMBAGA1UECAwJR3Vhbmdkb25nMFkwEwYHKoZIzj0C
AQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX6TCKAmQJArAO7VOt
ZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEKBgMC4GCSqGSIb3DQEJDjEh
MB8wHQYDVR0OBBYEFA3FO8vT+8qZBfGZa2TRhLRbme+9MC4GCSqGSIb3DQEJDjEh
MB8wHQYDVR0RBBYwFIESZW1tYW4uc3VuQGlxYXguY29tMAoGCCqBHM9VAYN1A0cA
MEQCIBQx6yv3rzfWCkKqDZQOfNKESQc6NtpQbeVvcxfBrciwAiAj78kkrF5R3g4l
bxIHjKZHc2sztHCXe7cseWGiLq0syg==
-----END CERTIFICATE REQUEST-----
`

func TestParsePKIXPublicKeyFromExternal(t *testing.T) {
	tests := []struct {
		name string
		pem  string
	}{
		{"ALI", publicKeyPemFromAliKms},
		{"HUAWEI", publicKeyPemFromHuaweiKms},
	}
	for _, test := range tests {
		pub, err := getPublicKey([]byte(test.pem))
		if err != nil {
			t.Fatalf("%s failed to get public key %v", test.name, err)
		}
		pub1 := pub.(*ecdsa.PublicKey)
		_, err = sm2.Encrypt(rand.Reader, pub1, []byte("encryption standard"), sm2.ASN1EncrypterOpts)
		if err != nil {
			t.Fatalf("%s failed to encrypt %v", test.name, err)
		}
	}
}

func TestSignByCloudVerifyAtLocal(t *testing.T) {
	tests := []struct {
		name      string
		pem       string
		signature string
	}{
		{"ALI", publicKeyPemFromAliKmsForSign, signature},
		{"HUAWEI", publicKeyPemFromHuaweiKmsForSign, signatureFromHuawei},
	}
	for _, test := range tests {
		dig, err := base64.StdEncoding.DecodeString(test.signature)
		if err != nil {
			t.Fatalf("%s failed to decode signature %v", test.name, err)
		}
		pub, err := getPublicKey([]byte(test.pem))
		if err != nil {
			t.Fatal(err)
		}
		pub1 := pub.(*ecdsa.PublicKey)
		hashValue, _ := base64.StdEncoding.DecodeString(hashBase64)
		result := sm2.VerifyASN1(pub1, hashValue, dig)
		if !result {
			t.Fatalf("%s Verify fail", test.name)
		}
	}
}

func getPublicKey(pemContent []byte) (interface{}, error) {
	block, _ := pem.Decode(pemContent)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}
	return ParsePKIXPublicKey(block.Bytes)
}

const sm2Certificate = `
-----BEGIN CERTIFICATE-----
MIICiDCCAiygAwIBAgIQLaGmvQznbGJOY0t9ainQKjAMBggqgRzPVQGDdQUAMC4x
CzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVOUkNBQzEPMA0GA1UEAwwGUk9PVENBMB4X
DTEzMDkxMzA4MTAyNVoXDTMzMDkwODA4MTAyNVowNDELMAkGA1UEBhMCQ04xETAP
BgNVBAoMCFVuaVRydXN0MRIwEAYDVQQDDAlTSEVDQSBTTTIwWTATBgcqhkjOPQIB
BggqgRzPVQGCLQNCAAR90R+RLQZKVBDwhIRVJR28ovu1x3duw2yxaWaY6E3lUKDW
IsmAwMOqE71MW3gQOxm68QJfPy6JT4Evil10FwyAo4IBIjCCAR4wHwYDVR0jBBgw
FoAUTDKxl9kzG8SmBcHG5YtiW/CXdlgwDwYDVR0TAQH/BAUwAwEB/zCBugYDVR0f
BIGyMIGvMEGgP6A9pDswOTELMAkGA1UEBhMCQ04xDjAMBgNVBAoMBU5SQ0FDMQww
CgYDVQQLDANBUkwxDDAKBgNVBAMMA2FybDAqoCigJoYkaHR0cDovL3d3dy5yb290
Y2EuZ292LmNuL2FybC9hcmwuY3JsMD6gPKA6hjhsZGFwOi8vbGRhcC5yb290Y2Eu
Z292LmNuOjM4OS9DTj1hcmwsT1U9QVJMLE89TlJDQUMsQz1DTjAOBgNVHQ8BAf8E
BAMCAQYwHQYDVR0OBBYEFIkxBJF7Q6qqmr+EHZuG7vC4cJmgMAwGCCqBHM9VAYN1
BQADSAAwRQIhAIp7/3vva+ZxFePKdqkzdGoVyGsfGHhiLLQeKrCZQ2Q5AiAmMOdf
0f0b8CilrVWdi8pfZyO6RqYfnpcJ638l7KHfNA==
-----END CERTIFICATE-----`

func Test_ParseCertificate(t *testing.T) {
	cert, err := ParseCertificatePEM([]byte(sm2Certificate))
	if err != nil {
		t.Fatal(err)
	}
	_, err = json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateSM2CertificateRequest(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)

	names := pkix.Name{CommonName: "TestName"}
	var template = x509.CertificateRequest{Subject: names, SignatureAlgorithm: SM2WithSM3}
	csrblock, err := CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: csrblock, Type: "CERTIFICATE REQUEST"}
	pemContent := string(pem.EncodeToMemory(block))
	err = parseAndCheckCsr([]byte(pemContent))
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseAliCertificateRequest(t *testing.T) {
	err := parseAndCheckCsr([]byte(csrFromAli))
	if err == nil {
		t.Fatal("ParseCertificate should fail when parsing certificate with duplicate extensions")
	}
}

func TestMarshalPKIXPublicKey(t *testing.T) {
	pub, err := getPublicKey([]byte(publicKeyPemFromAliKms))
	if err != nil {
		t.Fatal(err)
	}
	result, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: result, Type: "PUBLIC KEY"}
	pemContent := string(pem.EncodeToMemory(block))
	if !strings.EqualFold(publicKeyPemFromAliKms, pemContent) {
		t.Errorf("expected=%s, result=%s", publicKeyPemFromAliKms, pemContent)
	}
}

func parseAndCheckCsr(csrPem []byte) error {
	csr, err := ParseCertificateRequestPEM(csrPem)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}
