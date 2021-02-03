package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const publicKeyPemFromAliKms = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELfjZP28bYfGSvbODYlXiB5bcoXE+
2LRjjpIH3DcCCct9FuVhi9cm60nDFrbW49k2D3GJco2iWPlr0+5LV+t4AQ==
-----END PUBLIC KEY-----
`

const publicKeyPemFromAliKmsForSign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX
6TCKAmQJArAO7VOtZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEA==
-----END PUBLIC KEY-----
`

const hashBase64 = `Zsfw9GLu7dnR8tRr3BDk4kFnxIdc8veiKX2gK49LqOA=`
const signature = `MEUCIHV5hOCgYzlO4HkrUhct1Cc8BeKmbXNP+ASje5rGOcCYAiEA2XOajXo3/IihtCEJmNpImtWw3uHIy5CX5TIxit7V0gQ=`
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

func getPublicKey(pemContent []byte) (interface{}, error) {
	block, _ := pem.Decode(pemContent)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}
	return ParsePKIXPublicKey(block.Bytes)
}

func parseAndCheckCsr(csrblock []byte) error {
	csr, err := ParseCertificateRequest(csrblock)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", csr)
	return CheckSignature(csr)
}

func TestParseCertificateRequest(t *testing.T) {
	block, _ := pem.Decode([]byte(csrFromAli))
	if block == nil {
		t.Fatal("Failed to parse PEM block")
	}
	err := parseAndCheckCsr(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	names := pkix.Name{CommonName: "TestName"}
	var template = x509.CertificateRequest{Subject: names}
	csrblock, err := CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: csrblock, Type: "CERTIFICATE REQUEST"}
	pemContent := string(pem.EncodeToMemory(block))
	fmt.Printf("%s\n", pemContent)
	err = parseAndCheckCsr(csrblock)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignByAliVerifyAtLocal(t *testing.T) {
	var rs = &ecdsaSignature{}
	dig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := asn1.Unmarshal(dig, rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("rest len=%d", len(rest))
	}

	fmt.Printf("r=%s, s=%s\n", hex.EncodeToString(rs.R.Bytes()), hex.EncodeToString(rs.S.Bytes()))
	pub, err := getPublicKey([]byte(publicKeyPemFromAliKmsForSign))
	pub1 := pub.(*ecdsa.PublicKey)
	hashValue, _ := base64.StdEncoding.DecodeString(hashBase64)
	result := Verify(pub1, hashValue, rs.R, rs.S)
	if !result {
		t.Error("Verify fail")
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	pub, err := getPublicKey([]byte(publicKeyPemFromAliKms))
	if err != nil {
		t.Fatal(err)
	}
	pub1 := pub.(*ecdsa.PublicKey)
	encrypted, err := Encrypt(rand.Reader, pub1, []byte("testfile"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("encrypted=%s\n", base64.StdEncoding.EncodeToString(encrypted))
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
