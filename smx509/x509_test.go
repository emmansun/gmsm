package smx509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

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

const pemCertificate = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIRAKQkkrFx1T/dgB/Go/xBM5swDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTcyMDM2MDdaFw0xNzA4MTcyMDM2
MDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAoJtjG7M6InsWwIo+l3qq9u+g2rKFXNu9/mZ24XQ8XhV6PUR+5HQ4
jUFWC58ExYhottqK5zQtKGkw5NuhjowFUgWB/VlNGAUBHtJcWR/062wYrHBYRxJH
qVXOpYKbIWwFKoXu3hcpg/CkdOlDWGKoZKBCwQwUBhWE7MDhpVdQ+ZljUJWL+FlK
yQK5iRsJd5TGJ6VUzLzdT4fmN2DzeK6GLeyMpVpU3sWV90JJbxWQ4YrzkKzYhMmB
EcpXTG2wm+ujiHU/k2p8zlf8Sm7VBM/scmnMFt0ynNXop4FWvJzEm1G0xD2t+e2I
5Utr04dOZPCgkm++QJgYhtZvgW7ZZiGTAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKC
EHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBADpqKQxrthH5InC7
X96UP0OJCu/lLEMkrjoEWYIQaFl7uLPxKH5AmQPH4lYwF7u7gksR7owVG9QU9fs6
1fK7II9CVgCd/4tZ0zm98FmU4D0lHGtPARrrzoZaqVZcAvRnFTlPX5pFkPhVjjai
/mkxX9LpD8oK1445DFHxK5UjLMmPIIWd8EOi+v5a+hgGwnJpoW7hntSl8kHMtTmy
fnnktsblSUV4lRCit0ymC7Ojhe+gzCCwkgs5kDzVVag+tnl/0e2DloIjASwOhpbH
KVcg7fBd484ht/sS+l0dsB4KDOSpd8JzVDMF8OZqlaydizoJO0yWr9GbCN1+OKq5
EhLrEqU=
-----END CERTIFICATE-----`

var pemPrivateKey = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA TESTING KEY-----
`)

const ed25519CRLKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINdKh2096vUBYu4EIFpjShsUSh3vimKya1sQ1YTT4RZG
-----END PRIVATE KEY-----`

const ed25519CRLCertificate = `
Certificate:
Data:
	Version: 3 (0x2)
	Serial Number:
		7a:07:a0:9d:14:04:16:fc:1f:d8:e5:fe:d1:1d:1f:8d
	Signature Algorithm: ED25519
	Issuer: CN = Ed25519 CRL Test CA
	Validity
		Not Before: Oct 30 01:20:20 2019 GMT
		Not After : Dec 31 23:59:59 9999 GMT
	Subject: CN = Ed25519 CRL Test CA
	Subject Public Key Info:
		Public Key Algorithm: ED25519
			ED25519 Public-Key:
			pub:
				95:73:3b:b0:06:2a:31:5a:b6:a7:a6:6e:ef:71:df:
				ac:6f:6b:39:03:85:5e:63:4b:f8:a6:0f:68:c6:6f:
				75:21
	X509v3 extensions:
		X509v3 Key Usage: critical
			Digital Signature, Certificate Sign, CRL Sign
		X509v3 Extended Key Usage: 
			TLS Web Client Authentication, TLS Web Server Authentication, OCSP Signing
		X509v3 Basic Constraints: critical
			CA:TRUE
		X509v3 Subject Key Identifier: 
			B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60
		X509v3 Authority Key Identifier: 
			keyid:B7:17:DA:16:EA:C5:ED:1F:18:49:44:D3:D2:E3:A0:35:0A:81:93:60
Signature Algorithm: ED25519
	 fc:3e:14:ea:bb:70:c2:6f:38:34:70:bc:c8:a7:f4:7c:0d:1e:
	 28:d7:2a:9f:22:8a:45:e8:02:76:84:1e:2d:64:2d:1e:09:b5:
	 29:71:1f:95:8a:4e:79:87:51:60:9a:e7:86:40:f6:60:c7:d1:
	 ee:68:76:17:1d:90:cc:92:93:07
-----BEGIN CERTIFICATE-----
MIIBijCCATygAwIBAgIQegegnRQEFvwf2OX+0R0fjTAFBgMrZXAwHjEcMBoGA1UE
AxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAgFw0xOTEwMzAwMTIwMjBaGA85OTk5MTIz
MTIzNTk1OVowHjEcMBoGA1UEAxMTRWQyNTUxOSBDUkwgVGVzdCBDQTAqMAUGAytl
cAMhAJVzO7AGKjFatqembu9x36xvazkDhV5jS/imD2jGb3Uho4GNMIGKMA4GA1Ud
DwEB/wQEAwIBhjAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUF
BwMJMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLcX2hbqxe0fGElE09LjoDUK
gZNgMB8GA1UdIwQYMBaAFLcX2hbqxe0fGElE09LjoDUKgZNgMAUGAytlcANBAPw+
FOq7cMJvODRwvMin9HwNHijXKp8iikXoAnaEHi1kLR4JtSlxH5WKTnmHUWCa54ZA
9mDH0e5odhcdkMySkwc=
-----END CERTIFICATE-----`

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

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

func getPublicKey(pemContent []byte) (interface{}, error) {
	block, _ := pem.Decode(pemContent)
	if block == nil {
		return nil, errors.New("Failed to parse PEM block")
	}
	return ParsePKIXPublicKey(block.Bytes)
}

func parseAndCheckCsr(csrPem []byte) error {
	csr, err := ParseCertificateRequestPEM(csrPem)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}

func Test_ParseCertificate(t *testing.T) {
	cert, err := ParseCertificatePEM([]byte(sm2Certificate))
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	jsonContent, err := json.Marshal(cert)
	fmt.Printf("%s\n", jsonContent)
}

func TestParseCertificateRequest(t *testing.T) {
	err := parseAndCheckCsr([]byte(csrFromAli))
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	priv, _ := sm2.GenerateKey(rand.Reader)

	names := pkix.Name{CommonName: "TestName"}
	var template = x509.CertificateRequest{Subject: names, SignatureAlgorithm: SM2WithSM3}
	csrblock, err := CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Bytes: csrblock, Type: "CERTIFICATE REQUEST"}
	pemContent := string(pem.EncodeToMemory(block))
	fmt.Printf("%s\n", pemContent)
	err = parseAndCheckCsr([]byte(pemContent))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignByAliVerifyAtLocal(t *testing.T) {
	dig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := getPublicKey([]byte(publicKeyPemFromAliKmsForSign))
	pub1 := pub.(*ecdsa.PublicKey)
	hashValue, _ := base64.StdEncoding.DecodeString(hashBase64)
	result := sm2.VerifyASN1(pub1, hashValue, dig)
	if !result {
		t.Error("Verify fail")
	}
}

func TestSignByHuaweiVerifyAtLocal(t *testing.T) {
	dig, err := base64.StdEncoding.DecodeString(signatureFromHuawei)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := getPublicKey([]byte(publicKeyPemFromHuaweiKmsForSign))
	pub1 := pub.(*ecdsa.PublicKey)
	hashValue, _ := base64.StdEncoding.DecodeString(hashBase64)
	result := sm2.VerifyASN1(pub1, hashValue, dig)
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
	encrypted, err := sm2.Encrypt(rand.Reader, pub1, []byte("testfile"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("encrypted=%s\n", base64.StdEncoding.EncodeToString(encrypted))
}

func TestParsePKIXPublicKeyFromHuawei(t *testing.T) {
	pub, err := getPublicKey([]byte(publicKeyPemFromHuaweiKms))
	if err != nil {
		t.Fatal(err)
	}
	pub1 := pub.(*ecdsa.PublicKey)
	encrypted, err := sm2.Encrypt(rand.Reader, pub1, []byte("encryption standard"), sm2.NewASN1EncrypterOpts())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("encrypted=%s\n", base64.RawURLEncoding.EncodeToString(encrypted))
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

func Test_CreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}

	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	_, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name    string
		priv    interface{}
		sigAlgo x509.SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, x509.SHA1WithRSA},
		{"SM2-256", sm2Priv, SM2WithSM3},
		{"ECDSA-256", ecdsa256Priv, x509.ECDSAWithSHA1},
		{"ECDSA-384", ecdsa384Priv, x509.ECDSAWithSHA1},
		{"ECDSA-521", ecdsa521Priv, x509.ECDSAWithSHA1},
		{"Ed25519", ed25519Priv, x509.PureEd25519},
	}

	for _, test := range tests {
		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = out.CheckSignature()
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	random := rand.Reader

	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(random)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name      string
		pub, priv interface{}
		checkSig  bool
		sigAlgo   x509.SignatureAlgorithm
	}{
		{"RSA/RSA", &testPrivateKey.PublicKey, testPrivateKey, true, x509.SHA1WithRSA},
		{"RSA/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, x509.ECDSAWithSHA384},
		{"RSA/SM2", &testPrivateKey.PublicKey, sm2Priv, false, SM2WithSM3},
		{"ECDSA/RSA", &ecdsaPriv.PublicKey, testPrivateKey, false, x509.SHA256WithRSA},
		{"ECDSA/ECDSA", &ecdsaPriv.PublicKey, ecdsaPriv, true, x509.ECDSAWithSHA1},
		{"ECDSA/SM2", &ecdsaPriv.PublicKey, sm2Priv, false, SM2WithSM3},
		{"SM2/ECDSA", &sm2Priv.PublicKey, ecdsaPriv, false, x509.ECDSAWithSHA1},
		{"RSAPSS/RSAPSS", &testPrivateKey.PublicKey, testPrivateKey, true, x509.SHA256WithRSAPSS},
		{"ECDSA/RSAPSS", &ecdsaPriv.PublicKey, testPrivateKey, false, x509.SHA256WithRSAPSS},
		{"SM2/RSAPSS", &sm2Priv.PublicKey, testPrivateKey, false, x509.SHA256WithRSAPSS},
		{"RSAPSS/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, x509.ECDSAWithSHA384},
		{"Ed25519", ed25519Pub, ed25519Priv, true, x509.PureEd25519},
		{"SM2", &sm2Priv.PublicKey, sm2Priv, true, SM2WithSM3},
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		template := x509.Certificate{
			// SerialNumber is negative to ensure that negative
			// values are parsed. This is due to the prevalence of
			// buggy code that produces certificates with negative
			// serial numbers.
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
				Country:      []string{"US"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: "Gopher",
					},
					// This should override the Country, above.
					{
						Type:  []int{2, 5, 4, 6},
						Value: "NL",
					},
				},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     x509.KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA:                  true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

			PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
			PermittedDNSDomains:     []string{".example.com", "example.com"},
			ExcludedDNSDomains:      []string{"bar.example.com"},
			PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
			ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
			PermittedEmailAddresses: []string{"foo@example.com"},
			ExcludedEmailAddresses:  []string{".example.com", "example.com"},
			PermittedURIDomains:     []string{".bar.com", "bar.com"},
			ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       oidExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := CreateCertificate(random, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.PolicyIdentifiers) != 1 || !cert.PolicyIdentifiers[0].Equal(template.PolicyIdentifiers[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.PolicyIdentifiers)
		}

		if len(cert.PermittedDNSDomains) != 2 || cert.PermittedDNSDomains[0] != ".example.com" || cert.PermittedDNSDomains[1] != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSDomains)
		}

		if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bar.example.com" {
			t.Errorf("%s: failed to parse name constraint exclusions: %#v", test.name, cert.ExcludedDNSDomains)
		}

		if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "192.168.0.0/16" || cert.PermittedIPRanges[1].String() != "1.0.0.0/8" {
			t.Errorf("%s: failed to parse IP constraints: %#v", test.name, cert.PermittedIPRanges)
		}

		if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "2001:db8::/48" {
			t.Errorf("%s: failed to parse IP constraint exclusions: %#v", test.name, cert.ExcludedIPRanges)
		}

		if len(cert.PermittedEmailAddresses) != 1 || cert.PermittedEmailAddresses[0] != "foo@example.com" {
			t.Errorf("%s: failed to parse permitted email addreses: %#v", test.name, cert.PermittedEmailAddresses)
		}

		if len(cert.ExcludedEmailAddresses) != 2 || cert.ExcludedEmailAddresses[0] != ".example.com" || cert.ExcludedEmailAddresses[1] != "example.com" {
			t.Errorf("%s: failed to parse excluded email addreses: %#v", test.name, cert.ExcludedEmailAddresses)
		}

		if len(cert.PermittedURIDomains) != 2 || cert.PermittedURIDomains[0] != ".bar.com" || cert.PermittedURIDomains[1] != "bar.com" {
			t.Errorf("%s: failed to parse permitted URIs: %#v", test.name, cert.PermittedURIDomains)
		}

		if len(cert.ExcludedURIDomains) != 2 || cert.ExcludedURIDomains[0] != ".bar2.com" || cert.ExcludedURIDomains[1] != "bar2.com" {
			t.Errorf("%s: failed to parse excluded URIs: %#v", test.name, cert.ExcludedURIDomains)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s: ExtraNames didn't override Country", test.name)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidExtensionSubjectAltName) {
				if ext.Critical {
					t.Fatal("SAN extension is marked critical")
				}
			}
		}

		found := false
		for _, atv := range cert.Subject.Names {
			if atv.Type.Equal([]int{2, 5, 4, 42}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Names didn't contain oid 2.5.4.42 from ExtraNames", test.name)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
			t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if !reflect.DeepEqual(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !reflect.DeepEqual(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://foo.com/wibble#foo" {
			t.Errorf("%s: URIs differ from template. Got %v, want %v", test.name, cert.URIs, template.URIs)
		}

		if !reflect.DeepEqual(cert.IPAddresses, template.IPAddresses) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if !bytes.Contains(derBytes, extraExtensionData) {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = cert.CheckSignatureFrom(cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	privRSA, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	certRSA, _ := ParseCertificate(block.Bytes)

	block, _ = pem.Decode([]byte(ed25519CRLKey))
	privEd25519, _ := ParsePKCS8PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(ed25519CRLCertificate))
	certEd25519, _ := ParseCertificate(block.Bytes)

	tests := []struct {
		name string
		priv interface{}
		cert *Certificate
	}{
		{"RSA CA", privRSA, certRSA},
		{"Ed25519 CA", privEd25519, certEd25519},
	}

	loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

	now := time.Unix(1000, 0).In(loc)
	nowUTC := now.UTC()
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber: big.NewInt(42),
			// RevocationTime should be converted to UTC before marshaling.
			RevocationTime: now,
		},
	}
	expectedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: nowUTC,
		},
	}

	for _, test := range tests {
		crlBytes, err := test.cert.CreateCRL(rand.Reader, test.priv, revokedCerts, now, expiry)
		if err != nil {
			t.Errorf("%s: error creating CRL: %s", test.name, err)
		}

		parsedCRL, err := x509.ParseDERCRL(crlBytes)
		if err != nil {
			t.Errorf("%s: error reparsing CRL: %s", test.name, err)
		}
		if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, expectedCerts) {
			t.Errorf("%s: RevokedCertificates mismatch: got %v; want %v.", test.name,
				parsedCRL.TBSCertList.RevokedCertificates, expectedCerts)
		}
	}
}

func TestCreateRevocationList(t *testing.T) {
	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %s", err)
	}
	tests := []struct {
		name          string
		key           crypto.Signer
		issuer        *x509.Certificate
		template      *x509.RevocationList
		expectedError string
	}{
		{
			name:          "nil template",
			key:           sm2Priv,
			issuer:        nil,
			template:      nil,
			expectedError: "x509: template can not be nil",
		},
		{
			name:          "nil issuer",
			key:           sm2Priv,
			issuer:        nil,
			template:      &x509.RevocationList{},
			expectedError: "x509: issuer can not be nil",
		},
		{
			name: "issuer doesn't have crlSign key usage bit set",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCertSign,
			},
			template:      &x509.RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
			},
			template:      &x509.RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "nil Number",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: template contains nil Number field",
		},
		{
			name: "invalid signature algorithm",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				SignatureAlgorithm: x509.SHA256WithRSA,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
			expectedError: "x509: requested SignatureAlgorithm does not match private key type",
		},
		{
			name: "valid",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, Ed25519 key",
			key:  ed25519Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, non-default signature algorithm",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				SignatureAlgorithm: x509.ECDSAWithSHA512,
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
		{
			name: "valid, extra extension",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				ExtraExtensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
		{
			name: "valid, empty list",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: x509.KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				Number:     big.NewInt(5),
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var issuer *Certificate
			if tc.issuer != nil {
				issuer = &Certificate{*tc.issuer}
			}
			crl, err := CreateRevocationList(rand.Reader, tc.template, issuer, tc.key)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateRevocationList failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateRevocationList failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateRevocationList didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if tc.template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm &&
				parsedCRL.SignatureAlgorithm.Algorithm.Equal(signatureAlgorithmDetails[tc.template.SignatureAlgorithm].oid) {
				t.Fatalf("SignatureAlgorithm mismatch: got %v; want %v.", parsedCRL.SignatureAlgorithm,
					tc.template.SignatureAlgorithm)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.ExtraExtensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.ExtraExtensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if len(parsedCRL.TBSCertList.Extensions[2:]) == 0 && len(tc.template.ExtraExtensions) == 0 {
				// If we don't have anything to check return early so we don't
				// hit a [] != nil false positive below.
				return
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.ExtraExtensions)
			}
		})
	}
}
