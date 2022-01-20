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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"runtime"
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

func TestParseAliCertificateRequest(t *testing.T) {
	err := parseAndCheckCsr([]byte(csrFromAli))
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
	fmt.Printf("%s\n", pemContent)
	err = parseAndCheckCsr([]byte(pemContent))
	if err != nil {
		t.Fatal(err)
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
		pub1 := pub.(*ecdsa.PublicKey)
		hashValue, _ := base64.StdEncoding.DecodeString(hashBase64)
		result := sm2.VerifyASN1(pub1, hashValue, dig)
		if !result {
			t.Fatalf("%s Verify fail", test.name)
		}
	}
}

const pemCRLBase64 = "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tDQpNSUlCOWpDQ0FWOENBUUV3RFFZSktvWklodmNOQVFFRkJRQXdiREVhTUJnR0ExVUVDaE1SVWxOQklGTmxZM1Z5DQphWFI1SUVsdVl5NHhIakFjQmdOVkJBTVRGVkpUUVNCUWRXSnNhV01nVW05dmRDQkRRU0IyTVRFdU1Dd0dDU3FHDQpTSWIzRFFFSkFSWWZjbk5oYTJWdmJuSnZiM1J6YVdkdVFISnpZWE5sWTNWeWFYUjVMbU52YlJjTk1URXdNakl6DQpNVGt5T0RNd1doY05NVEV3T0RJeU1Ua3lPRE13V2pDQmpEQktBaEVBckRxb2g5RkhKSFhUN09QZ3V1bjQrQmNODQpNRGt4TVRBeU1UUXlOekE1V2pBbU1Bb0dBMVVkRlFRRENnRUpNQmdHQTFVZEdBUVJHQTh5TURBNU1URXdNakUwDQpNalExTlZvd1BnSVJBTEd6blowOTVQQjVhQU9MUGc1N2ZNTVhEVEF5TVRBeU16RTBOVEF4TkZvd0dqQVlCZ05WDQpIUmdFRVJnUE1qQXdNakV3TWpNeE5EVXdNVFJhb0RBd0xqQWZCZ05WSFNNRUdEQVdnQlQxVERGNlVRTS9MTmVMDQpsNWx2cUhHUXEzZzltekFMQmdOVkhSUUVCQUlDQUlRd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQUZVNUFzNk16DQpxNVBSc2lmYW9iUVBHaDFhSkx5QytNczVBZ2MwYld5QTNHQWR4dXI1U3BQWmVSV0NCamlQL01FSEJXSkNsQkhQDQpHUmNxNXlJZDNFakRrYUV5eFJhK2k2N0x6dmhJNmMyOUVlNks5cFNZd2ppLzdSVWhtbW5Qclh0VHhsTDBsckxyDQptUVFKNnhoRFJhNUczUUE0Q21VZHNITnZicnpnbUNZcHZWRT0NCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0NCg0K"

func TestParsePEMCRL(t *testing.T) {
	pemBytes := fromBase64(pemCRLBase64)
	certList, err := ParseCRL(pemBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 2
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

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
		encrypted, err := sm2.Encrypt(rand.Reader, pub1, []byte("encryption standard"), sm2.ASN1EncrypterOpts)
		if err != nil {
			t.Fatalf("%s failed to encrypt %v", test.name, err)
		}
		fmt.Printf("encrypted=%s\n", base64.RawURLEncoding.EncodeToString(encrypted))
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
		sigAlgo SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, SHA1WithRSA},
		{"SM2-256", sm2Priv, SM2WithSM3},
		{"ECDSA-256", ecdsa256Priv, ECDSAWithSHA1},
		{"ECDSA-384", ecdsa384Priv, ECDSAWithSHA1},
		{"ECDSA-521", ecdsa521Priv, ECDSAWithSHA1},
		{"Ed25519", ed25519Priv, PureEd25519},
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
		sigAlgo   SignatureAlgorithm
	}{
		{"RSA/RSA", &testPrivateKey.PublicKey, testPrivateKey, true, SHA1WithRSA},
		{"RSA/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"RSA/SM2", &testPrivateKey.PublicKey, sm2Priv, false, SM2WithSM3},
		{"ECDSA/RSA", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSA},
		{"ECDSA/ECDSA", &ecdsaPriv.PublicKey, ecdsaPriv, true, ECDSAWithSHA1},
		{"ECDSA/SM2", &ecdsaPriv.PublicKey, sm2Priv, false, SM2WithSM3},
		{"SM2/ECDSA", &sm2Priv.PublicKey, ecdsaPriv, false, ECDSAWithSHA1},
		{"RSAPSS/RSAPSS", &testPrivateKey.PublicKey, testPrivateKey, true, SHA256WithRSAPSS},
		{"ECDSA/RSAPSS", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSAPSS},
		{"SM2/RSAPSS", &sm2Priv.PublicKey, testPrivateKey, false, SHA256WithRSAPSS},
		{"RSAPSS/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"Ed25519", ed25519Pub, ed25519Priv, true, PureEd25519},
		{"SM2", &sm2Priv.PublicKey, sm2Priv, true, SM2WithSM3},
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
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
			KeyUsage:     KeyUsageCertSign,

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

var certBytes = "MIIE0jCCA7qgAwIBAgIQWcvS+TTB3GwCAAAAAGEAWzANBgkqhkiG9w0BAQsFADBCMQswCQYD" +
	"VQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMwEQYDVQQDEwpHVFMg" +
	"Q0EgMU8xMB4XDTIwMDQwMTEyNTg1NloXDTIwMDYyNDEyNTg1NlowaTELMAkGA1UEBhMCVVMx" +
	"EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxEzARBgNVBAoT" +
	"Ckdvb2dsZSBMTEMxGDAWBgNVBAMTD21haWwuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqG" +
	"SM49AwEHA0IABO+dYiPnkFl+cZVf6mrWeNp0RhQcJSBGH+sEJxjvc+cYlW3QJCnm57qlpFdd" +
	"pz3MPyVejvXQdM6iI1mEWP4C2OujggJmMIICYjAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAww" +
	"CgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUI6pZhnQ/lQgmPDwSKR2A54G7" +
	"AS4wHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEEWDBWMCcG" +
	"CCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYIKwYBBQUHMAKGH2h0" +
	"dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwLAYDVR0RBCUwI4IPbWFpbC5nb29nbGUu" +
	"Y29tghBpbmJveC5nb29nbGUuY29tMCEGA1UdIAQaMBgwCAYGZ4EMAQICMAwGCisGAQQB1nkC" +
	"BQMwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5wa2kuZ29vZy9HVFMxTzEuY3JsMIIB" +
	"AwYKKwYBBAHWeQIEAgSB9ASB8QDvAHYAsh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+L" +
	"kF4AAAFxNgmxKgAABAMARzBFAiEA12/OHdTGXQ3qHHC3NvYCyB8aEz/+ZFOLCAI7lhqj28sC" +
	"IG2/7Yz2zK6S6ai+dH7cTMZmoFGo39gtaTqtZAqEQX7nAHUAXqdz+d9WwOe1Nkh90EngMnqR" +
	"mgyEoRIShBh1loFxRVgAAAFxNgmxTAAABAMARjBEAiA7PNq+MFfv6O9mBkxFViS2TfU66yRB" +
	"/njcebWglLQjZQIgOyRKhxlEizncFRml7yn4Bg48ktXKGjo+uiw6zXEINb0wDQYJKoZIhvcN" +
	"AQELBQADggEBADM2Rh306Q10PScsolYMxH1B/K4Nb2WICvpY0yDPJFdnGjqCYym196TjiEvs" +
	"R6etfeHdyzlZj6nh82B4TVyHjiWM02dQgPalOuWQcuSy0OvLh7F1E7CeHzKlczdFPBTOTdM1" +
	"RDTxlvw1bAqc0zueM8QIAyEy3opd7FxAcGQd5WRIJhzLBL+dbbMOW/LTeW7cm/Xzq8cgCybN" +
	"BSZAvhjseJ1L29OlCTZL97IfnX0IlFQzWuvvHy7V2B0E3DHlzM0kjwkkCKDUUp/wajv2NZKC" +
	"TkhEyERacZRKc9U0ADxwsAzHrdz5+5zfD2usEV/MQ5V6d8swLXs+ko0X6swrd4YCiB8wggRK" +
	"MIIDMqADAgECAg0B47SaoY2KqYElaVC4MA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0ds" +
	"b2JhbFNpZ24gUm9vdCBDQSAtIFIyMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH" +
	"bG9iYWxTaWduMB4XDTE3MDYxNTAwMDA0MloXDTIxMTIxNTAwMDA0MlowQjELMAkGA1UEBhMC" +
	"VVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczETMBEGA1UEAxMKR1RTIENBIDFP" +
	"MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAYz0XUi83TnORA73603WkhG8nP" +
	"PI5MdbkPMRmEPZ48Ke9QDRCTbwWAgJ8qoL0SSwLhPZ9YFiT+MJ8LdHdVkx1L903hkoIQ9lGs" +
	"DMOyIpQPNGuYEEnnC52DOd0gxhwt79EYYWXnI4MgqCMS/9Ikf9Qv50RqW03XUGawr55CYwX7" +
	"4BzEY2Gvn2oz/2KXvUjZ03wUZ9x13C5p6PhteGnQtxAFuPExwjsk/RozdPgj4OxrGYoWxuPN" +
	"pM0L27OkWWA4iDutHbnGjKdTG/y82aSrvN08YdeTFZjugb2P4mRHIEAGTtesl+i5wFkSoUkl" +
	"I+TtcDQspbRjfPmjPYPRzW0krAcCAwEAAaOCATMwggEvMA4GA1UdDwEB/wQEAwIBhjAdBgNV" +
	"HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E" +
	"FgQUmNH4bhDrz5vsYJ8YkBug630J/SswHwYDVR0jBBgwFoAUm+IHV2ccHsBqBt5ZtJot39wZ" +
	"hi4wNQYIKwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC5wa2kuZ29vZy9n" +
	"c3IyMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMi9nc3IyLmNy" +
	"bDA/BgNVHSAEODA2MDQGBmeBDAECAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3BraS5nb29n" +
	"L3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAagD42efvzLqlGN31eVBY1rsdOCJn+" +
	"vdE0aSZSZgc9CrpJy2L08RqO/BFPaJZMdCvTZ96yo6oFjYRNTCBlD6WW2g0W+Gw7228EI4hr" +
	"OmzBYL1on3GO7i1YNAfw1VTphln9e14NIZT1jMmo+NjyrcwPGvOap6kEJ/mjybD/AnhrYbrH" +
	"NSvoVvpPwxwM7bY8tEvq7czhPOzcDYzWPpvKQliLzBYhF0C8otZm79rEFVvNiaqbCSbnMtIN" +
	"bmcgAlsQsJAJnAwfnq3YO+qh/GzoEFwIUhlRKnG7rHq13RXtK8kIKiyKtKYhq2P/11JJUNCJ" +
	"t63yr/tQri/hlQ3zRq2dnPXK"

const emptyNameConstraintsPEM = `
-----BEGIN CERTIFICATE-----
MIIC1jCCAb6gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABoxEwDzANBgNVHR4EBjAEoAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMH
QhP8uNCtgSHyim/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb
6L+iJa4ElREJOi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6H
v5SsvpYW+1XleYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6M
LYPmRhTioROA/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOga
nCOSyFYfGhqOANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8
o+WoY6IsCKXV/g==
-----END CERTIFICATE-----`

func TestEmptyNameConstraints(t *testing.T) {
	block, _ := pem.Decode([]byte(emptyNameConstraintsPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatal("unexpected success")
	}

	const expected = "empty name constraints"
	if str := err.Error(); !strings.Contains(str, expected) {
		t.Errorf("expected %q in error but got %q", expected, str)
	}
}

func TestPKIXNameString(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(der)
	if err != nil {
		t.Fatal(err)
	}

	// Check that parsed non-standard attributes are printed.
	rdns := pkix.Name{
		Locality: []string{"Gophertown"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}.ToRDNSequence()
	nn := pkix.Name{}
	nn.FillFromRDNSequence(&rdns)

	// Check that zero-length non-nil ExtraNames hide Names.
	extra := []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "backing array"}}
	extraNotNil := pkix.Name{
		Locality:   []string{"Gophertown"},
		ExtraNames: extra[:0],
		Names: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
	}

	tests := []struct {
		dn   pkix.Name
		want string
	}{
		{nn, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		{extraNotNil, "L=Gophertown"},
		{pkix.Name{
			CommonName:         "Steve Kille",
			Organization:       []string{"Isode Limited"},
			OrganizationalUnit: []string{"RFCs"},
			Locality:           []string{"Richmond"},
			Province:           []string{"Surrey"},
			StreetAddress:      []string{"The Square"},
			PostalCode:         []string{"TW9 1DT"},
			SerialNumber:       "RFC 2253",
			Country:            []string{"GB"},
		}, "SERIALNUMBER=RFC 2253,CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB"},
		{certs[0].Subject,
			"CN=mail.google.com,O=Google LLC,L=Mountain View,ST=California,C=US"},
		{pkix.Name{
			Organization: []string{"#Google, Inc. \n-> 'Alphabet\" "},
			Country:      []string{"US"},
		}, "O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US"},
		{pkix.Name{
			CommonName:   "foo.com",
			Organization: []string{"Gopher Industries"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{2, 5, 4, 3}), Value: "bar.com"}},
		}, "CN=bar.com,O=Gopher Industries"},
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
		// If there are no ExtraNames, the Names are printed instead.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "L=Gophertown,1.2.3.4.5=#130a676f6c616e672e6f7267"},
		// If there are both, print only the ExtraNames.
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 6}), Value: "example.com"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
	}

	for i, test := range tests {
		if got := test.dn.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}

	if extra[0].Value != "backing array" {
		t.Errorf("the backing array of an empty ExtraNames got modified by String")
	}
}

func TestRDNSequenceString(t *testing.T) {
	// Test some extra cases that get lost in pkix.Name conversions such as
	// multi-valued attributes.

	var (
		oidCountry            = []int{2, 5, 4, 6}
		oidOrganization       = []int{2, 5, 4, 10}
		oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName         = []int{2, 5, 4, 3}
	)

	tests := []struct {
		seq  pkix.RDNSequence
		want string
	}{
		{
			seq: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidCountry, Value: "US"},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Widget Inc."},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganizationalUnit, Value: "Sales"},
					pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "J. Smith"},
				},
			},
			want: "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
		},
	}

	for i, test := range tests {
		if got := test.seq.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

const criticalNameConstraintWithUnknownTypePEM = `
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABozgwNjA0BgNVHR4BAf8EKjAooCQwIokgIACrzQAAAAAAAAAAAAAAAP////8A
AAAAAAAAAAAAAAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMHQhP8uNCtgSHy
im/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb6L+iJa4ElREJ
Oi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6Hv5SsvpYW+1Xl
eYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6MLYPmRhTioROA
/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOganCOSyFYfGhqO
ANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8o+WoY6IsCKXV
/g==
-----END CERTIFICATE-----`

func TestCriticalNameConstraintWithUnknownType(t *testing.T) {
	block, _ := pem.Decode([]byte(criticalNameConstraintWithUnknownTypePEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected parsing failure: %s", err)
	}

	if l := len(cert.UnhandledCriticalExtensions); l != 1 {
		t.Fatalf("expected one unhandled critical extension, but found %d", l)
	}
}

const badIPMaskPEM = `
-----BEGIN CERTIFICATE-----
MIICzzCCAbegAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMSQmFk
IElQIG1hc2sgaXNzdWVyMB4XDTEzMDIwMTAwMDAwMFoXDTIwMDUzMDEwNDgzOFow
FjEUMBIGA1UEAxMLQmFkIElQIG1hc2swggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDCuISVQi3csKqYk5uz7IOhY8MXkiqBaTqagihtiM997G1mJhTojcR+
8DCg3E8OQ3ZajByhxRkwlsR4Srl5sGSwWfF/XaAHGUhWIhjBkDO7toW+EMzI8pAj
cLwIbRlIL0AFnUTe6Z0DcIS5406Y/9MKE2oKXbf4EbVBv88mSkA74Z+lZJWFNxXn
cx/9wq8UdyMY2vHN1Kir1/JbtrqB9wYRBjQtWSbAVZR8nTBPyRp4uvQTS2jOQh+j
TUo1Y3O/o1xg/zRA4FEOUCla704OYRUkc8NuXHiPNNDcktr7gO8E06NVQ6n6aBGa
OJbSst2vHA7Eiog7A2PB4wKn+GDFf+FNAgMBAAGjIDAeMBwGA1UdHgEB/wQSMBCg
DDAKhwgBAgME//8BAKEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYb7/NQwdCE/y40K2B
IfKKb++HvCaKfAC9aAwrGWQsEWezqdl5Cqw5XWUAFjtTRm6iprVnmdvov6IlrgSV
EQk6L96stz24vAF0MIBHSFRMoPtrqLiihLf0NOV7ztxSePQxbUJRroe/lKy+lhb7
VeV5gmT9rFA45NzLgSznd2+dmyNcfQQD9AeeftRX4maUTeu1XFxinowtg+ZGFOKh
E4D92uCGJxGSK72HF0/LGRhLXozmDdmPfSN2b6T/oLo942031iY46BqcI5LIVh8a
Go4A1jOma5X6gh50Cw+kht8jM3yeNhSzXOKj7Uigjijx10z2wJu09Tyj5ahjoiwI
pdX+
-----END CERTIFICATE-----`

func TestBadIPMask(t *testing.T) {
	block, _ := pem.Decode([]byte(badIPMaskPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatalf("unexpected success")
	}

	const expected = "contained invalid mask"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %q in error but got: %s", expected, err)
	}
}

const additionalGeneralSubtreePEM = `
-----BEGIN CERTIFICATE-----
MIIG4TCCBMmgAwIBAgIRALss+4rLw2Ia7tFFhxE8g5cwDQYJKoZIhvcNAQELBQAw
bjELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
MT0wOwYDVQQDDDRNaW5pc3RlcmllIHZhbiBEZWZlbnNpZSBDZXJ0aWZpY2F0aWUg
QXV0b3JpdGVpdCAtIEcyMB4XDTEzMDMwNjEyMDM0OVoXDTEzMTEzMDEyMDM1MFow
bDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUNlcnRpUGF0aCBMTEMxIjAgBgNVBAsT
GUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxITAfBgNVBAMTGENlcnRpUGF0aCBC
cmlkZ2UgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLW
4kXiRqvwBhJfN9uz12FA+P2D34MPxOt7TGXljm2plJ2CLzvaH8/ymsMdSWdJBS1M
8FmwvNL1w3A6ZuzksJjPikAu8kY3dcp3mrkk9eCPORDAwGtfsXwZysLiuEaDWpbD
dHOaHnI6qWU0N6OI+hNX58EjDpIGC1WQdho1tHOTPc5Hf5/hOpM/29v/wr7kySjs
Z+7nsvkm5rNhuJNzPsLsgzVaJ5/BVyOplZy24FKM8Y43MjR4osZm+a2e0zniqw6/
rvcjcGYabYaznZfQG1GXoyf2Vea+CCgpgUhlVafgkwEs8izl8rIpvBzXiFAgFQuG
Ituoy92PJbDs430fA/cCAwEAAaOCAnowggJ2MEUGCCsGAQUFBwEBBDkwNzA1Bggr
BgEFBQcwAoYpaHR0cDovL2NlcnRzLmNhLm1pbmRlZi5ubC9taW5kZWYtY2EtMi5w
N2MwHwYDVR0jBBgwFoAUzln9WSPz2M64Rl2HYf2/KD8StmQwDwYDVR0TAQH/BAUw
AwEB/zCB6QYDVR0gBIHhMIHeMEgGCmCEEAGHawECBQEwOjA4BggrBgEFBQcCARYs
aHR0cDovL2Nwcy5kcC5jYS5taW5kZWYubmwvbWluZGVmLWNhLWRwLWNwcy8wSAYK
YIQQAYdrAQIFAjA6MDgGCCsGAQUFBwIBFixodHRwOi8vY3BzLmRwLmNhLm1pbmRl
Zi5ubC9taW5kZWYtY2EtZHAtY3BzLzBIBgpghBABh2sBAgUDMDowOAYIKwYBBQUH
AgEWLGh0dHA6Ly9jcHMuZHAuY2EubWluZGVmLm5sL21pbmRlZi1jYS1kcC1jcHMv
MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmxzLmNhLm1pbmRlZi5ubC9taW5k
ZWYtY2EtMi5jcmwwDgYDVR0PAQH/BAQDAgEGMEYGA1UdHgEB/wQ8MDqhODA2pDEw
LzELMAkGA1UEBhMCTkwxIDAeBgNVBAoTF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
gQFjMF0GA1UdIQRWMFQwGgYKYIQQAYdrAQIFAQYMKwYBBAGBu1MBAQECMBoGCmCE
EAGHawECBQIGDCsGAQQBgbtTAQEBAjAaBgpghBABh2sBAgUDBgwrBgEEAYG7UwEB
AQIwHQYDVR0OBBYEFNDCjBM3M3ZKkag84ei3/aKc0d0UMA0GCSqGSIb3DQEBCwUA
A4ICAQAQXFn9jF90/DNFf15JhoGtta/0dNInb14PMu3PAjcdrXYCDPpQZOArTUng
5YT1WuzfmjnXiTsziT3my0r9Mxvz/btKK/lnVOMW4c2q/8sIsIPnnW5ZaRGrsANB
dNDZkzMYmeG2Pfgvd0AQSOrpE/TVgWfu/+MMRWwX9y6VbooBR7BLv7zMuVH0WqLn
6OMFth7fqsThlfMSzkE/RDSaU6n3wXAWT1SIqBITtccRjSUQUFm/q3xrb2cwcZA6
8vdS4hzNd+ttS905ay31Ks4/1Wrm1bH5RhEfRSH0VSXnc0b+z+RyBbmiwtVZqzxE
u3UQg/rAmtLDclLFEzjp8YDTIRYSLwstDbEXO/0ArdGrQm79HQ8i/3ZbP2357myW
i15qd6gMJIgGHS4b8Hc7R1K8LQ9Gm1aLKBEWVNGZlPK/cpXThpVmoEyslN2DHCrc
fbMbjNZpXlTMa+/b9z7Fa4X8dY8u/ELzZuJXJv5Rmqtg29eopFFYDCl0Nkh1XAjo
QejEoHHUvYV8TThHZr6Z6Ib8CECgTehU4QvepkgDXNoNrKRZBG0JhLjkwxh2whZq
nvWBfALC2VuNOM6C0rDY+HmhMlVt0XeqnybD9MuQALMit7Z00Cw2CIjNsBI9xBqD
xKK9CjUb7gzRUWSpB9jGHsvpEMHOzIFhufvH2Bz1XJw+Cl7khw==
-----END CERTIFICATE-----`

func TestAdditionFieldsInGeneralSubtree(t *testing.T) {
	// Very rarely, certificates can include additional fields in the
	// GeneralSubtree structure. This tests that such certificates can be
	// parsed.
	block, _ := pem.Decode([]byte(additionalGeneralSubtreePEM))
	if _, err := ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}

func TestEmptySubject(t *testing.T) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
	}

	derBytes, err := CreateCertificate(rand.Reader, &template, &template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			if !ext.Critical {
				t.Fatal("SAN extension is not critical")
			}
			return
		}
	}

	t.Fatal("SAN extension is missing")
}

// multipleURLsInCRLDPPEM contains two URLs in a single CRL DistributionPoint
// structure. It is taken from https://crt.sh/?id=12721534.
const multipleURLsInCRLDPPEM = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----
`

func TestMultipleURLsInCRLDP(t *testing.T) {
	block, _ := pem.Decode([]byte(multipleURLsInCRLDPPEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	want := []string{
		"http://epscd.catcert.net/crl/ec-acc.crl",
		"http://epscd2.catcert.net/crl/ec-acc.crl",
	}
	if got := cert.CRLDistributionPoints; !reflect.DeepEqual(got, want) {
		t.Errorf("CRL distribution points = %#v, want #%v", got, want)
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
				KeyUsage: KeyUsageCertSign,
			},
			template:      &x509.RevocationList{},
			expectedError: "x509: issuer must have the crlSign key usage bit set",
		},
		{
			name: "issuer missing SubjectKeyId",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: KeyUsageCRLSign,
			},
			template:      &x509.RevocationList{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			key:  sm2Priv,
			issuer: &x509.Certificate{
				KeyUsage: KeyUsageCRLSign,
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
				KeyUsage: KeyUsageCRLSign,
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
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				SignatureAlgorithm: SHA256WithRSA,
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
				KeyUsage: KeyUsageCRLSign,
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
				KeyUsage: KeyUsageCRLSign,
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
				KeyUsage: KeyUsageCRLSign,
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: &x509.RevocationList{
				SignatureAlgorithm: ECDSAWithSHA512,
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
				KeyUsage: KeyUsageCRLSign,
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
				KeyUsage: KeyUsageCRLSign,
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

			if tc.template.SignatureAlgorithm != UnknownSignatureAlgorithm &&
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

func marshalAndParseCSR(t *testing.T, template *x509.CertificateRequest) *CertificateRequest {
	derBytes, err := CreateCertificateRequest(rand.Reader, template, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestCertificateRequestRoundtripFields(t *testing.T) {
	urlA, err := url.Parse("https://example.com/_")
	if err != nil {
		t.Fatal(err)
	}
	urlB, err := url.Parse("https://example.org/_")
	if err != nil {
		t.Fatal(err)
	}
	in := &x509.CertificateRequest{
		DNSNames:       []string{"example.com", "example.org"},
		EmailAddresses: []string{"a@example.com", "b@example.com"},
		IPAddresses:    []net.IP{net.IPv4(192, 0, 2, 0), net.IPv6loopback},
		URIs:           []*url.URL{urlA, urlB},
	}
	out := marshalAndParseCSR(t, in)

	if !reflect.DeepEqual(in.DNSNames, out.DNSNames) {
		t.Fatalf("Unexpected DNSNames: got %v, want %v", out.DNSNames, in.DNSNames)
	}
	if !reflect.DeepEqual(in.EmailAddresses, out.EmailAddresses) {
		t.Fatalf("Unexpected EmailAddresses: got %v, want %v", out.EmailAddresses, in.EmailAddresses)
	}
	if len(in.IPAddresses) != len(out.IPAddresses) ||
		!in.IPAddresses[0].Equal(out.IPAddresses[0]) ||
		!in.IPAddresses[1].Equal(out.IPAddresses[1]) {
		t.Fatalf("Unexpected IPAddresses: got %v, want %v", out.IPAddresses, in.IPAddresses)
	}
	if !reflect.DeepEqual(in.URIs, out.URIs) {
		t.Fatalf("Unexpected URIs: got %v, want %v", out.URIs, in.URIs)
	}
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidExtensionSubjectAltName,
				Value:    sanContents,
				Critical: true,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.DNSNames)
	}

	if len(csr.Extensions) != 1 || !csr.Extensions[0].Id.Equal(oidExtensionSubjectAltName) || !csr.Extensions[0].Critical {
		t.Errorf("SAN extension was not faithfully copied, got %#v", csr.Extensions)
	}

	// If there is already an attribute with X.509 extensions then the
	// extra extensions should be added to it rather than creating a CSR
	// with two extension attributes.

	template.Attributes = []pkix.AttributeTypeAndValueSET{
		{
			Type: oidExtensionRequest,
			Value: [][]pkix.AttributeTypeAndValue{
				{
					{
						Type:  oidExtensionAuthorityInfoAccess,
						Value: []byte("foo"),
					},
				},
			},
		},
	}

	csr = marshalAndParseCSR(t, &template)
	if l := len(csr.Attributes); l != 1 {
		t.Errorf("incorrect number of attributes: %d\n", l)
	}

	if !csr.Attributes[0].Type.Equal(oidExtensionRequest) ||
		len(csr.Attributes[0].Value) != 1 ||
		len(csr.Attributes[0].Value[0]) != 2 {
		t.Errorf("bad attributes: %#v\n", csr.Attributes)
	}

	sanContents2, err := marshalSANs([]string{"foo2.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Extensions in Attributes should override those in ExtraExtensions.
	template.Attributes[0].Value[0] = append(template.Attributes[0].Value[0], pkix.AttributeTypeAndValue{
		Type:  oidExtensionSubjectAltName,
		Value: sanContents2,
	})

	csr = marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo2.example.com" {
		t.Errorf("Attributes did not override ExtraExtensions. Got %v\n", csr.DNSNames)
	}
}

type brokenSigner struct {
	pub crypto.PublicKey
}

func (bs *brokenSigner) Public() crypto.PublicKey {
	return bs.pub
}

func (bs *brokenSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

func TestCreateCertificateBrokenSigner(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"example.com"},
	}
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate test key: %s", err)
	}
	expectedErr := "x509: signature over certificate returned by signer is invalid: crypto/rsa: verification error"
	_, err = CreateCertificate(rand.Reader, template, template, k.Public(), &brokenSigner{k.Public()})
	if err == nil {
		t.Fatal("expected CreateCertificate to fail with a broken signer")
	} else if err.Error() != expectedErr {
		t.Fatalf("CreateCertificate returned an unexpected error: got %q, want %q", err, expectedErr)
	}
}

func TestRSAPSAParameters(t *testing.T) {
	generateParams := func(hashFunc crypto.Hash) []byte {
		var hashOID asn1.ObjectIdentifier

		switch hashFunc {
		case crypto.SHA256:
			hashOID = oidSHA256
		case crypto.SHA384:
			hashOID = oidSHA384
		case crypto.SHA512:
			hashOID = oidSHA512
		}

		params := pssParameters{
			Hash: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.NullRawValue,
			},
			MGF: pkix.AlgorithmIdentifier{
				Algorithm: oidMGF1,
			},
			SaltLength:   hashFunc.Size(),
			TrailerField: 1,
		}

		mgf1Params := pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		}

		var err error
		params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
		if err != nil {
			t.Fatalf("failed to marshal MGF parameters: %s", err)
		}

		serialized, err := asn1.Marshal(params)
		if err != nil {
			t.Fatalf("failed to marshal parameters: %s", err)
		}

		return serialized
	}

	for h, params := range hashToPSSParameters {
		generated := generateParams(h)
		if !bytes.Equal(params.FullBytes, generated) {
			t.Errorf("hardcoded parameters for %s didn't match generated parameters: got (generated) %x, wanted (hardcoded) %x", h, generated, params.FullBytes)
		}
	}
}

func TestUnknownExtKey(t *testing.T) {
	const errorContains = "unknown extended key usage"

	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		DNSNames:     []string{"foo"},
		ExtKeyUsage:  []ExtKeyUsage{ExtKeyUsage(-1)},
	}
	signer, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Errorf("failed to generate key for TestUnknownExtKey")
	}

	_, err = CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

func TestIA5SANEnforcement(t *testing.T) {
	k, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %s", err)
	}

	testURL, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatalf("url.Parse failed: %s", err)
	}
	testURL.RawQuery = "∞"

	marshalTests := []struct {
		name          string
		template      *x509.Certificate
		expectedError string
	}{
		{
			name: "marshal: unicode dNSName",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(0),
				DNSNames:     []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode rfc822Name",
			template: &x509.Certificate{
				SerialNumber:   big.NewInt(0),
				EmailAddresses: []string{"∞"},
			},
			expectedError: "x509: \"∞\" cannot be encoded as an IA5String",
		},
		{
			name: "marshal: unicode uniformResourceIdentifier",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(0),
				URIs:         []*url.URL{testURL},
			},
			expectedError: "x509: \"https://example.com/?∞\" cannot be encoded as an IA5String",
		},
	}

	for _, tc := range marshalTests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CreateCertificate(rand.Reader, tc.template, tc.template, k.Public(), k)
			if err == nil {
				t.Errorf("expected CreateCertificate to fail with template: %v", tc.template)
			} else if err.Error() != tc.expectedError {
				t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
			}
		})
	}

	unmarshalTests := []struct {
		name          string
		cert          string
		expectedError string
	}{
		{
			name:          "unmarshal: unicode dNSName",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000424bcc48180d8d9db794028f2575ebe3cac79f04d7b0d0151c5292e588aac3668c495f108c626168462e0668c9705e08a211dd103a659d2684e0adf8c2bfd47baa315301330110603551d110101ff040730058203e2889e300a06082a8648ce3d04030203490030460221008ac7827ac326a6ee0fa70b2afe99af575ec60b975f820f3c25f60fff43fbccd0022100bffeed93556722d43d13e461d5b3e33efc61f6349300327d3a0196cb6da501c2",
			expectedError: "x509: SAN dNSName is malformed",
		},
		{
			name:          "unmarshal: unicode rfc822Name",
			cert:          "308201083081aea003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d0301070342000405cb4c4ba72aac980f7b11b0285191425e29e196ce7c5df1c83f56886566e517f196657cc1b73de89ab84ce503fd634e2f2af88fde24c63ca536dc3a5eed2665a315301330110603551d110101ff040730058103e2889e300a06082a8648ce3d0403020349003046022100ed1431cd4b9bb03d88d1511a0ec128a51204375764c716280dc36e2a60142c8902210088c96d25cfaf97eea851ff17d87bb6fe619d6546656e1739f35c3566051c3d0f",
			expectedError: "x509: SAN rfc822Name is malformed",
		},
		{
			name:          "unmarshal: unicode uniformResourceIdentifier",
			cert:          "3082011b3081c3a003020102020100300a06082a8648ce3d04030230003022180f30303031303130313030303030305a180f30303031303130313030303030305a30003059301306072a8648ce3d020106082a8648ce3d03010703420004ce0a79b511701d9188e1ea76bcc5907f1db51de6cc1a037b803f256e8588145ca409d120288bfeb4e38f3088104674d374b35bb91fc80d768d1d519dbe2b0b5aa32a302830260603551d110101ff041c301a861868747470733a2f2f6578616d706c652e636f6d2f3fe2889e300a06082a8648ce3d0403020347003044022044f4697779fd1dae1e382d2452413c5c5ca67851e267d6bc64a8d164977c172c0220505015e657637aa1945d46e7650b6f59b968fc1508ca8b152c99f782446dfc81",
			expectedError: "x509: SAN uniformResourceIdentifier is malformed",
		},
	}

	for _, tc := range unmarshalTests {
		der, err := hex.DecodeString(tc.cert)
		if err != nil {
			t.Fatalf("failed to decode test cert: %s", err)
		}
		_, err = ParseCertificate(der)
		if err == nil {
			t.Error("expected CreateCertificate to fail")
		} else if err.Error() != tc.expectedError {
			t.Errorf("unexpected error: got %q, want %q", err.Error(), tc.expectedError)
		}
	}
}

func TestParseCertificateRawEquals(t *testing.T) {
	p, _ := pem.Decode([]byte(pemCertificate))
	cert, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if !bytes.Equal(p.Bytes, cert.Raw) {
		t.Fatalf("unexpected Certificate.Raw\ngot: %x\nwant: %x\n", cert.Raw, p.Bytes)
	}
}

// certPoolEqual reports whether a and b are equal, except for the
// function pointers.
func certPoolEqual(a, b *CertPool) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	if a == nil {
		return true
	}
	if !reflect.DeepEqual(a.byName, b.byName) ||
		len(a.lazyCerts) != len(b.lazyCerts) {
		return false
	}
	for i := range a.lazyCerts {
		la, lb := a.lazyCerts[i], b.lazyCerts[i]
		if !bytes.Equal(la.rawSubject, lb.rawSubject) {
			return false
		}
		ca, err := la.getCert()
		if err != nil {
			panic(err)
		}
		cb, err := la.getCert()
		if err != nil {
			panic(err)
		}
		if !ca.Equal(cb) {
			return false
		}
	}

	return true
}

func fromBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		panic("failed to base64 decode")
	}
	return out[:n]
}

// These CSR was generated with OpenSSL:
//  openssl req -out CSR.csr -new -sha256 -nodes -keyout privateKey.key -config openssl.cnf
//
// With openssl.cnf containing the following sections:
//   [ v3_req ]
//   basicConstraints = CA:FALSE
//   keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//   subjectAltName = email:gopher@golang.org,DNS:test.example.com
//   [ req_attributes ]
//   challengePassword = ignored challenge
//   unstructuredName  = ignored unstructured name
var csrBase64Array = [...]string{
	// Just [ v3_req ]
	"MIIDHDCCAgQCAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAB6VPMRrchvNW61Tokyq3ZvO6/NoGIbuwUn54q6l5VZW0Ep5Nq8juhegSSnaJ0jrovmUgKDN9vEo2KxuAtwG6udS6Ami3zP+hRd4k9Q8djJPb78nrjzWiindLK5Fps9U5mMoi1ER8ViveyAOTfnZt/jsKUaRsscY2FzE9t9/o5moE6LTcHUS4Ap1eheR+J72WOnQYn3cifYaemsA9MJuLko+kQ6xseqttbh9zjqd9fiCSh/LNkzos9c+mg2yMADitaZinAh+HZi50ooEbjaT3erNq9O6RqwJlgD00g6MQdoz9bTAryCUhCQfkIaepmQ7BxS0pqWNW3MMwfDwx/Snz6g=",
	// Both [ v3_req ] and [ req_attributes ]
	"MIIDaTCCAlECAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaCBpTAgBgkqhkiG9w0BCQcxEwwRaWdub3JlZCBjaGFsbGVuZ2UwKAYJKoZIhvcNAQkCMRsMGWlnbm9yZWQgdW5zdHJ1Y3R1cmVkIG5hbWUwVwYJKoZIhvcNAQkOMUowSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAuBgNVHREEJzAlgRFnb3BoZXJAZ29sYW5nLm9yZ4IQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgxe2N5O48EMsYE7o0rZBB0wi3Ov5/yYfnmmVI22Y3sP6VXbLDW0+UWIeSccOhzUCcZ/G4qcrfhhx6gTZTeA01nP7TdTJURvWAH5iFqj9sQ0qnLq6nEcVHij3sG6M5+BxAIVClQBk6lTCzgphc835Fjj6qSLuJ20XHdL5UfUbiJxx299CHgyBRL+hBUIPfz8p+ZgamyAuDLfnj54zzcRVyLlrmMLNPZNll1Q70RxoU6uWvLH8wB8vQe3Q/guSGubLyLRTUQVPh+dw1L4t8MKFWfX/48jwRM4gIRHFHPeAAE9D9YAoqdIvj/iFm/eQ++7DP8MDwOZWsXeB6jjwHuLmkQ==",
}

func TestParseCertificateRequest(t *testing.T) {
	for _, csrBase64 := range csrBase64Array {
		csrBytes := fromBase64(csrBase64)
		csr, err := ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %s", err)
		}

		if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "gopher@golang.org" {
			t.Errorf("incorrect email addresses found: %v", csr.EmailAddresses)
		}

		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
			t.Errorf("incorrect DNS names found: %v", csr.DNSNames)
		}

		if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
			t.Errorf("incorrect Subject name: %v", csr.Subject)
		}

		found := false
		for _, e := range csr.Extensions {
			if e.Id.Equal(oidExtensionBasicConstraints) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("basic constraints extension not found in CSR")
		}
	}
}

func TestCriticalFlagInCSRRequestedExtensions(t *testing.T) {
	// This CSR contains an extension request where the extensions have a
	// critical flag in them. In the past we failed to handle this.
	const csrBase64 = "MIICrTCCAZUCAQIwMzEgMB4GA1UEAwwXU0NFUCBDQSBmb3IgRGV2ZWxlciBTcmwxDzANBgNVBAsMBjQzNTk3MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFMAJ7Zy9YyfgbNlbUWAW0LalNRMPs7aXmLANsCpjhnw3lLlfDPaLeWyKh1nK5I5ojaJOW6KIOSAcJkDUe3rrE0wR0RVt3UxArqs0R/ND3u5Q+bDQY2X1HAFUHzUzcdm5JRAIA355v90teMckaWAIlkRQjDE22Lzc6NAl64KOd1rqOUNj8+PfX6fSo20jm94Pp1+a6mfk3G/RUWVuSm7owO5DZI/Fsi2ijdmb4NUar6K/bDKYTrDFkzcqAyMfP3TitUtBp19Mp3B1yAlHjlbp/r5fSSXfOGHZdgIvp0WkLuK2u5eQrX5l7HMB/5epgUs3HQxKY6ljhh5wAjDwz//LsCAwEAAaA1MDMGCSqGSIb3DQEJDjEmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEFBQADggEBAAMq3bxJSPQEgzLYR/yaVvgjCDrc3zUbIwdOis6Go06Q4RnjH5yRaSZAqZQTDsPurQcnz2I39VMGEiSkFJFavf4QHIZ7QFLkyXadMtALc87tm17Ej719SbHcBSSZayR9VYJUNXRLayI6HvyUrmqcMKh+iX3WY3ICr59/wlM0tYa8DYN4yzmOa2Onb29gy3YlaF5A2AKAMmk003cRT9gY26mjpv7d21czOSSeNyVIoZ04IR9ee71vWTMdv0hu/af5kSjQ+ZG5/Qgc0+mnECLz/1gtxt1srLYbtYQ/qAY8oX1DCSGFS61tN/vl+4cxGMD/VGcGzADRLRHSlVqy2Qgss6Q="

	csrBytes := fromBase64(csrBase64)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	expected := []struct {
		Id    asn1.ObjectIdentifier
		Value []byte
	}{
		{oidExtensionBasicConstraints, fromBase64("MAYBAf8CAQA=")},
		{oidExtensionKeyUsage, fromBase64("AwIChA==")},
	}

	if n := len(csr.Extensions); n != len(expected) {
		t.Fatalf("expected to find %d extensions but found %d", len(expected), n)
	}

	for i, extension := range csr.Extensions {
		if !extension.Id.Equal(expected[i].Id) {
			t.Fatalf("extension #%d has unexpected type %v (expected %v)", i, extension.Id, expected[i].Id)
		}

		if !bytes.Equal(extension.Value, expected[i].Value) {
			t.Fatalf("extension #%d has unexpected contents %x (expected %x)", i, extension.Value, expected[i].Value)
		}
	}
}

// serialiseAndParse generates a self-signed certificate from template and
// returns a parsed version of it.
func serialiseAndParse(t *testing.T, template *x509.Certificate) *Certificate {
	derBytes, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
		return nil
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
		return nil
	}

	return cert
}

func TestMaxPathLenNotCA(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false, got %d", m)
	}

	template.MaxPathLen = -1
	if m := serialiseAndParse(t, template).MaxPathLen; m != -1 {
		t.Errorf("MaxPathLen should be -1 when IsCa is false and MaxPathLen set to -1, got %d", m)
	}

	template.MaxPathLen = 5
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("specifying a MaxPathLen when IsCA is false should fail")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	if _, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey); err == nil {
		t.Error("setting MaxPathLenZero when IsCA is false should fail")
	}

	template.BasicConstraintsValid = false
	if m := serialiseAndParse(t, template).MaxPathLen; m != 0 {
		t.Errorf("Bad MaxPathLen should be ignored if BasicConstraintsValid is false, got %d", m)
	}
}

func TestMaxPathLen(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert1 := serialiseAndParse(t, template)
	if m := cert1.MaxPathLen; m != -1 {
		t.Errorf("Omitting MaxPathLen didn't turn into -1, got %d", m)
	}
	if cert1.MaxPathLenZero {
		t.Errorf("Omitting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 1
	cert2 := serialiseAndParse(t, template)
	if m := cert2.MaxPathLen; m != 1 {
		t.Errorf("Setting MaxPathLen didn't work. Got %d but set 1", m)
	}
	if cert2.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	cert3 := serialiseAndParse(t, template)
	if m := cert3.MaxPathLen; m != 0 {
		t.Errorf("Setting MaxPathLenZero didn't work, got %d", m)
	}
	if !cert3.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen to zero didn't result in MaxPathLenZero")
	}
}

func TestNoAuthorityKeyIdInSelfSignedCert(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) != 0 {
		t.Fatalf("self-signed certificate contained default authority key id")
	}

	template.AuthorityKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit authority key id")
	}
}

func TestNoSubjectKeyIdInCert(t *testing.T) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate did not generate subject key id using the public key")
	}

	template.IsCA = false
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) != 0 {
		t.Fatalf("self-signed certificate generated subject key id when it isn't a CA")
	}

	template.SubjectKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.SubjectKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit subject key id")
	}
}

func TestVerifyEmptyCertificate(t *testing.T) {
	if _, err := new(Certificate).Verify(VerifyOptions{}); err != errNotParsed {
		t.Errorf("Verifying empty certificate resulted in unexpected error: %q (wanted %q)", err, errNotParsed)
	}
}

// certMissingRSANULL contains an RSA public key where the AlgorithmIdentifier
// parameters are omitted rather than being an ASN.1 NULL.
const certMissingRSANULL = `
-----BEGIN CERTIFICATE-----
MIIB7TCCAVigAwIBAgIBADALBgkqhkiG9w0BAQUwJjEQMA4GA1UEChMHQWNtZSBD
bzESMBAGA1UEAxMJMTI3LjAuMC4xMB4XDTExMTIwODA3NTUxMloXDTEyMTIwNzA4
MDAxMlowJjEQMA4GA1UEChMHQWNtZSBDbzESMBAGA1UEAxMJMTI3LjAuMC4xMIGc
MAsGCSqGSIb3DQEBAQOBjAAwgYgCgYBO0Hsx44Jk2VnAwoekXh6LczPHY1PfZpIG
hPZk1Y/kNqcdK+izIDZFI7Xjla7t4PUgnI2V339aEu+H5Fto5OkOdOwEin/ekyfE
ARl6vfLcPRSr0FTKIQzQTW6HLlzF0rtNS0/Otiz3fojsfNcCkXSmHgwa2uNKWi7e
E5xMQIhZkwIDAQABozIwMDAOBgNVHQ8BAf8EBAMCAKAwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDALBgkqhkiG9w0BAQUDgYEANh+zegx1yW43RmEr1b3A
p0vMRpqBWHyFeSnIyMZn3TJWRSt1tukkqVCavh9a+hoV2cxVlXIWg7nCto/9iIw4
hB2rXZIxE0/9gzvGnfERYraL7KtnvshksBFQRlgXa5kc0x38BvEO5ZaoDPl4ILdE
GFGNEH5PlGffo05wc46QkYU=
-----END CERTIFICATE-----`

func TestRSAMissingNULLParameters(t *testing.T) {
	block, _ := pem.Decode([]byte(certMissingRSANULL))
	if _, err := ParseCertificate(block.Bytes); err == nil {
		t.Error("unexpected success when parsing certificate with missing RSA NULL parameter")
	} else if !strings.Contains(err.Error(), "missing NULL") {
		t.Errorf("unrecognised error when parsing certificate with missing RSA NULL parameter: %s", err)
	}
}

const certISOOID = `
-----BEGIN CERTIFICATE-----
MIIB5TCCAVKgAwIBAgIQtwyL3RPWV7dJQp34HwZG9DAJBgUrDgMCHQUAMBExDzAN
BgNVBAMTBm15dGVzdDAeFw0xNjA4MDkyMjExMDVaFw0zOTEyMzEyMzU5NTlaMBEx
DzANBgNVBAMTBm15dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArzIH
GsyDB3ohIGkkvijF2PTRUX1bvOtY1eUUpjwHyu0twpAKSuaQv2Ha+/63+aHe8O86
BT+98wjXFX6RFSagtAujo80rIF2dSm33BGt18pDN8v6zp93dnAm0jRaSQrHJ75xw
5O+S1oEYR1LtUoFJy6qB104j6aINBAgOiLIKiMkCAwEAAaNGMEQwQgYDVR0BBDsw
OYAQVuYVQ/WDjdGSkZRlTtJDNKETMBExDzANBgNVBAMTBm15dGVzdIIQtwyL3RPW
V7dJQp34HwZG9DAJBgUrDgMCHQUAA4GBABngrSkH7vG5lY4sa4AZF59lAAXqBVJE
J4TBiKC62hCdZv18rBleP6ETfhbPg7pTs8p4ebQbpmtNxRS9Lw3MzQ8Ya5Ybwzj2
NwBSyCtCQl7mrEg4nJqJl4A2EUhnET/oVxU0oTV/SZ3ziGXcY1oG1s6vidV7TZTu
MCRtdSdaM7g3
-----END CERTIFICATE-----`

func TestISOOIDInCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certISOOID))
	if cert, err := ParseCertificate(block.Bytes); err != nil {
		t.Errorf("certificate with ISO OID failed to parse: %s", err)
	} else if cert.SignatureAlgorithm == UnknownSignatureAlgorithm {
		t.Errorf("ISO OID not recognised in certificate")
	}
}

// certMultipleRDN contains a RelativeDistinguishedName with two elements (the
// common name and serial number). This particular certificate was the first
// such certificate in the “Pilot” Certificate Transparency log.
const certMultipleRDN = `
-----BEGIN CERTIFICATE-----
MIIFRzCCBC+gAwIBAgIEOl59NTANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMREwDwYDVQQLEwhzaWdvdi1j
YTAeFw0xMjExMTYxMDUyNTdaFw0xNzExMTYxMjQ5MDVaMIGLMQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMRkwFwYDVQQLExB3ZWItY2Vy
dGlmaWNhdGVzMRAwDgYDVQQLEwdTZXJ2ZXJzMTIwFAYDVQQFEw0xMjM2NDg0MDEw
MDEwMBoGA1UEAxMTZXBvcnRhbC5tc3MuZWR1cy5zaTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMrNkZH9MPuBTjMGNk3sJX8V+CkFx/4ru7RTlLS6dlYM
098dtSfJ3s2w0p/1NB9UmR8j0yS0Kg6yoZ3ShsSO4DWBtcQD8820a6BYwqxxQTNf
HSRZOc+N/4TQrvmK6t4k9Aw+YEYTMrWOU4UTeyhDeCcUsBdh7HjfWsVaqNky+2sv
oic3zP5gF+2QfPkvOoHT3FLR8olNhViIE6Kk3eFIEs4dkq/ZzlYdLb8pHQoj/sGI
zFmA5AFvm1HURqOmJriFjBwaCtn8AVEYOtQrnUCzJYu1ex8azyS2ZgYMX0u8A5Z/
y2aMS/B2W+H79WcgLpK28vPwe7vam0oFrVytAd+u65ECAwEAAaOCAf4wggH6MA4G
A1UdDwEB/wQEAwIFoDBABgNVHSAEOTA3MDUGCisGAQQBr1kBAwMwJzAlBggrBgEF
BQcCARYZaHR0cDovL3d3dy5jYS5nb3Yuc2kvY3BzLzAfBgNVHREEGDAWgRRwb2Rw
b3JhLm1pemtzQGdvdi5zaTCB8QYDVR0fBIHpMIHmMFWgU6BRpE8wTTELMAkGA1UE
BhMCc2kxGzAZBgNVBAoTEnN0YXRlLWluc3RpdHV0aW9uczERMA8GA1UECxMIc2ln
b3YtY2ExDjAMBgNVBAMTBUNSTDM5MIGMoIGJoIGGhldsZGFwOi8veDUwMC5nb3Yu
c2kvb3U9c2lnb3YtY2Esbz1zdGF0ZS1pbnN0aXR1dGlvbnMsYz1zaT9jZXJ0aWZp
Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2WGK2h0dHA6Ly93d3cuc2lnb3YtY2EuZ292
LnNpL2NybC9zaWdvdi1jYS5jcmwwKwYDVR0QBCQwIoAPMjAxMjExMTYxMDUyNTda
gQ8yMDE3MTExNjEyNDkwNVowHwYDVR0jBBgwFoAUHvjUU2uzgwbpBAZXAvmlv8ZY
PHIwHQYDVR0OBBYEFGI1Duuu+wTGDZka/xHNbwcbM69ZMAkGA1UdEwQCMAAwGQYJ
KoZIhvZ9B0EABAwwChsEVjcuMQMCA6gwDQYJKoZIhvcNAQEFBQADggEBAHny0K1y
BQznrzDu3DDpBcGYguKU0dvU9rqsV1ua4nxkriSMWjgsX6XJFDdDW60I3P4VWab5
ag5fZzbGqi8kva/CzGgZh+CES0aWCPy+4Gb8lwOTt+854/laaJvd6kgKTER7z7U9
9C86Ch2y4sXNwwwPJ1A9dmrZJZOcJjS/WYZgwaafY2Hdxub5jqPE5nehwYUPVu9R
uH6/skk4OEKcfOtN0hCnISOVuKYyS4ANARWRG5VGHIH06z3lGUVARFRJ61gtAprd
La+fgSS+LVZ+kU2TkeoWAKvGq8MAgDq4D4Xqwekg7WKFeuyusi/NI5rm40XgjBMF
DF72IUofoVt7wo0=
-----END CERTIFICATE-----`

func TestMultipleRDN(t *testing.T) {
	block, _ := pem.Decode([]byte(certMultipleRDN))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certificate with two elements in an RDN failed to parse: %v", err)
	}

	if want := "eportal.mss.edus.si"; cert.Subject.CommonName != want {
		t.Errorf("got common name of %q, but want %q", cert.Subject.CommonName, want)
	}

	if want := "1236484010010"; cert.Subject.SerialNumber != want {
		t.Errorf("got serial number of %q, but want %q", cert.Subject.SerialNumber, want)
	}
}

func TestSystemCertPool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not implemented on Windows (Issue 16736, 18609) or darwin (Issue 46287)")
	}
	a, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	b, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !certPoolEqual(a, b) {
		t.Fatal("two calls to SystemCertPool had different results")
	}
	if ok := b.AppendCertsFromPEM([]byte(`
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIRANXM5I3gjuqDfTp/PYrs+u8wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODAzMjcxOTU2MjFaFw0xOTAzMjcxOTU2
MjFaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDK+9m3rjsO2Djes6bIYQZ3eV29JF09ZrjOrEHLtaKrD6/acsoSoTsf
cQr+rzzztdB5ijWXCS64zo/0OiqBeZUNZ67jVdToa9qW5UYe2H0Y+ZNdfA5GYMFD
yk/l3/uBu3suTZPfXiW2TjEi27Q8ruNUIZ54DpTcs6y2rBRFzadPWwn/VQMlvRXM
jrzl8Y08dgnYmaAHprxVzwMXcQ/Brol+v9GvjaH1DooHqkn8O178wsPQNhdtvN01
IXL46cYdcUwWrE/GX5u+9DaSi+0KWxAPQ+NVD5qUI0CKl4714yGGh7feXMjJdHgl
VG4QJZlJvC4FsURgCHJT6uHGIelnSwhbAgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMCAGA1UdEQQZMBeC
FVRlc3RTeXN0ZW1DZXJ0UG9vbC5nbzANBgkqhkiG9w0BAQsFAAOCAQEAwuSRx/VR
BKh2ICxZjL6jBwk/7UlU1XKbhQD96RqkidDNGEc6eLZ90Z5XXTurEsXqdm5jQYPs
1cdcSW+fOSMl7MfW9e5tM66FaIPZl9rKZ1r7GkOfgn93xdLAWe8XHd19xRfDreub
YC8DVqgLASOEYFupVSl76ktPfxkU5KCvmUf3P2PrRybk1qLGFytGxfyice2gHSNI
gify3K/+H/7wCkyFW4xYvzl7WW4mXxoqPRPjQt1J423DhnnQ4G1P8V/vhUpXNXOq
N9IEPnWuihC09cyx/WMQIUlWnaQLHdfpPS04Iez3yy2PdfXJzwfPrja7rNE+skK6
pa/O1nF0AfWOpw==
-----END CERTIFICATE-----
	`)); !ok {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if reflect.DeepEqual(a, b) {
		t.Fatal("changing one pool modified the other")
	}
}

// mismatchingSigAlgIDPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching OIDs
const mismatchingSigAlgIDPEM = `-----BEGIN CERTIFICATE-----
MIIBBzCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAKBggqhkjOPQQD
AwNIADBFAiBi1jz/T2HT5nAfrD7zsgR+68qh7Erc6Q4qlxYBOgKG4QIhAOtjIn+Q
tA+bq+55P3ntxTOVRq0nv1mwnkjwt9cQR9Fn
-----END CERTIFICATE-----`

// mismatchingSigAlgParamPEM contains a certificate where the Certificate
// signatureAlgorithm and the TBSCertificate signature contain
// mismatching parameters
const mismatchingSigAlgParamPEM = `-----BEGIN CERTIFICATE-----
MIIBCTCBrqADAgECAgEAMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBa
GA8wMDAxMDEwMTAwMDAwMFowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOqV
EDuVXxwZgIU3+dOwv1SsMu0xuV48hf7xmK8n7sAMYgllB+96DnPqBeboJj4snYnx
0AcE0PDVQ1l4Z3YXsQWjFTATMBEGA1UdEQEB/wQHMAWCA2FzZDAMBggqhkjOPQQD
AgUAA0gAMEUCIGLWPP9PYdPmcB+sPvOyBH7ryqHsStzpDiqXFgE6AobhAiEA62Mi
f5C0D5ur7nk/ee3FM5VGrSe/WbCeSPC31xBH0Wc=
-----END CERTIFICATE-----`

func TestSigAlgMismatch(t *testing.T) {
	for _, certPEM := range []string{mismatchingSigAlgIDPEM, mismatchingSigAlgParamPEM} {
		b, _ := pem.Decode([]byte(certPEM))
		if b == nil {
			t.Fatalf("couldn't decode test certificate")
		}
		_, err := ParseCertificate(b.Bytes)
		if err == nil {
			t.Fatalf("expected ParseCertificate to fail")
		}
		expected := "x509: inner and outer signature algorithm identifiers don't match"
		if err.Error() != expected {
			t.Errorf("unexpected error from ParseCertificate: got %q, want %q", err.Error(), expected)
		}
	}
}

const optionalAuthKeyIDPEM = `-----BEGIN CERTIFICATE-----
MIIFEjCCBHugAwIBAgICAQwwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1Zh
bGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIElu
Yy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24g
QXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAe
BgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDYyOTE3MzkxNloX
DTI0MDYyOTE3MzkxNlowaDELMAkGA1UEBhMCVVMxJTAjBgNVBAoTHFN0YXJmaWVs
ZCBUZWNobm9sb2dpZXMsIEluYy4xMjAwBgNVBAsTKVN0YXJmaWVsZCBDbGFzcyAy
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0A
MIIBCAKCAQEAtzLI/ulxpgSFrQwRZN/OTe/IAxiHP6Gr+zymn/DDodrU2G4rU5D7
JKQ+hPCe6F/s5SdE9SimP3ve4CrwyK9TL57KBQGTHo9mHDmnTfpatnMEJWbrd3/n
WcZKmSUUVOsmx/N/GdUwcI+vsEYq/63rKe3Xn6oEh6PU+YmlNF/bQ5GCNtlmPLG4
uYL9nDo+EMg77wZlZnqbGRg9/3FRPDAuX749d3OyXQZswyNWmiuFJpIcpwKz5D8N
rwh5grg2Peqc0zWzvGnK9cyd6P1kjReAM25eSl2ZyR6HtJ0awNVuEzUjXt+bXz3v
1vd2wuo+u3gNHEJnawTY+Nbab4vyRKABqwIBA6OCAfMwggHvMB0GA1UdDgQWBBS/
X7fRzt0fhvRbVazc1xDCDqmI5zCB0gYDVR0jBIHKMIHHoYHBpIG+MIG7MSQwIgYD
VQQHExtWYWxpQ2VydCBWYWxpZGF0aW9uIE5ldHdvcmsxFzAVBgNVBAoTDlZhbGlD
ZXJ0LCBJbmMuMTUwMwYDVQQLEyxWYWxpQ2VydCBDbGFzcyAyIFBvbGljeSBWYWxp
ZGF0aW9uIEF1dGhvcml0eTEhMB8GA1UEAxMYaHR0cDovL3d3dy52YWxpY2VydC5j
b20vMSAwHgYJKoZIhvcNAQkBFhFpbmZvQHZhbGljZXJ0LmNvbYIBATAPBgNVHRMB
Af8EBTADAQH/MDkGCCsGAQUFBwEBBC0wKzApBggrBgEFBQcwAYYdaHR0cDovL29j
c3Auc3RhcmZpZWxkdGVjaC5jb20wSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2Nl
cnRpZmljYXRlcy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5L3Jvb3QuY3Js
MFEGA1UdIARKMEgwRgYEVR0gADA+MDwGCCsGAQUFBwIBFjBodHRwOi8vY2VydGlm
aWNhdGVzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQD
AgEGMA0GCSqGSIb3DQEBBQUAA4GBAKVi8afCXSWlcD284ipxs33kDTcdVWptobCr
mADkhWBKIMuh8D1195TaQ39oXCUIuNJ9MxB73HZn8bjhU3zhxoNbKXuNSm8uf0So
GkVrMgfHeMpkksK0hAzc3S1fTbvdiuo43NlmouxBulVtWmQ9twPMHOKRUJ7jCUSV
FxdzPcwl
-----END CERTIFICATE-----`

func TestAuthKeyIdOptional(t *testing.T) {
	b, _ := pem.Decode([]byte(optionalAuthKeyIDPEM))
	if b == nil {
		t.Fatalf("couldn't decode test certificate")
	}
	_, err := ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate to failed to parse certificate with optional authority key identifier fields: %s", err)
	}
}
