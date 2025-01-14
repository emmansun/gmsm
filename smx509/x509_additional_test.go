package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/ecdh"
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

func getPublicKey(pemContent []byte) (any, error) {
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

const openSSL3Certificate = `
-----BEGIN CERTIFICATE-----
MIICGzCCAcCgAwIBAgIUZ2YpsJJVNcwfjCHBEz8otQDEpUEwCgYIKoEcz1UBg3Uw
YjELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUJlbmdhbHVydTENMAsGA1UEBwwEQ2l0
eTEQMA4GA1UECgwHU29tZU9yZzENMAsGA1UECwwEVGVzdDEPMA0GA1UEAwwGUm9v
dENBMB4XDTI0MDgyNzAyMzQ1NloXDTM0MDgyNTAyMzQ1NlowYjELMAkGA1UEBhMC
SU4xEjAQBgNVBAgMCUJlbmdhbHVydTENMAsGA1UEBwwEQ2l0eTEQMA4GA1UECgwH
U29tZU9yZzENMAsGA1UECwwEVGVzdDEPMA0GA1UEAwwGUm9vdENBMFowFAYIKoEc
z1UBgi0GCCqBHM9VAYItA0IABC8HaH8+WYCtUk06wAFfzR09nnOlQOJ2oORwD25m
S55CdJv+Svzji0nSeSWtXBzo9y4Q6EKLDpOSQbKYeswVDoejUzBRMB0GA1UdDgQW
BBRSGm5/62dcOw8vkiG8YGoZMf6UIzAfBgNVHSMEGDAWgBRSGm5/62dcOw8vkiG8
YGoZMf6UIzAPBgNVHRMBAf8EBTADAQH/MAoGCCqBHM9VAYN1A0kAMEYCIQDC4s3P
wAKTEz+410/odAO30Wzam895L31T1MQ0EaBYtQIhALbw1l4lcun4RTVWYQN5A2r2
Cm2A1bCQaLWY1jsQTBpf
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
	cert, err = ParseCertificatePEM([]byte(openSSL3Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatal("should be ECDSA")
	}
	if cert.SignatureAlgorithm != SM2WithSM3 {
		t.Fatal("should be SM2WithSM3")
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
	if err != nil {
		t.Fatal("ParseCertificateRequest should succeed when parsing CSR with duplicate attributes")
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

func TestMarshalECDHPKIXPublicKey(t *testing.T) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result1, err := MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := ParsePKIXPublicKey(result1)
	if err != nil {
		t.Fatal(err)
	}
	sm2PubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("should be valid sm2 public key")
	}
	sm2ecdhPub, err := sm2.PublicKeyToECDH(sm2PubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !privKey.PublicKey().Equal(sm2ecdhPub) {
		t.Fatal("should be same")
	}
}

func TestToCertificate(t *testing.T) {
	x509Cert := new(x509.Certificate)

	c, err := toCertificate(x509Cert)
	if err != nil || c != x509Cert {
		t.Fatal("should be no error")
	}

	smX509Cert := new(Certificate)
	_, err = toCertificate(smX509Cert)
	if err != nil {
		t.Fatal("should be no error")
	}

	_, err = toCertificate("test")
	if err == nil {
		t.Fatal("should be error")
	}

	_, err = toCertificate(nil)
	if err == nil {
		t.Fatal("should be error")
	}
}

func TestInvalidParentTemplate(t *testing.T) {
	random := rand.Reader

	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}
	_, err = CreateCertificate(random, nil, nil, sm2Priv.PublicKey, sm2Priv)
	if err == nil {
		t.Fatal("should be error")
	}
	if err.Error() != "x509: unsupported template parameter type: <nil>" {
		t.Fatalf("unexpected error message: %v", err.Error())
	}

	_, err = CreateCertificate(random, new(x509.Certificate), nil, sm2Priv.PublicKey, sm2Priv)
	if err == nil {
		t.Fatal("should be error")
	}
	if err.Error() != "x509: unsupported parent parameter type: <nil>" {
		t.Fatalf("unexpected error message: %v", err.Error())
	}
}

func TestCheckSignatureWithDigest(t *testing.T) {
	rawMessage := []byte("test message")
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %s", err)
	}
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %s", err)
	}
	ecdsaPrivateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %s", err)
	}
	sm2PrivateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %s", err)
	}
	sm2PrivateKey2, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %s", err)
	}
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %s", err)
	}

	tests := []struct {
		name          string
		cert          *Certificate
		algo          SignatureAlgorithm
		digest        []byte
		signature     []byte
		expectedError error
	}{
		{
			name: "Valid RSA PKCS1v15 signature",
			cert: &Certificate{
				PublicKey: &rsaPrivateKey.PublicKey,
			},
			algo: SHA256WithRSA,
			digest: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return mustSignPKCS1v15(t, rsaPrivateKey, crypto.SHA256, hash[:])
			}(),
			expectedError: nil,
		},
		{
			name: "Valid ECDSA signature",
			cert: &Certificate{
				PublicKey: &ecdsaPrivateKey.PublicKey,
			},
			algo: ECDSAWithSHA256,
			digest: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return mustSignECDSA(t, ecdsaPrivateKey, hash[:])
			}(),
			expectedError: nil,
		},
		{
			name: "Invalid ECDSA signature",
			cert: &Certificate{
				PublicKey: &ecdsaPrivateKey.PublicKey,
			},
			algo: ECDSAWithSHA256,
			digest: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return mustSignECDSA(t, ecdsaPrivateKey2, hash[:])
			}(),
			expectedError: errors.New("x509: ECDSA verification failure"),
		},
		{
			name: "Valid SM2 signature",
			cert: &Certificate{
				PublicKey: &sm2PrivateKey.PublicKey,
			},
			algo: SM2WithSM3,
			digest: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey.PublicKey, rawMessage, nil)
				return hash[:]
			}(),
			signature: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey.PublicKey, rawMessage, nil)
				return mustSignSM2(t, sm2PrivateKey, hash[:])
			}(),
			expectedError: nil,
		},
		{
			name: "Invalid SM2 signature",
			cert: &Certificate{
				PublicKey: &sm2PrivateKey.PublicKey,
			},
			algo: SM2WithSM3,
			digest: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey.PublicKey, rawMessage, nil)
				return hash[:]
			}(),
			signature: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey2.PublicKey, rawMessage, nil)
				return mustSignSM2(t, sm2PrivateKey2, hash[:])
			}(),
			expectedError: errors.New("x509: SM2 verification failure"),
		},
		{
			name: "Insecure algorithm",
			cert: &Certificate{
				PublicKey: &rsaPrivateKey.PublicKey,
			},
			algo: MD5WithRSA,
			digest: func() []byte {
				hash := md5.Sum(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := md5.Sum(rawMessage)
				return mustSignPKCS1v15(t, rsaPrivateKey, crypto.MD5, hash[:])
			}(),
			expectedError: x509.InsecureAlgorithmError(MD5WithRSA),
		},
		{
			name: "Unsupported algorithm",
			cert: &Certificate{
				PublicKey: ed25519Pub,
			},
			algo: PureEd25519,
			digest: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return ed25519.Sign(ed25519Priv, hash[:])
			}(),
			expectedError: x509.ErrUnsupportedAlgorithm,
		},
		{
			name: "Inconsistent digest and signature algorithm",
			cert: &Certificate{
				PublicKey: &rsaPrivateKey.PublicKey,
			},
			algo: SHA256WithRSA,
			digest: func() []byte {
				hash := sha1.Sum(rawMessage)
				return hash[:]
			}(),
			signature: func() []byte {
				hash := sha256.Sum256(rawMessage)
				return mustSignPKCS1v15(t, rsaPrivateKey, crypto.SHA256, hash[:])
			}(),
			expectedError: errors.New("x509: inconsistent digest and signature algorithm"),
		},
		{
			name: "Inconsistent digest and signature algorithm (SM2)",
			cert: &Certificate{
				PublicKey: &sm2PrivateKey.PublicKey,
			},
			algo: SM2WithSM3,
			digest: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey.PublicKey, rawMessage, nil)
				return hash[:20]
			}(),
			signature: func() []byte {
				hash, _ := sm2.CalculateSM2Hash(&sm2PrivateKey.PublicKey, rawMessage, nil)
				return mustSignSM2(t, sm2PrivateKey, hash[:])
			}(),
			expectedError: errors.New("x509: inconsistent digest and signature algorithm"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cert.CheckSignatureWithDigest(tt.algo, tt.digest, tt.signature)
			if (err == nil || tt.expectedError == nil) && err != tt.expectedError {
				t.Errorf("Case <%v>: expected error %v, got %v", tt.name, tt.expectedError, err)
			}
			if err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("Case <%v>: expected error %v, got %v", tt.name, tt.expectedError, err)
			}
		})
	}
}

func mustSignPKCS1v15(t *testing.T, priv *rsa.PrivateKey, hash crypto.Hash, digest []byte) []byte {
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, hash, digest)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	return signature
}

func mustSignECDSA(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) []byte {
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("failed to marshal signature: %s", err)
	}
	return signature
}

func mustSignSM2(t *testing.T, priv *sm2.PrivateKey, digest []byte) []byte {
	signature, err := sm2.SignASN1(rand.Reader, priv, digest, nil)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	return signature
}
