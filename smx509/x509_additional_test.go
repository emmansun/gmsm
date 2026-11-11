package smx509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/mldsa"
	"github.com/emmansun/gmsm/mlkem"
	"github.com/emmansun/gmsm/sm2"
)

const rfc9935MLKEM512PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIDMjALBglghkgBZQMEBAEDggMhADmVgV5ZfRBDVc8pqlMzyTJRhp1bzb5IcST2
Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHmvG+QsOSb
aTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbWf/mqvJdQ
Pyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lAk0Frg7gS
Tmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8XSCVcuD8
dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoEZM5BqLtE
wtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRrevpsRZMl
JqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5JPSQpaxU
lfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6tnVUAAUH
gVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10zgGocjicy
r5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyekb7U7oR3l
y0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oXthQzzRr4
D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPMFgCQPmUp
NWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGmgx1bVMC3
kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9huqtxp6PT
UZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2NoPwS/eg
nMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3guBw7xZoG
WhttY7Js
-----END PUBLIC KEY-----
`

const rfc9935MLKEM512CertificatePEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

func TestMLKEMPKIXPublicKeyRoundTrip(t *testing.T) {
	seed := make([]byte, mlkem.SeedSize)
	seed[0] = 1
	tests := []struct {
		name string
		key  func() (interface{ Bytes() []byte }, error)
	}{
		{"512", func() (interface{ Bytes() []byte }, error) {
			privateKey, err := mlkem.NewDecapsulationKeyFromSeed512(seed)
			if err != nil {
				return nil, err
			}
			return privateKey.EncapsulationKey(), nil
		}},
		{"768", func() (interface{ Bytes() []byte }, error) {
			privateKey, err := mlkem.NewDecapsulationKeyFromSeed768(seed)
			if err != nil {
				return nil, err
			}
			return privateKey.EncapsulationKey(), nil
		}},
		{"1024", func() (interface{ Bytes() []byte }, error) {
			privateKey, err := mlkem.NewDecapsulationKeyFromSeed1024(seed)
			if err != nil {
				return nil, err
			}
			return privateKey.EncapsulationKey(), nil
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publicKey, err := test.key()
			if err != nil {
				t.Fatal(err)
			}
			der, err := MarshalPKIXPublicKey(publicKey)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			parsedPublicKey, ok := parsed.(interface{ Bytes() []byte })
			if !ok || !bytes.Equal(publicKey.Bytes(), parsedPublicKey.Bytes()) {
				t.Fatalf("parsed public key does not match original: %T", parsed)
			}
			remarshaled, err := MarshalPKIXPublicKey(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(der, remarshaled) {
				t.Fatal("PKIX DER encoding changed after round trip")
			}
		})
	}
}

func TestMLKEMRFC9935SPKIVector(t *testing.T) {
	block, rest := pem.Decode([]byte(rfc9935MLKEM512PublicKeyPEM))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid RFC 9935 SPKI PEM fixture")
	}
	publicKey, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	encapsulationKey, ok := publicKey.(interface{ Bytes() []byte })
	if !ok || len(encapsulationKey.Bytes()) != 800 {
		t.Fatalf("unexpected ML-KEM public key: %T", publicKey)
	}
	remarshaled, err := MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, block.Bytes) {
		t.Fatal("SPKI DER encoding changed after RFC 9935 vector round trip")
	}
}

func TestMLKEMRFC9935CertificateVector(t *testing.T) {
	block, rest := pem.Decode([]byte(rfc9935MLKEM512CertificatePEM))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid RFC 9935 certificate PEM fixture")
	}
	certificate, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.KeyUsage != KeyUsageKeyEncipherment {
		t.Fatalf("unexpected ML-KEM key usage: %v", certificate.KeyUsage)
	}
	publicKeyBlock, _ := pem.Decode([]byte(rfc9935MLKEM512PublicKeyPEM))
	if !bytes.Equal(certificate.RawSubjectPublicKeyInfo, publicKeyBlock.Bytes) {
		t.Fatal("certificate SPKI does not match RFC 9935 public-key vector")
	}
}

func TestMLKEMCertificateKeyUsage(t *testing.T) {
	issuerKey, err := mldsa.GenerateKey44(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ML-KEM issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              KeyUsageCertSign,
	}
	issuerDER, err := CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	decapsulationKey, err := mlkem.NewDecapsulationKeyFromSeed512(make([]byte, mlkem.SeedSize))
	if err != nil {
		t.Fatal(err)
	}

	for _, keyUsage := range []KeyUsage{0, KeyUsageKeyEncipherment} {
		template := &Certificate{
			SerialNumber: big.NewInt(int64(keyUsage) + 2),
			Subject:      pkix.Name{CommonName: "ML-KEM subject"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     keyUsage,
		}
		certificateDER, err := CreateCertificate(rand.Reader, template, issuer, decapsulationKey.EncapsulationKey(), issuerKey)
		if err != nil {
			t.Fatalf("CreateCertificate with key usage %v: %v", keyUsage, err)
		}
		if _, err := ParseCertificate(certificateDER); err != nil {
			t.Fatalf("ParseCertificate with key usage %v: %v", keyUsage, err)
		}
	}

	invalidTemplate := &Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "Invalid ML-KEM subject"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     KeyUsageDigitalSignature,
	}
	if _, err := CreateCertificate(rand.Reader, invalidTemplate, issuer, decapsulationKey.EncapsulationKey(), issuerKey); err == nil {
		t.Fatal("CreateCertificate accepted an invalid ML-KEM key usage")
	}
}

func TestVerifyDistrustedSPKI(t *testing.T) {
	chain := make([]*Certificate, 0, 3)
	for _, certPEM := range []string{googleLeaf, gtsIntermediate, gtsRoot} {
		cert, err := certificateFromPEM(certPEM)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	opts := VerifyOptions{
		Roots:         NewCertPool(),
		Intermediates: NewCertPool(),
		CurrentTime:   time.Unix(1677615892, 0),
		DNSName:       "www.google.com",
	}
	opts.Roots.AddCert(chain[2])
	opts.Intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(opts); err != nil {
		t.Fatalf("trusted chain failed: %v", err)
	}
	for index, name := range []string{"leaf", "intermediate", "root"} {
		t.Run(name, func(t *testing.T) {
			digest := sha256.Sum256(chain[index].RawSubjectPublicKeyInfo)
			hash := hex.EncodeToString(digest[:])
			if _, exists := distrustedSPKIHashes[hash]; exists {
				t.Fatal("test certificate is already distrusted")
			}
			distrustedSPKIHashes[hash] = struct{}{}
			t.Cleanup(func() { delete(distrustedSPKIHashes, hash) })
			for _, keyUsages := range [][]ExtKeyUsage{nil, {ExtKeyUsageAny}} {
				opts.KeyUsages = keyUsages
				chains, err := chain[0].Verify(opts)
				var invalid CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != NoValidChains || len(chains) != 0 {
					t.Fatalf("distrusted chain accepted or wrong error: chains=%d, err=%v", len(chains), err)
				}
			}
		})
	}
	if _, err := chain[0].Verify(opts); err != nil {
		t.Fatalf("trusted chain failed after restoring denylist: %v", err)
	}
}

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
	if cert.PublicKeyAlgorithm != ECDSA {
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
	var template = CertificateRequest{Subject: names, SignatureAlgorithm: SM2WithSM3}
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

func TestInvalidParentTemplate(t *testing.T) {
	random := rand.Reader

	sm2Priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate SM2 key: %s", err)
	}

	// CreateCertificate with a nil parent should panic (nil pointer dereference)
	// since the clean fork doesn't wrap stdlib with defensive nil checks.
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for nil template/parent")
			}
		}()
		_, _ = CreateCertificate(random, nil, nil, sm2Priv.PublicKey, sm2Priv)
	}()
}
