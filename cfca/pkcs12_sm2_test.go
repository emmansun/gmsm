package cfca

import (
	"encoding/pem"
	"errors"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

var v2exKeyPem = `-----BEGIN CFCA KEY-----
MIIDSQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDkLvKllj9ZWhaKU6MSnxBBV5yaF3tEcOk1
vQniWyVzyaQA4F3j/YvDJwEoE8gOF/swggL5BgoqgRzPVQYBBAIBBIIC6TCCAuUwggKJoAMCAQIC
BRBAmQgJMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu
Y2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex
MB4XDTIwMTExOTA4MzExOFoXDTI1MTExOTA4MzExOFowgYkxCzAJBgNVBAYTAkNOMRcwFQYDVQQK
DA5DRkNBIFRFU1QgT0NBMTENMAsGA1UECwwEUFNCQzEZMBcGA1UECwwQT3JnYW5pemF0aW9uYWwt
MjE3MDUGA1UEAwwuMDUxQOmCruWCqOe6v+S4iuaUtuWNleWVhuaIt0BONTEwMTEzMDAwMTg4NzhA
MTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABJVRC63OKfcL4H324rDOdb4SSlbAjoJDXnK0qmwX
Z59FWmiSqt3ipreljKew4QynjTgR/yfp9yjNgNU8G5pkYdujggEGMIIBAjAfBgNVHSMEGDAWgBRr
/hjaj0I6prhtsy6Igzo0osEw4TAMBgNVHRMBAf8EAjAAMEgGA1UdIARBMD8wPQYIYIEchu8qAQEw
MTAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZmNhLmNvbS5jbi91cy91cy0xNC5odG0wOQYDVR0f
BDIwMDAuoCygKoYoaHR0cDovL3VjcmwuY2ZjYS5jb20uY24vU00yL2NybDE0MzU2LmNybDAOBgNV
HQ8BAf8EBAMCBsAwHQYDVR0OBBYEFPiGPZT0oTuRXvkyGoOgviNEWnc1MB0GA1UdJQQWMBQGCCsG
AQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQCJDSsVPfhr+gnDASMj5Syt+hxs
amHygPecjCLbcdFQQgIgSXC4musF5Fnj/CpNTqvk9+56FuINkATGS8xRh7kzKBE=
-----END CFCA KEY-----
`

var cfcasm2oca1 = `-----BEGIN CERTIFICATE-----
MIICTTCCAfKgAwIBAgIKZCTXgL0MKPOtBzAMBggqgRzPVQGDdQUAMF0xCzAJBgNV
BAYTAkNOMTAwLgYDVQQKDCdDaGluYSBGaW5hbmNpYWwgQ2VydGlmaWNhdGlvbiBB
dXRob3JpdHkxHDAaBgNVBAMME0NGQ0EgVEVTVCBDUyBTTTIgQ0EwHhcNMTIxMjI1
MTIyNTA2WhcNMzIwNzIzMTIyNTA2WjBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwn
Q2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQD
DBJDRkNBIFRFU1QgU00yIE9DQTEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQz
uFgJbedY55u6NToJElGWzPT+9UF1dxcopnerNO3fqRd4C1lDzz9LJZSfmMyNYaky
YC+6zh9G6/aPXW1Od/RFo4GYMIGVMB8GA1UdIwQYMBaAFLXYkG9c8Ngz0mO9frLD
jcZPEnphMAwGA1UdEwQFMAMBAf8wOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovLzIx
MC43NC40Mi4zL3Rlc3RyY2EvU00yL2NybDEuY3JsMAsGA1UdDwQEAwIBBjAdBgNV
HQ4EFgQUa/4Y2o9COqa4bbMuiIM6NKLBMOEwDAYIKoEcz1UBg3UFAANHADBEAiAR
kDmkQ0Clio48994IUs63nA8k652O2C4+7EQs1SSbuAIgcwNUrHJyEYX8xT5BKl9T
lJOefzCNNJW5Z0f3Y/SjaG0=
-----END CERTIFICATE-----
`

func parseTestKeyAndCert() (*sm2.PrivateKey, *smx509.Certificate, error) {
	password := []byte("123456")
	var block *pem.Block
	block, rest := pem.Decode([]byte(v2exKeyPem))
	if len(rest) != 0 {
		return nil, nil, errors.New("unexpected remaining PEM block during decode")
	}
	return ParseSM2(password, block.Bytes)
}

func TestParseSM2(t *testing.T) {
	_, _, err := parseTestKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalSM2(t *testing.T) {
	password := []byte("changeit")
	priv, cert, err := parseTestKeyAndCert()
	if err != nil {
		t.Fatal(err)
	}
	rootca1, err := smx509.ParseCertificatePEM([]byte(cfcasm2oca1))
	if err != nil {
		t.Fatal(err)
	}
	err = rootca1.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatal(err)
	}
	result, err := MarshalSM2(password, priv, cert)
	if err != nil {
		t.Fatal(err)
	}

	priv1, cert1, err := ParseSM2(password, result)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(priv1) {
		t.Fatal("not same private key")
	}
	if !cert.Equal(cert1) {
		t.Fatal("not same certficate")
	}
}
