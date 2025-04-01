// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/sm2"
)

func TestCreateCFCACertificateRequest(t *testing.T) {
	random := rand.Reader
	certKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	certRSAKey, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), random)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "certRequisition",
			Organization: []string{"CFCA TEST CA"},
			Country:      []string{"CN"},
		},
	}

	testCases := []struct {
		template          *x509.CertificateRequest
		priv              interface{}
		tmpPub            interface{}
		challengePassword string
		wantErr           bool
		errormsg          string
	}{
		{
			template:          template,
			priv:              certKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "111111",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              certRSAKey,
			tmpPub:            rsaKey.Public(),
			challengePassword: "111111",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              p256Key,
			tmpPub:            nil,
			challengePassword: "",
			wantErr:           false,
			errormsg:          "",
		},
		{
			template:          template,
			priv:              "",
			tmpPub:            "",
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: certificate private key does not implement crypto.Signer",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            "",
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            rsaKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              certRSAKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: RSA temp public key is required",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            p256Key.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: SM2 temp public key is required",
		},
		{
			template:          template,
			priv:              p256Key,
			tmpPub:            certKey.Public(),
			challengePassword: "111111",
			wantErr:           true,
			errormsg:          "x509: only RSA or SM2 key is supported",
		},
		{
			template:          template,
			priv:              certKey,
			tmpPub:            tmpKey.Public(),
			challengePassword: "",
			wantErr:           true,
			errormsg:          "x509: challenge password is required",
		},
	}
	for _, tc := range testCases {
		_, err := CreateCFCACertificateRequest(random, tc.template, tc.priv, tc.tmpPub, tc.challengePassword)
		if tc.wantErr {
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if err.Error() != tc.errormsg {
				t.Fatalf("expected error %s, got %s", tc.errormsg, err.Error())
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

var sadkGeneratedCSR = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBtDCCAVgCAQAwPjEYMBYGA1UEAwwPY2VydFJlcXVpc2l0aW9uMRUwEwYDVQQK
DAxDRkNBIFRFU1QgQ0ExCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UB
gi0DQgAEBtbaBT0KiK9mSUPnTOVCMydUWbSr0DkHi6i3GAuE0d1+/7ROMhVvWpz6
OFP4T6CeZggKwvxwrCL/rj3vR/R6rqCBtzATBgkqhkiG9w0BCQcTBjExMTExMTCB
nwYJKoZIhvcNAQk/BIGRMIGOAgEBBIGIALQAAAABAAAouT7CmwV94vbCwPIwBag6
SSoEh+WxOcV6Sp5xjVSdIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
e0nExPMojCs0CdTvzhh7kakxQBQF6mLFeUGJ9IjIH4IAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAADAMBggqgRzPVQGDdQUAA0gAMEUCIFtu6pSUf8yOxgqo
fpFA45HniI2StqJomsjYqIMH6jEYAiEAuLl7Q42zA8sR7U5nOza88ehpqV0TdzZq
XAZJg0bKNMY=
-----END CERTIFICATE REQUEST-----
`

func TestSADKGeneratedCSR(t *testing.T) {
	block, _ := pem.Decode([]byte(sadkGeneratedCSR))
	csr, err := ParseCFCACertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "111111" {
		t.Fatal("challenge password not match")
	}
	if pub, ok := csr.TmpPublicKey.(*ecdsa.PublicKey); !ok || pub.X == nil {
		t.Fatal("tmp public key is nil")
	}

	block, _ = pem.Decode([]byte(rsaSignedCSR))
	csr, err = ParseCFCACertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "111111" {
		t.Fatal("challenge password not match")
	}
	if pub, ok := csr.TmpPublicKey.(*rsa.PublicKey); !ok || pub.N == nil {
		t.Fatal("tmp public key is nil")
	}
}

// https://myssl.com/csr_create.html
// challenge password is empty
var trustAsiaCSR = `
-----BEGIN CERTIFICATE REQUEST-----
MIIB3DCCAYECAQAwRjELMAkGA1UEBhMCQ04xDzANBgNVBAgTBlpodWhhaTESMBAG
A1UEBxMJR3Vhbmdkb25nMRIwEAYDVQQDEwlURVNUIENFUlQwWTATBgcqhkjOPQIB
BggqgRzPVQGCLQNCAARGJcrt6CdYj+keIe3dVUfgFUY4rB9otZg4rneLhtkJbnhX
/NOH7lBYOifxCUpS77WlAmHqZ4X3IxWcq6QCsMpYoIHYMA0GCSqGSIb3DQEJBxMA
MIGfBgkqhkiG9w0BCT8EgZEwgY4CAQEEgYgAtAAAAAEAAJLVPiiG5UmFz2/ZPjgE
E/88SRe2O24QzIC9hpIVDYHyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AACAIx+hRlrU3htrIPZQOxeIyizbX8Y1ZoUQ6sF6l/byRQAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJ
VEVTVCBDRVJUMAwGCCqBHM9VAYN1BQADRwAwRAIgdAK3Jgs47/ATROPmvh06F0DG
8+esUW+7jahyNvKhLRYCIGKjS7FIYI2qG4scPsHZ+qyBNRIfUP7w8c/PQSaXmzqD
-----END CERTIFICATE REQUEST-----
`

func TestTrustAsiaGeneratedCSR(t *testing.T) {
	block, _ := pem.Decode([]byte(trustAsiaCSR))
	csr, err := ParseCFCACertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "TEST CERT" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "" {
		t.Fatal("challenge password not match")
	}
	if pub, ok := csr.TmpPublicKey.(*ecdsa.PublicKey); !ok || pub.X == nil {
		t.Fatal("tmp public key is nil")
	}
}

var rsaSignedCSR = `
-----BEGIN CERTIFICATE REQUEST-----
MIIDxjCCAq4CAQAwPjEYMBYGA1UEAwwPY2VydFJlcXVpc2l0aW9uMRUwEwYDVQQK
DAxDRkNBIFRFU1QgQ0ExCzAJBgNVBAYTAkNOMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAzKukdxeh3wJXNtwbYEnfFnYXHSCTOP4/CO1C5vU+OMNx9yML
WEBrPZ4UufaM6l0xKRiWKLvwgjrkSb8tz3V/6ff8cDrKx4OzZZWs2xuUH4vL3Wrt
Pi6D2Mb0PBRwImSg4rxoQHoR+CQb+wfXsGwE5GaFhfStoNX1pWapGDM0+cpbIozN
4zG6b7sRuvCOIl/32p69Dl7eZ8AgCHV9pLLqB7wAHTKHatIs46XKaCDeVXTO6oDt
hi8yUShjLh94h8ILm8a/zSXT1q8lBXOPm9sRkwUMr5zPjnt+UpmfMsTQAP8DW3GF
PLaCiEUpK/muGy4ndMzsokrnRn+3cQFSewIyLQIDAQABoIIBQTATBgkqhkiG9w0B
CQcTBjExMTExMTCCASgGCSqGSIb3DQEJPwSCARkwggEVAgEBBIIBDjCCAQoCggEB
AJjSdzS6Y2tSaisHfgnLMDhugWZly7ros/Le8jKKI+tJKzjR4iHMD/B+kvdn8rCL
eaRu8Zqhr2vYqhNNs5NaGfoiSBx+yONWJrtTLFCo4uSD/BASAMtXYSHPh5nVb3vk
ssWqKVcMHfHy6IqSIahxi1tqyhWikaB86VFQyOpt6mCdg0W9cJvGNhjX5bbsMKHg
qbnrHpUQ1fgHqsBqeBxvPhUxcX89PeeBYH+x1Uz5m8pd1wnzSGJeIE+YyPRnQpRX
cBy2my6WLgGjO157raQZX8Kz0HfuIJekQUWTuB33J7RMvgY7neHKvlJher9zFEoA
Rfjt+krxvdLReRhTx7DghPsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAHzJVPBHc
WoThQICR9TbX4+UBS1ToVsl9GedMRSiE373PqoWygax3bPoy1M3ySDBwj5zfyThb
KiWf972CDkKVDeUZq++oTlEr4+BVmOzWQXlbTfuUdpLx14ygFyg7wpAViBF4aR+y
LFKfGhdBvkaU/yFYn3bGjgpc0m+Wecl5XWSTOK1zj3jf0ZVr9e8lsTcvLI7Clq9T
7Wh6UhRoPGgZ5+giRqATkSA61UlhKwk2qdbg7RTUSy/OVQuT2v4TKoE5ArBHo15z
7FVX3QQDEP65oJ7WS7c+L9Pkcj+n271uwlsZUzzHAJSEZkdWZIunDRqB/KzCLoBD
zwV8qP5llIORug==
-----END CERTIFICATE REQUEST-----
`