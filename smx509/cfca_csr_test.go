// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	tmpKey, err := sm2.GenerateKey(random)
	if err != nil {
		t.Fatal(err)
	}
	invalidTmpKey, err := ecdsa.GenerateKey(elliptic.P256(), random)
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
	_, err = CreateCFCACertificateRequest(random, template, "", "", "")
	if err == nil || err.Error() != "x509: certificate private key does not implement crypto.Signer" {
		t.Fatalf("expect certificate private key does not implement crypto.Signer, got %v", err)
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, "", "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatalf("expected only SM2 public key is supported, got %v", err)
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, invalidTmpKey.Public(), "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatalf("expect only SM2 public key is supported, got %v", err)
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, tmpKey.Public(), "")
	if err == nil || err.Error() != "x509: challenge password is required" {
		t.Fatalf("expect challenge password is required, got %v", err)
	}
	csrDer, err := CreateCFCACertificateRequest(random, template, certKey, tmpKey.Public(), "111111")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCFCACertificateRequest(csrDer)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "111111" {
		t.Fatal("challenge password not match")
	}
	if !tmpKey.PublicKey.Equal(csr.TmpPublicKey) {
		t.Fatal("tmp public key not match")
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
