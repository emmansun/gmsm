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
	"encoding/base64"
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
		t.Fatal("certificate private key does not implement crypto.Signer")
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, "", "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatal("only SM2 public key is supported")
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, invalidTmpKey.Public(), "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatal("only SM2 public key is supported")
	}
	_, err = CreateCFCACertificateRequest(random, template, certKey, tmpKey.Public(), "")
	if err == nil || err.Error() != "x509: challenge password is required" {
		t.Fatal("challenge password is required")
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

var sadkGeneratedCSR = `MIIBtDCCAVgCAQAwPjEYMBYGA1UEAwwPY2VydFJlcXVpc2l0aW9uMRUwEwYDVQQKDAxDRkNBIFRFU1QgQ0ExCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBtbaBT0KiK9mSUPnTOVCMydUWbSr0DkHi6i3GAuE0d1+/7ROMhVvWpz6OFP4T6CeZggKwvxwrCL/rj3vR/R6rqCBtzATBgkqhkiG9w0BCQcTBjExMTExMTCBnwYJKoZIhvcNAQk/BIGRMIGOAgEBBIGIALQAAAABAAAouT7CmwV94vbCwPIwBag6SSoEh+WxOcV6Sp5xjVSdIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAe0nExPMojCs0CdTvzhh7kakxQBQF6mLFeUGJ9IjIH4IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAMBggqgRzPVQGDdQUAA0gAMEUCIFtu6pSUf8yOxgqofpFA45HniI2StqJomsjYqIMH6jEYAiEAuLl7Q42zA8sR7U5nOza88ehpqV0TdzZqXAZJg0bKNMY=`

func TestSADKGeneratedCSR(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString(sadkGeneratedCSR)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCFCACertificateRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
	if csr.ChallengePassword != "111111" {
		t.Fatal("challenge password not match")
	}
	if csr.TmpPublicKey == nil {
		t.Fatal("tmp public key is nil")
	}
}
