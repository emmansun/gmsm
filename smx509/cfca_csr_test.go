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
	if csr.TmpPublicKey == nil {
		t.Fatal("tmp public key not match")
	}
}
