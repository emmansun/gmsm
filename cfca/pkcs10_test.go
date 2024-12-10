// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestCreateCertificateRequest(t *testing.T) {
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
	_, err = smx509.CreateCFCACertificateRequest(random, template, "", "", "")
	if err == nil || err.Error() != "x509: certificate private key does not implement crypto.Signer" {
		t.Fatal("certificate private key does not implement crypto.Signer")
	}
	_, err = smx509.CreateCFCACertificateRequest(random, template, certKey, "", "")
	if err == nil || err.Error() != "x509: tmp private key does not implement crypto.Signer" {
		t.Fatal("tmp private key does not implement crypto.Signer")
	}
	_, err = smx509.CreateCFCACertificateRequest(random, template, certKey, invalidTmpKey, "")
	if err == nil || err.Error() != "x509: only SM2 public key is supported" {
		t.Fatal("only SM2 public key is supported")
	}
	_, err = smx509.CreateCFCACertificateRequest(random, template, certKey, tmpKey, "")
	if err == nil || err.Error() != "x509: challenge password is required" {
		t.Fatal("challenge password is required")
	}
	csrDer, err := smx509.CreateCFCACertificateRequest(random, template, certKey, tmpKey, "111111")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := smx509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "certRequisition" {
		t.Fatal("common name not match")
	}
}
