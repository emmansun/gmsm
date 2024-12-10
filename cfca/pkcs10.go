// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto/x509"
	"io"

	"github.com/emmansun/gmsm/smx509"
)

// CreateCertificateRequest creates a new certificate request based on a template.
// The following members of template are used: Subject.
// The certPriv is the private key for the certificate, and the tmpPriv is the temporary private key for returning encryption key decryption.
// The challenge password is basically a shared-secret nonce between you and CFCA, embedded in the CSR.
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, certPriv, tmpPriv any, challengePassword string) ([]byte, error) {
	return smx509.CreateCFCACertificateRequest(rand, template, certPriv, tmpPriv, challengePassword)
}
