// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto"

	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
)

func signMessage(data []byte, cert *smx509.Certificate, key crypto.PrivateKey, detached bool) ([]byte, error) {
	signData, _ := pkcs7.NewSMSignedData(data)
	if err := signData.SignWithoutAttr(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	if detached {
		signData.Detach()
	}
	return signData.Finish()
}

// SignMessageAttach signs the data with the certificate and private key, returns the signed data in PKCS7 (DER) format.
// This method corresponds to CFCA SADK's cfca.sadk.util.p7SignMessageAttach.
func SignMessageAttach(data []byte, cert *smx509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	return signMessage(data, cert, key, false)
}

// VerifyMessageAttach verifies the signed data in PKCS7 (DER) format.
// This method corresponds to CFCA SADK's cfca.sadk.util.p7VerifyMessageAttach.
// If verification fails, an error is returned. otherwise, nil is returned.
func VerifyMessageAttach(p7Der []byte) error {
	p7, err := pkcs7.Parse(p7Der)
	if err != nil {
		return err
	}
	return p7.Verify()
}

// SignMessageDetach signs the data with the certificate and private key, returns the signed data in PKCS7 (DER) format.
// This method corresponds to CFCA SADK's cfca.sadk.util.p7SignMessageDetach.
func SignMessageDetach(data []byte, cert *smx509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	return signMessage(data, cert, key, true)
}

// VerifyMessageDetach verifies the signed data in PKCS7 (DER) format with the given source data.
// This method corresponds to CFCA SADK's cfca.sadk.util.p7VerifyMessageDetach.
// If verification fails, an error is returned. otherwise, nil is returned.
func VerifyMessageDetach(p7Der, sourceData []byte) error {
	p7, err := pkcs7.Parse(p7Der)
	if err != nil {
		return err
	}
	p7.Content = sourceData
	return p7.Verify()
}

// SignDigestDetach signs a given digest using the provided certificate and private key,
// and returns the detached PKCS7 signature.
//
// This method corresponds to CFCA SADK's cfca.sadk.util.p7SignByHash.
func SignDigestDetach(digest []byte, cert *smx509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	signData, _ := pkcs7.NewSMSignedDataWithDigest(digest)
	if err := signData.SignWithoutAttr(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}
	return signData.Finish()
}

// VerifyDigestDetach verifies a detached PKCS7 signature against a given digest.
// It parses the p7Der, assigns the provided digest to the parsed PKCS7 content, and then verifies it.
//
// This method corresponds to CFCA SADK's cfca.sadk.util.p7VerifyByHash.
func VerifyDigestDetach(p7Der, digest []byte) error {
	p7, err := pkcs7.Parse(p7Der)
	if err != nil {
		return err
	}
	p7.Content = digest
	return p7.VerifyAsDigest()
}
