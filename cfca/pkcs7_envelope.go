// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"crypto"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/pkcs7"
	"github.com/emmansun/gmsm/smx509"
)

// EnvelopeMessage creates and returns an envelope data PKCS7 structure (DER encoded) with encrypted
// recipient keys for each recipient public key.
//
// The OIDs use GM/T 0010 - 2012 set and the encrypted key uses ASN.1 format.
// This function uses recipient's SubjectKeyIdentifier to identify the recipient.
func EnvelopeMessage(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return pkcs7.EnvelopeMessageCFCA(cipher, content, recipients)
}

// OpenEnvelopedMessage decrypts the enveloped message (DER encoded) using the provided certificate and private key.
// The certificate is used to identify the recipient and the private key is used to decrypt the encrypted key.
func OpenEnvelopedMessage(data []byte, recipientCert *smx509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	return p7.Decrypt(recipientCert, key)
}

// EnvelopeMessageLegacy creates and returns an envelope data PKCS7 structure (DER encoded) with encrypted
// recipient keys for each recipient public key. This method is used for CFCA SADK verion less than 3.2 compatibility.
//
// The OIDs use GM/T 0010 - 2012 set and the encrypted key use C1C2C3 format and without 0x4 prefix.
// This function uses recipient's IssuerAndSerialNumber to identify the recipient.
func EnvelopeMessageLegacy(cipher pkcs.Cipher, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return pkcs7.EncryptCFCA(cipher, content, recipients)
}

// OpenEnvelopedMessageLegacy decrypts the enveloped message (DER encoded) using the provided certificate and private key.
// The certificate is used to identify the recipient and the private key is used to decrypt the encrypted key.
//
// This method is used for CFCA SADK verion less than 3.2 compatibility.
func OpenEnvelopedMessageLegacy(data []byte, recipientCert *smx509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	return p7.DecryptCFCA(recipientCert, key)
}
