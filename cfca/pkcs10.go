// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cfca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type CertificateRequest = smx509.CertificateRequestCFCA

// CreateCertificateRequest creates a new certificate request based on a template.
// The following members of template are used: Subject.
// The certPriv is the private key for the certificate, and the tmpPub is the temporary public key for returning encryption key decryption.
// The challenge password is basically a shared-secret nonce between you and CFCA, embedded in the CSR.
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, certPriv, tmpPub any, challengePassword string) ([]byte, error) {
	return smx509.CreateCFCACertificateRequest(rand, template, certPriv, tmpPub, challengePassword)
}

// ParseCertificateRequest parses a certificate request from the given DER data.
// This method corresponds to CFCA SADK's cfca.sadk.asn1.pkcs.PKCS10.load.
func ParseCertificateRequest(der []byte) (*CertificateRequest, error) {
	return smx509.ParseCFCACertificateRequest(der)
}

const encryptedEncKeyPrefix = "0000000000000001000000000000000100000000000000000000000000000000"

type encryptedPrivateKeyInfo struct {
	Version      int `asn1:"default:1"`
	EncryptedKey []byte
}

// ParseEscrowPrivateKey parses an CFCA generated and returned SM2 private key from the given data.
// The data is expected to be in the format of "0000000000000001000000000000000100000000000000000000000000000000...".
// If the data is not in this format, it will be treated as base64 encoded data directly.
func ParseEscrowPrivateKey(tmpPriv *sm2.PrivateKey, data []byte) (*sm2.PrivateKey, error) {
	if len(data) < 268 {
		return nil, errors.New("cfca: invalid encrypted private key data")
	}
	encodedKeyPart := data
	if bytes.HasPrefix(data, []byte(encryptedEncKeyPrefix)) {
		retLen, err := strconv.Atoi(string(data[64:80]))
		if err != nil {
			return nil, err
		}
		if retLen != len(data[80:]) {
			return nil, errors.New("cfca: invalid encrypted private key data")
		}
		encodedKeyPart = data[80:]
	}
	// remove all commas ONLY now. If there are other non-base64 characters, the base64 decoder will fail.
	encodedKeyPart = bytes.ReplaceAll(encodedKeyPart, []byte{44}, []byte{})
	der, err := base64.StdEncoding.DecodeString(string(encodedKeyPart))
	if err != nil {
		return nil, err
	}
	var keyInfo encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &keyInfo); err != nil {
		return nil, err
	}
	var ret []byte
	if ret, err = tmpPriv.Decrypt(nil, append([]byte{0x04}, keyInfo.EncryptedKey...), nil); err != nil {
		return nil, errors.New("cfca: failed to decrypt the private key, possibly due to incorrect key data")
	}
	// X || Y || D
	if len(ret) != 96 {
		return nil, errors.New("cfca: invalid decrypted private key data")
	}
	var priv *sm2.PrivateKey
	if priv, err = sm2.NewPrivateKey(ret[64:]); err != nil {
		return nil, err
	}
	var pub *ecdsa.PublicKey
	if pub, err = sm2.NewPublicKey(append([]byte{0x04}, ret[:64]...)); err != nil {
		return nil, err
	}
	if !pub.Equal(&priv.PublicKey) {
		return nil, errors.New("cfca: key pair mismatch, possibly due to incorrect key data or corruption")
	}
	return priv, nil
}
