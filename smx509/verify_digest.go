// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/emmansun/gmsm/sm2"
)

// CheckSignatureWithDigest verifies the signature of a certificate using the specified
// signature algorithm and pre-computed digest. It supports RSA, ECDSA, and SM2 public keys.
//
// This is a low-level API that performs no validity checks on the certificate.
func (c *Certificate) CheckSignatureWithDigest(algo SignatureAlgorithm, digest, signature []byte) (err error) {
	var hashType crypto.Hash
	var pubKeyAlgo PublicKeyAlgorithm

	publicKey := c.PublicKey

	isSM2 := (algo == SM2WithSM3)
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
			break
		}
	}

	switch hashType {
	case crypto.Hash(0):
		if !isSM2 {
			return ErrUnsupportedAlgorithm
		}
		if len(digest) != 32 { // SM3 hash size
			return errors.New("x509: inconsistent digest and signature algorithm")
		}
	case crypto.MD5:
		return InsecureAlgorithmError(algo)
	case crypto.SHA1:
		// SHA-1 signatures are only allowed for CRLs and CSRs.
		return InsecureAlgorithmError(algo)
	default:
		if !hashType.Available() {
			return ErrUnsupportedAlgorithm
		}
		if len(digest) != hashType.Size() {
			return errors.New("x509: inconsistent digest and signature algorithm")
		}
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, hashType, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
		}
	case *ecdsa.PublicKey:
		if pubKeyAlgo != ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if isSM2 {
			if !sm2.VerifyASN1(pub, digest, signature) {
				return errors.New("x509: SM2 verification failure")
			}
		} else if !ecdsa.VerifyASN1(pub, digest, signature) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}
