// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/emmansun/gmsm/shake"
	"github.com/emmansun/gmsm/sm3"
)

var (
	// Digest Algorithms
	OIDDigestAlgorithmSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA512   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA3_256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDDigestAlgorithmSHA3_384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDDigestAlgorithmSHA3_512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
	OIDDigestAlgorithmSHAKE128 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 11}
	OIDDigestAlgorithmSHAKE256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 12}
	OIDDigestAlgorithmSM3      = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
)

var ErrUnsupportedDigestAlgorithm = errors.New("mldsa: unsupported digest algorithm")

func getHashByOID(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(OIDDigestAlgorithmSHA256):
		return sha256.New(), nil
	case oid.Equal(OIDDigestAlgorithmSHA512):
		return sha512.New(), nil
	case oid.Equal(OIDDigestAlgorithmSHA3_256):
		return sha3.New256(), nil
	case oid.Equal(OIDDigestAlgorithmSHA3_384):
		return sha3.New384(), nil
	case oid.Equal(OIDDigestAlgorithmSHA3_512):
		return sha3.New512(), nil
	case oid.Equal(OIDDigestAlgorithmSHAKE128):
		return shake.NewSHAKE128(32), nil
	case oid.Equal(OIDDigestAlgorithmSHAKE256):
		return shake.NewSHAKE256(64), nil
	case oid.Equal(OIDDigestAlgorithmSM3):
		return sm3.New(), nil
	default:
		return nil, ErrUnsupportedDigestAlgorithm
	}
}

func preHash(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	h, err := getHashByOID(oid)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	oidBytes, _ := asn1.Marshal(oid)
	return h.Sum(oidBytes), nil
}

type Options struct {
	Context    []byte
	PrehashOID asn1.ObjectIdentifier
}

func (opts *Options) HashFunc() crypto.Hash {
	return crypto.Hash(0)
}
