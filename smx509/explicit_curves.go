// Copyright 2026 The gmsm Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// parseExplicitECParameters parses explicit elliptic curve parameters as defined
// in RFC 3279 Section 2.3.5 and attempts to match them to known named curves.
func parseExplicitECParameters(params cryptobyte.String) (elliptic.Curve, error) {
	var version int
	if !params.ReadASN1Integer(&version) {
		return nil, errors.New("x509: failed to read EC parameters version")
	}
	if version != 1 {
		return nil, errors.New("x509: unsupported EC parameters version")
	}

	var fieldID cryptobyte.String
	if !params.ReadASN1(&fieldID, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid fieldID in EC parameters")
	}

	var fieldType asn1.ObjectIdentifier
	if !fieldID.ReadASN1ObjectIdentifier(&fieldType) {
		return nil, errors.New("x509: invalid fieldType OID")
	}
	if !fieldType.Equal(oidPrimeField) {
		return nil, errors.New("x509: unsupported field type OID")
	}

	p := new(big.Int)
	if !fieldID.ReadASN1Integer(p) {
		return nil, errors.New("x509: failed to read prime field modulus")
	}

	var curveSeq cryptobyte.String
	if !params.ReadASN1(&curveSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("x509: invalid curve sequence")
	}

	var aBytes, bBytes cryptobyte.String
	if !curveSeq.ReadASN1(&aBytes, cryptobyte_asn1.OCTET_STRING) ||
		!curveSeq.ReadASN1(&bBytes, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("x509: invalid curve coefficients")
	}
	_ = aBytes
	_ = bBytes

	var basePoint cryptobyte.String
	if !params.ReadASN1(&basePoint, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("x509: invalid base point")
	}
	_ = basePoint

	order := new(big.Int)
	if !params.ReadASN1Integer(order) {
		return nil, errors.New("x509: invalid curve order")
	}

	return matchKnownCurve(p, order)
}

func matchKnownCurve(p, n *big.Int) (elliptic.Curve, error) {
	p256 := elliptic.P256().Params()
	if p.Cmp(p256.P) == 0 && n.Cmp(p256.N) == 0 {
		return elliptic.P256(), nil
	}

	p384 := elliptic.P384().Params()
	if p.Cmp(p384.P) == 0 && n.Cmp(p384.N) == 0 {
		return elliptic.P384(), nil
	}

	p521 := elliptic.P521().Params()
	if p.Cmp(p521.P) == 0 && n.Cmp(p521.N) == 0 {
		return elliptic.P521(), nil
	}

	sm2Params := sm2.P256().Params()
	if p.Cmp(sm2Params.P) == 0 && n.Cmp(sm2Params.N) == 0 {
		return sm2.P256(), nil
	}

	return nil, errors.New("x509: explicit curve parameters do not match any known curve")
}

var oidPrimeField = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
