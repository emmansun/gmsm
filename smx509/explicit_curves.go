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
//
// ECParameters ::= SEQUENCE {
//     version         INTEGER { ecpVer1(1) },
//     fieldID         FieldID,
//     curve           Curve,
//     base            OCTET STRING,
//     order           INTEGER,
//     cofactor        INTEGER OPTIONAL
// }
//
// This function provides fallback support for legacy certificates that use
// explicit curve encoding instead of named curve OIDs (RFC 5480).
func parseExplicitECParameters(params cryptobyte.String) (elliptic.Curve, error) {
	// 1. Read version (must be 1 for ecpVer1)
	var version int
	if !params.ReadASN1Integer(&version) {
		return nil, errors.New("smx509: failed to read EC parameters version")
	}
	if version != 1 {
		return nil, errors.New("smx509: unsupported EC parameters version")
	}

	// 2. Read fieldID SEQUENCE
	var fieldID cryptobyte.String
	if !params.ReadASN1(&fieldID, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("smx509: invalid fieldID in EC parameters")
	}

	// Read fieldType OID (should be prime-field: 1.2.840.10045.1.1)
	var fieldType asn1.ObjectIdentifier
	if !fieldID.ReadASN1ObjectIdentifier(&fieldType) {
		return nil, errors.New("smx509: invalid fieldType OID")
	}
	if !fieldType.Equal(oidPrimeField) {
		return nil, errors.New("smx509: unsupported field type OID")
	}

	// Read prime p (field modulus)
	p := new(big.Int)
	if !fieldID.ReadASN1Integer(p) {
		return nil, errors.New("smx509: failed to read prime field modulus")
	}

	// 3. Read curve SEQUENCE (contains a, b coefficients)
	var curveSeq cryptobyte.String
	if !params.ReadASN1(&curveSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("smx509: invalid curve sequence")
	}

	var aBytes, bBytes cryptobyte.String
	if !curveSeq.ReadASN1(&aBytes, cryptobyte_asn1.OCTET_STRING) ||
		!curveSeq.ReadASN1(&bBytes, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("smx509: invalid curve coefficients")
	}

	// Optional: skip curve seed (BIT STRING) if present
	// We don't need the seed for curve matching
	// curveSeq.ReadOptionalASN1BitString(...)

	// 4. Read base point G (OCTET STRING)
	var basePoint cryptobyte.String
	if !params.ReadASN1(&basePoint, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("smx509: invalid base point")
	}

	// 5. Read order n
	order := new(big.Int)
	if !params.ReadASN1Integer(order) {
		return nil, errors.New("smx509: invalid curve order")
	}

	// 6. Optional: read cofactor h
	// Usually not needed for curve identification
	// var cofactor *big.Int
	// params.ReadASN1Integer(&cofactor)

	// 7. Match to known curves by comparing p and n
	return matchKnownCurve(p, order)
}

// matchKnownCurve attempts to match explicit curve parameters to a known named curve
// by comparing the prime modulus (p) and order (n).
//
// This is necessary because Go's elliptic.Curve interface does not support
// dynamically creating curves from arbitrary parameters. We can only use
// predefined standard curves.
func matchKnownCurve(p, n *big.Int) (elliptic.Curve, error) {
	// Check NIST P-256 (secp256r1)
	p256 := elliptic.P256().Params()
	if p.Cmp(p256.P) == 0 && n.Cmp(p256.N) == 0 {
		return elliptic.P256(), nil
	}

	// Check NIST P-384 (secp384r1)
	p384 := elliptic.P384().Params()
	if p.Cmp(p384.P) == 0 && n.Cmp(p384.N) == 0 {
		return elliptic.P384(), nil
	}

	// Check NIST P-521 (secp521r1)
	p521 := elliptic.P521().Params()
	if p.Cmp(p521.P) == 0 && n.Cmp(p521.N) == 0 {
		return elliptic.P521(), nil
	}

	// Check SM2 P-256 (Chinese national standard)
	sm2Params := sm2.P256().Params()
	if p.Cmp(sm2Params.P) == 0 && n.Cmp(sm2Params.N) == 0 {
		return sm2.P256(), nil
	}

	// No known curve matched the explicit parameters
	return nil, errors.New("smx509: explicit curve parameters do not match any known curve")
}

var oidPrimeField = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}