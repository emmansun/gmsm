// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smx509

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	gmsmecdh "github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/mldsa"
	"github.com/emmansun/gmsm/slhdsa"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm9"
)

var (
	oidSM9     = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302}
	oidSM9Sign = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 1}
	oidSM9Enc  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 302, 3}
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *[rsa.PrivateKey], an *[ecdsa.PrivateKey], an [ed25519.PrivateKey] (not
// a pointer), or an *[ecdh.PrivateKey] (for X25519). More types might be supported
// in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
//
// Before Go 1.24, the CRT parameters of RSA keys were ignored and recomputed.
// To restore the old behavior, use the GODEBUG=x509rsacrt=0 environment variable.
func ParsePKCS8PrivateKey(der []byte) (key any, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		ecKey, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse SM2 private key embedded in PKCS#8: " + err.Error())
		}
		if ecKey.Curve != sm2.P256() {
			return nil, errors.New("x509: unsupported SM2 curve")
		}
		return new(sm2.PrivateKey).FromECPrivateKey(ecKey)

	case privKey.Algo.Algorithm.Equal(oidSM9), privKey.Algo.Algorithm.Equal(oidSM9Sign), privKey.Algo.Algorithm.Equal(oidSM9Enc):
		return parseSM9PrivateKey(privKey)

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		ecKey, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		if ecKey.Curve == sm2.P256() {
			return new(sm2.PrivateKey).FromECPrivateKey(ecKey)
		}
		return ecKey, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyX25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid X25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid X25519 private key: %v", err)
		}
		return ecdh.X25519().NewPrivateKey(curvePrivateKey)

	case privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA44), privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA65), privKey.Algo.Algorithm.Equal(oidPublicKeyMLDSA87):
		if len(privKey.Algo.Parameters.FullBytes) != 0 {
			return nil, errors.New("x509: MLDSA key encoded with illegal parameters")
		}
		return paseMLDSAPrivateKey(privKey)

	case isSLHDSAPublicKeyAlgorithm(getPublicKeyAlgorithmFromOID(privKey.Algo.Algorithm)):
		if len(privKey.Algo.Parameters.FullBytes) != 0 {
			return nil, errors.New("x509: SLH-DSA key encoded with illegal parameters")
		}
		return parseSLHDSAPrivateKey(privKey)

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *[rsa.PrivateKey],
// *[ecdsa.PrivateKey], [ed25519.PrivateKey] (not a pointer), and *[ecdh.PrivateKey].
// Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
//
// MarshalPKCS8PrivateKey runs [rsa.PrivateKey.Precompute] on RSA keys.
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		k.Precompute()
		if err := k.Validate(); err != nil {
			return nil, err
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *sm2.PrivateKey:
		return marshalPKCS8ECPrivateKey(&k.PrivateKey)

	case *ecdsa.PrivateKey:
		return marshalPKCS8ECPrivateKey(k)

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *ecdh.PrivateKey:
		if k.Curve() == ecdh.X25519() {
			privKey.Algo = pkix.AlgorithmIdentifier{
				Algorithm: oidPublicKeyX25519,
			}
			var err error
			if privKey.PrivateKey, err = asn1.Marshal(k.Bytes()); err != nil {
				return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
			}
		} else {
			return marshalPKCS8ECDHPrivateKey(k)
		}

	case *gmsmecdh.PrivateKey:
		return marshalPKCS8GMSMECDHPrivateKey(k)

	case *mldsa.Key44, *mldsa.Key65, *mldsa.Key87, *mldsa.PrivateKey44, *mldsa.PrivateKey65, *mldsa.PrivateKey87:
		return marshalPKCS8MLDSAPrivateKey(k)

	case *slhdsa.PrivateKey:
		return marshalPKCS8SLHDSAPrivateKey(k)

	case *sm9.SignPrivateKey:
		return marshalPKCS8SM9SignPrivateKey(k)
	case *sm9.EncryptPrivateKey:
		return marshalPKCS8SM9EncPrivateKey(k)
	case *sm9.SignMasterPrivateKey:
		return marshalPKCS8SM9SignMasterPrivateKey(k)
	case *sm9.EncryptMasterPrivateKey:
		return marshalPKCS8SM9EncMasterPrivateKey(k)

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}

func paseMLDSAPrivateKey(privKey pkcs8) (any, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(privKey.PrivateKey, &raw)
	if err != nil {
		return nil, errors.New("x509: failed to parse MLDSA private key: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after MLDSA private key")
	}

	oid := privKey.Algo.Algorithm
	if raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 {
		seed := raw.Bytes
		if len(seed) != 32 {
			return nil, errors.New("x509: invalid MLDSA seed size")
		}
		switch {
		case oid.Equal(oidPublicKeyMLDSA44):
			return mldsa.NewKey44(seed)
		case oid.Equal(oidPublicKeyMLDSA65):
			return mldsa.NewKey65(seed)
		case oid.Equal(oidPublicKeyMLDSA87):
			return mldsa.NewKey87(seed)
		default:
			return nil, errors.New("x509: unsupported MLDSA algorithm")
		}
	}

	if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagOctetString {
		expandedKey := raw.Bytes
		switch {
		case oid.Equal(oidPublicKeyMLDSA44):
			return mldsa.NewPrivateKey44(expandedKey)
		case oid.Equal(oidPublicKeyMLDSA65):
			return mldsa.NewPrivateKey65(expandedKey)
		case oid.Equal(oidPublicKeyMLDSA87):
			return mldsa.NewPrivateKey87(expandedKey)
		default:
			return nil, errors.New("x509: unsupported MLDSA algorithm")
		}
	}

	if raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence {
		var both struct {
			Seed        []byte
			ExpandedKey []byte
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &both); err != nil {
			return nil, errors.New("x509: failed to parse MLDSA both: " + err.Error())
		}

		var generatedKey any
		switch {
		case oid.Equal(oidPublicKeyMLDSA44):
			generatedKey, err = mldsa.NewKey44(both.Seed)
		case oid.Equal(oidPublicKeyMLDSA65):
			generatedKey, err = mldsa.NewKey65(both.Seed)
		case oid.Equal(oidPublicKeyMLDSA87):
			generatedKey, err = mldsa.NewKey87(both.Seed)
		default:
			return nil, errors.New("x509: unsupported MLDSA algorithm")
		}
		if err != nil {
			return nil, errors.New("x509: failed to generate key from seed: " + err.Error())
		}
		type bytesGetter interface{ Bytes() []byte }
		if !bytes.Equal(generatedKey.(bytesGetter).Bytes(), both.ExpandedKey) {
			return nil, errors.New("x509: MLDSA private key consistency check failed: seed and expandedKey are not consistent")
		}
		return generatedKey, nil
	}

	return nil, errors.New("x509: unknown MLDSA private key format")
}

func parseSLHDSAPrivateKey(privKey pkcs8) (any, error) {
	param, ok := slhdsa.GetParameterSetByOID(privKey.Algo.Algorithm)
	if !ok {
		return nil, errors.New("x509: unsupported SLH-DSA algorithm with OID: " + privKey.Algo.Algorithm.String())
	}
	return param.NewPrivateKey(privKey.PrivateKey)
}

func parseSM9PrivateKey(privKey pkcs8) (key any, err error) {
	switch {
	case privKey.Algo.Algorithm.Equal(oidSM9Sign):
		return sm9.UnmarshalSignPrivateKeyASN1(privKey.PrivateKey)
	case privKey.Algo.Algorithm.Equal(oidSM9Enc):
		return sm9.UnmarshalEncryptPrivateKeyASN1(privKey.PrivateKey)
	default:
		bytes := privKey.Algo.Parameters.FullBytes
		detailOID := new(asn1.ObjectIdentifier)
		if _, err = asn1.Unmarshal(bytes, detailOID); err != nil {
			return nil, err
		}
		switch {
		case oidSM9Sign.Equal(*detailOID):
			return sm9.UnmarshalSignMasterPrivateKeyASN1(privKey.PrivateKey)
		case oidSM9Enc.Equal(*detailOID):
			return sm9.UnmarshalEncryptMasterPrivateKeyASN1(privKey.PrivateKey)
		}
		return nil, errors.New("not support yet")
	}
}

type sm9PrivateKey struct {
	PrivateKey asn1.RawValue
	PublicKey  asn1.RawValue
}

func marshalPKCS8SLHDSAPrivateKey(k *slhdsa.PrivateKey) ([]byte, error) {
	var privKey pkcs8
	oid := k.OID()
	if len(oid) == 0 {
		return nil, errors.New("x509: unsupported SLH-DSA parameter set: " + k.ParameterSet())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oid}
	privKey.PrivateKey = k.Bytes()
	return asn1.Marshal(privKey)
}

func marshalPKCS8MLDSAPrivateKey(k any) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{}
	switch key := k.(type) {
	case *mldsa.PrivateKey44:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA44
		privKey.PrivateKey, _ = asn1.Marshal(key.Bytes())
	case *mldsa.PrivateKey65:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA65
		privKey.PrivateKey, _ = asn1.Marshal(key.Bytes())
	case *mldsa.PrivateKey87:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA87
		privKey.PrivateKey, _ = asn1.Marshal(key.Bytes())
	case *mldsa.Key44:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA44
		privKey.PrivateKey = append([]byte{0x80, 0x20}, key.Seed()...)
	case *mldsa.Key65:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA65
		privKey.PrivateKey = append([]byte{0x80, 0x20}, key.Seed()...)
	case *mldsa.Key87:
		privKey.Algo.Algorithm = oidPublicKeyMLDSA87
		privKey.PrivateKey = append([]byte{0x80, 0x20}, key.Seed()...)
	default:
		return nil, errors.New("x509: unsupported MLDSA private key type while marshaling to PKCS#8")
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9SignPrivateKey(k *sm9.SignPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidSM9Sign, Parameters: asn1.NullRawValue}
	key := sm9PrivateKey{}
	privasn1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privasn1
	key.PublicKey.FullBytes = pubasn1
	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 sign private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9EncPrivateKey(k *sm9.EncryptPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidSM9Enc, Parameters: asn1.NullRawValue}
	key := sm9PrivateKey{}
	privasn1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privasn1
	key.PublicKey.FullBytes = pubasn1
	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 encrypt private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9SignMasterPrivateKey(k *sm9.SignMasterPrivateKey) ([]byte, error) {
	var privKey pkcs8
	oidBytes, err := asn1.Marshal(oidSM9Sign)
	if err != nil {
		return nil, errors.New("x509: failed to marshal SM9 OID: " + err.Error())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidSM9, Parameters: asn1.RawValue{FullBytes: oidBytes}}
	key := sm9PrivateKey{}
	privasn1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.PublicKey().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privasn1
	key.PublicKey.FullBytes = pubasn1
	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 sign master private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9EncMasterPrivateKey(k *sm9.EncryptMasterPrivateKey) ([]byte, error) {
	var privKey pkcs8
	oidBytes, err := asn1.Marshal(oidSM9Enc)
	if err != nil {
		return nil, errors.New("x509: failed to marshal SM9 OID: " + err.Error())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidSM9, Parameters: asn1.RawValue{FullBytes: oidBytes}}
	key := sm9PrivateKey{}
	privasn1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.PublicKey().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privasn1
	key.PublicKey.FullBytes = pubasn1
	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 encrypt master private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8ECPrivateKey(k *ecdsa.PrivateKey) ([]byte, error) {
	var privKey pkcs8
	oid, ok := oidFromNamedCurve(k.Curve)
	if !ok {
		return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: oidBytes}}
	if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8ECDHPrivateKey(k *ecdh.PrivateKey) ([]byte, error) {
	var privKey pkcs8
	oid, ok := oidFromECDHCurve(k.Curve())
	if !ok {
		return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: oidBytes}}
	if privKey.PrivateKey, err = marshalECDHPrivateKey(k); err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8GMSMECDHPrivateKey(k *gmsmecdh.PrivateKey) ([]byte, error) {
	var privKey pkcs8
	oid, ok := oidFromGMSMECDHCurve(k.Curve())
	if !ok {
		return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
	}
	oidBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}
	privKey.Algo = pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: oidBytes}}
	if privKey.PrivateKey, err = asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: k.Bytes(),
		PublicKey:  asn1.BitString{Bytes: k.PublicKey().Bytes()},
	}); err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}
