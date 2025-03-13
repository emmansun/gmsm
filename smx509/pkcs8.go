package smx509

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/ecdh"
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
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, a *sm2.PrivateKey, a *sm9.SignMasterPrivateKey,
// a *sm9.SignPrivateKey, a *sm9.EncryptMasterPrivateKey, a *sm9.EncryptPrivateKey or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
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
		// convert *ecdsa.PrivateKey to *sm2.PrivateKey
		if ecKey.Curve == sm2.P256() {
			return new(sm2.PrivateKey).FromECPrivateKey(ecKey)
		}
		return ecKey, err

	default:
		// fallback to golang sdk
		return x509.ParsePKCS8PrivateKey(der)
	}
}

func parseSM9PrivateKey(privKey pkcs8) (key any, err error) {
	switch {
	case privKey.Algo.Algorithm.Equal(oidSM9Sign):
		key, err = sm9.UnmarshalSignPrivateKeyASN1(privKey.PrivateKey)
		return
	case privKey.Algo.Algorithm.Equal(oidSM9Enc):
		key, err = sm9.UnmarshalEncryptPrivateKeyASN1(privKey.PrivateKey)
		return
	default:
		bytes := privKey.Algo.Parameters.FullBytes
		detailOID := new(asn1.ObjectIdentifier)
		_, err = asn1.Unmarshal(bytes, detailOID)
		if err != nil {
			return
		}
		switch {
		case oidSM9Sign.Equal(*detailOID):
			key, err = sm9.UnmarshalSignMasterPrivateKeyASN1(privKey.PrivateKey)
			return
		case oidSM9Enc.Equal(*detailOID):
			key, err = sm9.UnmarshalEncryptMasterPrivateKeyASN1(privKey.PrivateKey)
			return
		}
		return nil, errors.New("not support yet")
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey, a *sm2.PrivateKey, a *ecdh.PrivateKey
// a *sm9.SignMasterPrivateKey, a *sm9.SignPrivateKey, a *sm9.EncryptMasterPrivateKey, a *sm9.EncryptPrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case *sm2.PrivateKey:
		return marshalPKCS8ECPrivateKey(&k.PrivateKey)
	case *ecdh.PrivateKey:
		return marshalPKCS8ECDHPrivateKey(k)
	case *sm9.SignPrivateKey:
		return marshalPKCS8SM9SignPrivateKey(k)
	case *sm9.EncryptPrivateKey:
		return marshalPKCS8SM9EncPrivateKey(k)
	case *sm9.SignMasterPrivateKey:
		return marshalPKCS8SM9SignMasterPrivateKey(k)
	case *sm9.EncryptMasterPrivateKey:
		return marshalPKCS8SM9EncMasterPrivateKey(k)
	}
	return x509.MarshalPKCS8PrivateKey(key)
}

type sm9PrivateKey struct {
	PrivateKey asn1.RawValue
	PublicKey  asn1.RawValue
}

func marshalPKCS8SM9SignPrivateKey(k *sm9.SignPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm:  oidSM9Sign,
		Parameters: asn1.NullRawValue,
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
	key.PublicKey.FullBytes = pubasn1

	if privKey.PrivateKey, err = asn1.Marshal(key); err != nil {
		return nil, errors.New("x509: failed to marshal sm9 sign private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}

func marshalPKCS8SM9EncPrivateKey(k *sm9.EncryptPrivateKey) ([]byte, error) {
	var privKey pkcs8
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm:  oidSM9Enc,
		Parameters: asn1.NullRawValue,
	}
	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.MasterPublic().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
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

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidSM9,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.Public().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
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

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidSM9,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

	key := sm9PrivateKey{}
	privans1, err := k.MarshalASN1()
	if err != nil {
		return nil, err
	}
	pubasn1, err := k.Public().MarshalASN1()
	if err != nil {
		return nil, err
	}
	key.PrivateKey.FullBytes = privans1
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

	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}

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
	privKey.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyECDSA,
		Parameters: asn1.RawValue{
			FullBytes: oidBytes,
		},
	}
	if privKey.PrivateKey, err = marshalECDHPrivateKey(k); err != nil {
		return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
	}
	return asn1.Marshal(privKey)
}
