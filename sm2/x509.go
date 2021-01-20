package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// http://gmssl.org/docs/oid.html
var (
	oidPublicKeyECDSA    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
//
// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or
// ed25519.PublicKey. More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (interface{}, error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		if _, err := asn1.Unmarshal(derBytes, &pkcs1PublicKey{}); err == nil {
			return nil, errors.New("x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)")
		}
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	if !pki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("x509: invalid public key algorithm")
	}
	keyData := &pki
	asn1Data := keyData.PublicKey.RightAlign()
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	namedCurve := P256()
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, errors.New("x509: failed to parse ECDSA parameters as named curve")
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ECDSA parameters")
	}
	if !namedCurveOID.Equal(oidNamedCurveP256SM2) {
		return nil, errors.New("x509: it's not SM2 elliptic curve")
	}
	x, y := elliptic.Unmarshal(namedCurve, asn1Data)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: namedCurve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
