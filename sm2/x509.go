package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

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

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

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
		return x509.ParsePKIXPublicKey(derBytes)
	}
	keyData := &pki
	asn1Data := keyData.PublicKey.RightAlign()
	paramsData := keyData.Algorithm.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
	if err != nil {
		return nil, errors.New("x509: failed to parse ECDSA parameters as named curve")
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ECDSA parameters")
	}
	if !namedCurveOID.Equal(oidNamedCurveP256SM2) {
		return x509.ParsePKIXPublicKey(derBytes)
	}
	namedCurve := P256()
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

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PublicKey, *ecdsa.PublicKey
// and ed25519.PublicKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	ecdPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecdPub.Curve != P256() {
		return x509.MarshalPKIXPublicKey(pub)
	}

	publicKeyAlgorithm := pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA}
	publicKeyBytes := elliptic.Marshal(ecdPub.Curve, ecdPub.X, ecdPub.Y)
	paramBytes, _ := asn1.Marshal(oidNamedCurveP256SM2)
	publicKeyAlgorithm.Parameters.FullBytes = paramBytes

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}
