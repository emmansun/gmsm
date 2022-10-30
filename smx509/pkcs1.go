package smx509

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
)

// pkcs1PrivateKey is a structure which mirrors the PKCS #1 ASN.1 for an RSA private key.
type pkcs1PrivateKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	// We ignore these values, if present, because rsa will calculate them.
	Dp   *big.Int `asn1:"optional"`
	Dq   *big.Int `asn1:"optional"`
	Qinv *big.Int `asn1:"optional"`

	AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
}

type pkcs1AdditionalRSAPrime struct {
	Prime *big.Int

	// We ignore these values because rsa will calculate them.
	Exp   *big.Int
	Coeff *big.Int
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS #1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// ParsePKCS1PrivateKey parses an RSA private key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(der)
}

// MarshalPKCS1PrivateKey converts an RSA private key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PRIVATE KEY".
// For a more flexible key format which is not RSA specific, use
// MarshalPKCS8PrivateKey.
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(key)
}

// ParsePKCS1PublicKey parses an RSA public key in PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(der)
}

// MarshalPKCS1PublicKey converts an RSA public key to PKCS #1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "RSA PUBLIC KEY".
func MarshalPKCS1PublicKey(key *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(key)
}
