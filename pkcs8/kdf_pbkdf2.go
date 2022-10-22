package pkcs8

//
// Reference https://datatracker.ietf.org/doc/html/rfc8018#section-5.2
//

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/pbkdf2"
)

// http://gmssl.org/docs/oid.html
var (
	oidPKCS5PBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidHMACWithSHA512_224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 12}
	oidHMACWithSHA512_256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 13}
	oidHMACWithSM3        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401, 2}
)

func init() {
	RegisterKDF(oidPKCS5PBKDF2, func() KDFParameters {
		return new(pbkdf2Params)
	})
}

func newHashFromPRF(ai pkix.AlgorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case len(ai.Algorithm) == 0 || ai.Algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA224):
		return sha256.New224, nil
	case ai.Algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512_224):
		return sha512.New512_224, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512_256):
		return sha512.New512_256, nil
	case ai.Algorithm.Equal(oidHMACWithSM3):
		return sm3.New, nil
	default:
		return nil, errors.New("pkcs8: unsupported hash function")
	}
}

func newPRFParamFromHash(h Hash) (pkix.AlgorithmIdentifier, error) {
	switch h {
	case SHA1:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA1,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA224:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA224,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA256:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA384:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA384,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA512:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA512,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA512_224:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA512_224,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SHA512_256:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSHA512_256,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil
	case SM3:
		return pkix.AlgorithmIdentifier{
			Algorithm:  oidHMACWithSM3,
			Parameters: asn1.RawValue{Tag: asn1.TagNull}}, nil

	}
	return pkix.AlgorithmIdentifier{}, errors.New("pkcs8: unsupported hash function")
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLen         int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

func (p pbkdf2Params) DeriveKey(password []byte, size int) (key []byte, err error) {
	h, err := newHashFromPRF(p.PRF)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(password, p.Salt, p.IterationCount, size, h), nil
}

// PBKDF2Opts contains options for the PBKDF2 key derivation function.
type PBKDF2Opts struct {
	SaltSize       int
	IterationCount int
	HMACHash       Hash
}

func (p PBKDF2Opts) DeriveKey(password, salt []byte, size int) (
	key []byte, params KDFParameters, err error) {

	key = pbkdf2.Key(password, salt, p.IterationCount, size, p.HMACHash.New)
	prfParam, err := newPRFParamFromHash(p.HMACHash)
	if err != nil {
		return nil, nil, err
	}
	params = pbkdf2Params{salt, p.IterationCount, size, prfParam}
	return key, params, nil
}

func (p PBKDF2Opts) GetSaltSize() int {
	return p.SaltSize
}

func (p PBKDF2Opts) OID() asn1.ObjectIdentifier {
	return oidPKCS5PBKDF2
}
