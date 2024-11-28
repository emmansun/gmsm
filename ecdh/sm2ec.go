package ecdh

import (
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math/bits"

	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/randutil"
	sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/internal/subtle"
)

type sm2Curve struct {
	name              string
	newPoint          func() *sm2ec.SM2P256Point
	scalarOrder       []byte
	scalarOrderMinus1 []byte
	constantA         []byte
	constantB         []byte
	generator         []byte
}

func (c *sm2Curve) String() string {
	return c.name
}

func (c *sm2Curve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	key := make([]byte, len(c.scalarOrderMinus1))
	randutil.MaybeReadByte(rand)

	for {
		if _, err := io.ReadFull(rand, key); err != nil {
			return nil, err
		}

		// In tests, rand will return all zeros and NewPrivateKey will reject
		// the zero key as it generates the identity as a public key. This also
		// makes this function consistent with crypto/elliptic.GenerateKey.
		key[1] ^= 0x42

		k, err := c.NewPrivateKey(key)
		if err == errInvalidPrivateKey {
			continue
		}
		return k, err
	}
}

func (c *sm2Curve) NewPrivateKey(key []byte) (*PrivateKey, error) {
	return c.newPrivateKey(key, true)
}

func (c *sm2Curve) newPrivateKey(key []byte, checkOrderMinus1 bool) (*PrivateKey, error) {
	if len(key) != len(c.scalarOrder) {
		return nil, errors.New("ecdh: invalid private key size")
	}
	if subtle.ConstantTimeAllZero(key) == 1 || (checkOrderMinus1 && !isLess(key, c.scalarOrderMinus1)) {
		return nil, errInvalidPrivateKey
	}
	return &PrivateKey{
		curve:      c,
		privateKey: append([]byte{}, key...),
	}, nil
}

func (c *sm2Curve) privateKeyToPublicKey(key *PrivateKey) *PublicKey {
	if key.curve != c {
		panic("ecdh: internal error: converting the wrong key type")
	}
	p, err := c.newPoint().ScalarBaseMult(key.privateKey)
	if err != nil {
		// This is unreachable because the only error condition of
		// ScalarBaseMult is if the input is not the right size.
		panic("ecdh: internal error: sm2ec ScalarBaseMult failed for a fixed-size input")
	}
	publicKey := p.Bytes()
	if len(publicKey) == 1 {
		// The encoding of the identity is a single 0x00 byte. This is
		// unreachable because the only scalar that generates the identity is
		// zero, which is rejected by NewPrivateKey.
		panic("ecdh: internal error: sm2ec ScalarBaseMult returned the identity")
	}
	return &PublicKey{
		curve:     key.curve,
		publicKey: publicKey,
	}
}

// GenerateKeyFromScalar generates a private key from a scalar. The scalar will
// be reduced to the range [0, Order).
func (c *sm2Curve) GenerateKeyFromScalar(scalar []byte) (*PrivateKey, error) {
	if size := len(c.scalarOrder); len(scalar) > size {
		scalar = scalar[:size]
	}
	m, err := bigmod.NewModulus(c.scalarOrder)
	if err != nil {
		return nil, err
	}
	p, err := bigmod.NewNat().SetOverflowingBytes(scalar, m)
	if err != nil {
		return nil, err
	}
	return c.newPrivateKey(p.Bytes(m), false)
}

func (c *sm2Curve) NewPublicKey(key []byte) (*PublicKey, error) {
	// Reject the point at infinity and compressed encodings.
	if len(key) == 0 || key[0] != 4 {
		return nil, errors.New("ecdh: invalid public key")
	}
	// SetBytes also checks that the point is on the curve.
	if _, err := c.newPoint().SetBytes(key); err != nil {
		return nil, err
	}

	return &PublicKey{
		curve:     c,
		publicKey: append([]byte{}, key...),
	}, nil
}

func (c *sm2Curve) ecdh(local *PrivateKey, remote *PublicKey) ([]byte, error) {
	p, err := c.newPoint().SetBytes(remote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p.ScalarMult(p, local.privateKey); err != nil {
		return nil, err
	}
	// BytesX will return an error if p is the point at infinity.
	return p.BytesX()
}

func (c *sm2Curve) addPublicKeys(a, b *PublicKey) (*PublicKey, error) {
	p1, err := c.newPoint().SetBytes(a.publicKey)
	if err != nil {
		return nil, err
	}
	p2, err := c.newPoint().SetBytes(b.publicKey)
	if err != nil {
		return nil, err
	}
	p1.Add(p1, p2)
	return c.NewPublicKey(p1.Bytes())
}

func (c *sm2Curve) addPrivateKeys(a, b *PrivateKey) (*PrivateKey, error) {
	m, err := bigmod.NewModulus(c.scalarOrder)
	if err != nil {
		return nil, err
	}
	aNat, err := bigmod.NewNat().SetBytes(a.privateKey, m)
	if err != nil {
		return nil, err
	}
	bNat, err := bigmod.NewNat().SetBytes(b.privateKey, m)
	if err != nil {
		return nil, err
	}
	aNat = aNat.Add(bNat, m)
	return c.NewPrivateKey(aNat.Bytes(m))
}

func (c *sm2Curve) secretKey(local *PrivateKey, remote *PublicKey) ([]byte, error) {
	p, err := c.newPoint().SetBytes(remote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p.ScalarMult(p, local.privateKey); err != nil {
		return nil, err
	}
	return p.Bytes(), nil
}

func (c *sm2Curve) sm2avf(secret *PublicKey) []byte {
	bytes := secret.publicKey[1:33]
	var result [32]byte
	copy(result[16:], bytes[16:])
	result[16] = (result[16] & 0x7f) | 0x80

	return result[:]
}

func (c *sm2Curve) sm2mqv(sLocal, eLocal *PrivateKey, sRemote, eRemote *PublicKey) (*PublicKey, error) {
	// implicitSig: (sLocal + avf(eLocal.Pub) * ePriv) mod N
	x2 := c.sm2avf(eLocal.PublicKey())
	t, err := sm2ec.ImplicitSig(sLocal.privateKey, eLocal.privateKey, x2)
	if err != nil {
		return nil, err
	}

	// new base point: peerPub + [x1](peerSecret)
	x1 := c.sm2avf(eRemote)
	p2, err := c.newPoint().SetBytes(eRemote.publicKey)
	if err != nil {
		return nil, err
	}
	if _, err := p2.ScalarMult(p2, x1); err != nil {
		return nil, err
	}
	p1, err := c.newPoint().SetBytes(sRemote.publicKey)
	if err != nil {
		return nil, err
	}
	p2.Add(p1, p2)

	if _, err := p2.ScalarMult(p2, t); err != nil {
		return nil, err
	}
	return c.NewPublicKey(p2.Bytes())
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5
func (c *sm2Curve) sm2za(md hash.Hash, pub *PublicKey, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("ecdh: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	md.Write(c.constantA)
	md.Write(c.constantB)
	md.Write(c.generator)
	md.Write(pub.publicKey[1:])

	return md.Sum(nil), nil
}

// P256 returns a [Curve] which implements SM2, also known as sm2p256v1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
func P256() Curve { return sm2P256 }

var sm2P256 = &sm2Curve{
	name:              "sm2p256v1",
	newPoint:          sm2ec.NewSM2P256Point,
	scalarOrder:       sm2P256Order,
	scalarOrderMinus1: sm2P256OrderMinus1,
	generator:         sm2Generator,
	constantA:         sm2ConstantA,
	constantB:         sm2ConstantB,
}

var sm2P256Order = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
	0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23}
var sm2P256OrderMinus1 = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
	0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x22}
var sm2Generator = []byte{
	0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
	0x5f, 0x99, 0x4, 0x46, 0x6a, 0x39, 0xc9, 0x94,
	0x8f, 0xe3, 0xb, 0xbf, 0xf2, 0x66, 0xb, 0xe1,
	0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
	0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
	0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
	0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
	0x2, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0}
var sm2ConstantA = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc}
var sm2ConstantB = []byte{
	0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
	0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
	0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
	0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93}

// isLess returns whether a < b, where a and b are big-endian buffers of the
// same length and shorter than 72 bytes.
func isLess(a, b []byte) bool {
	if len(a) != len(b) {
		panic("ecdh: internal error: mismatched isLess inputs")
	}

	// Copy the values into a fixed-size preallocated little-endian buffer.
	// 72 bytes is enough for every scalar in this package, and having a fixed
	// size lets us avoid heap allocations.
	if len(a) > 72 {
		panic("ecdh: internal error: isLess input too large")
	}
	bufA, bufB := make([]byte, 72), make([]byte, 72)
	for i := range a {
		bufA[i], bufB[i] = a[len(a)-i-1], b[len(b)-i-1]
	}

	// Perform a subtraction with borrow.
	var borrow uint64
	for i := 0; i < len(bufA); i += 8 {
		limbA, limbB := binary.LittleEndian.Uint64(bufA[i:]), binary.LittleEndian.Uint64(bufB[i:])
		_, borrow = bits.Sub64(limbA, limbB, borrow)
	}

	// If there is a borrow at the end of the operation, then a < b.
	return borrow == 1
}

var errInvalidPrivateKey = errors.New("ecdh: invalid private key")
