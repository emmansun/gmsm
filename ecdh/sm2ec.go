package ecdh

import (
	"encoding/binary"
	"errors"
	"io"
	"math/bits"

	"github.com/emmansun/gmsm/internal/randutil"
	sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/internal/subtle"
)

type sm2Curve struct {
	name        string
	newPoint    func() *sm2ec.SM2P256Point
	scalarOrder []byte
}

func (c *sm2Curve) String() string {
	return c.name
}

func (c *sm2Curve) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	key := make([]byte, len(c.scalarOrder))
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
	if len(key) != len(c.scalarOrder) {
		return nil, errors.New("ecdh: invalid private key size")
	}
	if subtle.ConstantTimeAllZero(key) || !isLess(key, c.scalarOrder) {
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

func (c *sm2Curve) ECDH(local *PrivateKey, remote *PublicKey) ([]byte, error) {
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

// P256 returns a Curve which implements SM2, also known as sm2p256v1
//
// Multiple invocations of this function will return the same value, so it can
// be used for equality checks and switch statements.
func P256() Curve { return sm2P256 }

var sm2P256 = &sm2Curve{
	name:        "sm2p256v1",
	newPoint:    sm2ec.NewSM2P256Point,
	scalarOrder: sm2P256Order,
}

var sm2P256Order = []byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23}

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
