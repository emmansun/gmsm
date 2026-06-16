// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"errors"
	"hash"
	"io"
	"sync"

	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/internal/sm3"
)

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = compressed02 | 0x01
	hybrid06     byte = 0x06
	hybrid07     byte = hybrid06 | 0x01
)

var (
	defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	errInvalidPrivateKey = errors.New("sm2: invalid private key")

	errInvalidSignature = errors.New("sm2: invalid signature")
)

// PrivateKey and PublicKey are not generic to make it possible to use them
// in other types without instantiating them with a specific point type.
// They are tied to one of the Curve types below through the curveID field.

type PrivateKey struct {
	pub PublicKey
	d   []byte // bigmod.(*Nat).Bytes output (fixed length)
	// inverseOfKeyPlus1 is set under inverseOfKeyPlus1Once
	inverseOfKeyPlus1     *bigmod.Nat
	inverseOfKeyPlus1Once sync.Once
}

func (priv *PrivateKey) Bytes() []byte {
	return priv.d
}

func (priv *PrivateKey) PublicKey() *PublicKey {
	return &priv.pub
}

// inverseOfPrivateKeyPlus1 calculates and returns the modular inverse of (private key + 1) modulo the curve order.
// It uses lazy initialization and caching to ensure the calculation is performed only once.
// If the private key is invalid, it returns an error.
func (priv *PrivateKey) inverseOfPrivateKeyPlus1(c *Curve) (*bigmod.Nat, error) {
	var (
		err           error
		oneNat        = bigmod.NewNat().SetUint(1, c.N)
		inverseDPlus1 *bigmod.Nat
		dp1Bytes      []byte
	)
	priv.inverseOfKeyPlus1Once.Do(func() {
		inverseDPlus1, err = bigmod.NewNat().SetBytes(priv.d, c.N)
		if err == nil {
			inverseDPlus1.Add(oneNat, c.N)
			if inverseDPlus1.IsZero() == 1 { // make sure private key is NOT N-1
				err = errInvalidPrivateKey
			} else {
				dp1Bytes, err = sm2ec.P256OrdInverse(inverseDPlus1.Bytes(c.N))
				if err == nil {
					priv.inverseOfKeyPlus1, err = bigmod.NewNat().SetBytes(dp1Bytes, c.N)
				}
			}
		}
	})
	if err != nil {
		return nil, errInvalidPrivateKey
	}
	return priv.inverseOfKeyPlus1, nil
}

type PublicKey struct {
	curve curveID
	q     []byte // uncompressed nistec Point.Bytes output
}

func (pub *PublicKey) Bytes() []byte {
	return pub.q
}

type curveID string

const (
	p256 curveID = "SM2 P-256"
)

type Curve struct {
	curve      curveID
	newPoint   func() *sm2ec.SM2P256Point
	ordInverse func([]byte) ([]byte, error)
	N          *bigmod.Modulus
	P          *bigmod.Modulus
	nMinus1    *bigmod.Nat
	nMinus2    []byte
	constantA  []byte
	constantB  []byte
	generator  []byte
}

func precomputeParams(c *Curve, order, p []byte) {
	c.P, _ = bigmod.NewModulus(p)
	c.N, _ = bigmod.NewModulus(order)
	c.nMinus1 = c.N.Nat().SubOne(c.N)
	c.nMinus2 = new(bigmod.Nat).Set(c.nMinus1).SubOne(c.N).Bytes(c.N)
}

var initonce sync.Once

func initAll() {
	initSM2P256()
}

func P256() *Curve {
	initonce.Do(initAll)
	return sm2p256
}

var sm2p256 = &Curve{
	curve:      p256,
	newPoint:   sm2ec.NewSM2P256Point,
	ordInverse: sm2ec.P256OrdInverse,
	generator:  sm2Generator,
	constantA:  sm2ConstantA,
	constantB:  sm2ConstantB,
}

func initSM2P256() {
	precomputeParams(sm2p256, p256Order, p256P)
}

var p256P = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

var p256Order = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
	0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23,
}

var sm2Generator = []byte{
	0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
	0x5f, 0x99, 0x4, 0x46, 0x6a, 0x39, 0xc9, 0x94,
	0x8f, 0xe3, 0xb, 0xbf, 0xf2, 0x66, 0xb, 0xe1,
	0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
	0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
	0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
	0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
	0x2, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
}

var sm2ConstantA = []byte{
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
}

var sm2ConstantB = []byte{
	0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
	0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
	0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
	0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
}

func NewPrivateKey(D, Q []byte) (*PrivateKey, error) {
	c := P256()
	if len(D) != c.N.Size() {
		return nil, errors.New("sm2: invalid private key size")
	}
	d, err := bigmod.NewNat().SetBytes(D, c.N)
	if err != nil {
		return nil, err
	}
	if d.IsZero() == 1 {
		return nil, errors.New("sm2: private key is zero")
	}
	if d.Equal(c.nMinus1) == 1 {
		return nil, errors.New("sm2: private key is N-1")
	}
	pub, err := NewPublicKey(Q)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{pub: *pub, d: d.Bytes(c.N)}
	return priv, nil
}

func NewPublicKey(Q []byte) (*PublicKey, error) {
	c := P256()
	// SetBytes checks that Q is a valid point on the curve, and that its
	// coordinates are reduced modulo p, fulfilling the requirements of SP
	// 800-89, Section 5.3.2.
	if len(Q) < 1 || Q[0] == 0 {
		return nil, errors.New("sm2: invalid public key encoding")
	}
	_, err := c.newPoint().SetBytes(Q)
	if err != nil {
		return nil, err
	}
	return &PublicKey{curve: c.curve, q: Q}, nil
}

func ZA(hasher hash.Hash, curve *Curve, pub *PublicKey) {
	hasher.Write(curve.constantA)
	hasher.Write(curve.constantB)
	hasher.Write(curve.generator)
	hasher.Write(pub.q[1:])
}

// GenerateKey generates a new SM2 private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256()
	k, Q, err := randomPoint(c, randFuncFac(rand), true)
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{
		pub: PublicKey{
			curve: c.curve,
			q:     Q.Bytes(),
		},
		d: k.Bytes(c.N),
	}
	return priv, nil
}

// randomPoint returns a random scalar and the corresponding point using a
// procedure equivalent to FIPS 186-5, Appendix A.2.2 (ECDSA Key Pair Generation
// by Rejection Sampling) and to Appendix A.3.2 (Per-Message Secret Number
// Generation of Private Keys by Rejection Sampling) or Appendix A.3.3
// (Per-Message Secret Number Generation for Deterministic ECDSA) followed by
// Step 5 of Section 6.4.1.
func randomPoint(c *Curve, generate func([]byte) error, checkOrderMinus1 bool) (k *bigmod.Nat, p *sm2ec.SM2P256Point, err error) {
	for {
		b := make([]byte, c.N.Size())
		if err := generate(b); err != nil {
			return nil, nil, err
		}
		// FIPS 186-5, Appendix A.4.2 makes us check x <= N - 2 and then return
		// x + 1. Note that it follows that 0 < x + 1 < N. Instead, SetBytes
		// checks that k < N, and we explicitly check 0 != k. Since k can't be
		// negative, this is strictly equivalent. None of this matters anyway
		// because the chance of selecting zero is cryptographically negligible.
		if k, err := bigmod.NewNat().SetBytes(b, c.N); err == nil && k.IsZero() == 0 && (!checkOrderMinus1 || k.Equal(c.nMinus1) == 0) {
			p, err := c.newPoint().ScalarBaseMult(k.Bytes(c.N))
			return k, p, err
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

// Signature is an ECDSA signature, where r and s are represented as big-endian
// byte slices of the same length as the curve order.
type Signature struct {
	R, S []byte
}

// CalculateSM2Hash calculates the SM2 hash for the given public key, data, and user ID (UID).
// If the UID is not provided, a default UID (1234567812345678) is used.
// The public key must be valid, otherwise will be panic.
// This function is used to calculate the hash value for SM2 signature.
// Reference: GM/T 0009-2023 Chapter 8.1 and 8.2.
func CalculateSM2Hash(pub *PublicKey, data, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := CalculateZA(pub, uid)
	if err != nil {
		return nil, err
	}
	md := sm3.New()
	md.Write(za)
	md.Write(data)
	return md.Sum(nil), nil
}

// hashToNat sets e to the left-most bits of hash, according to
// SEC 1, Section 4.1.3, point 5 and Section 4.1.4, point 3.
func hashToNat(c *Curve, e *bigmod.Nat, hash []byte) {
	// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
	// an integer modulo N. This is the absolute worst of all worlds: we still
	// have to reduce, because the result might still overflow N, but to take
	// the left-most bits for P-521 we have to do a right shift.
	if size := c.N.Size(); len(hash) > size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = append([]byte{}, hash...)
			for i := len(hash) - 1; i >= 0; i-- {
				hash[i] >>= excess
				if i > 0 {
					hash[i] |= hash[i-1] << (8 - excess)
				}
			}
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("sm2: internal error: truncated hash is too long")
	}
}

// bits2octets as specified in FIPS 186-5, Appendix B.2.4 or RFC 6979,
// Section 2.3.4. See RFC 6979, Section 3.5 for the rationale.
func bits2octets(c *Curve, hash []byte) []byte {
	e := bigmod.NewNat()
	hashToNat(c, e, hash)
	return e.Bytes(c.N)
}

func drbgRandFunc(drbg *hmacDRBG) func([]byte) error {
	return func(b []byte) error {
		drbg.Generate(b)
		return nil
	}
}

var randFuncFac = func(rand io.Reader) func([]byte) error {
	return func(b []byte) error {
		_, err := io.ReadFull(rand, b)
		return err
	}
}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5.
//
// This function will NOT use default UID even the uid argument is empty.
// Reference: GM/T 0009-2023 Chapter 8.1.
func CalculateZA(pub *PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen > 0x1fff {
		return nil, errors.New("sm2: the uid is too long")
	}
	uidBitLength := uint16(uidLen) << 3
	md := sm3.New()
	md.Write([]byte{byte(uidBitLength >> 8), byte(uidBitLength)})
	if uidLen > 0 {
		md.Write(uid)
	}
	c := P256()
	md.Write(c.constantA)
	md.Write(c.constantB)
	md.Write(c.generator)
	md.Write(pub.q[1:])
	return md.Sum(nil), nil
}

func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (*Signature, error) {
	c := P256()
	if len(hash) == 0 {
		return nil, errors.New("sm2: hash cannot be empty")
	}
	// Hedged signature construction per
	// draft-irtf-cfrg-det-sigs-with-noise-04, Section 4.
	//
	// The nonce is derived from HMAC-SM3(d || hash || Z), where Z is
	// random data from rand. If the RNG fails, the nonce is still bound
	// to (d, hash) through the personalization string, preventing key
	// leakage. If the RNG works, Z ensures each signature is unique,
	// providing fault injection tolerance.
	Z := make([]byte, c.N.Size())
	if _, err := io.ReadFull(rand, Z); err != nil {
		return nil, err
	}
	drbg := newDRBG(Z, nil, blockAlignedPersonalizationString{priv.d, bits2octets(c, hash)})
	return sign(c, priv, drbgRandFunc(drbg), hash)
}

// SignDeterministic generates a deterministic SM2 signature according to RFC 6979,
// using SM3 as the hash function for the HMAC-based deterministic nonce generation.
// This method eliminates the risk of random number generator failure and is
// widely used in blockchain, HSMs, and key custody scenarios.
// Note: This uses HMAC-SM3, not the GM/T 0105 DRBG, as it is a stateless
// deterministic derivation process rather than a random bit generator.
func SignDeterministic(priv *PrivateKey, hash []byte) (*Signature, error) {
	c := P256()
	if len(hash) == 0 {
		return nil, errors.New("sm2: hash cannot be empty")
	}
	drbg := newDRBG(priv.d, bits2octets(c, hash), nil) // RFC 6979, Section 3.3
	return sign(c, priv, drbgRandFunc(drbg), hash)
}

func sign(c *Curve, priv *PrivateKey, generate func([]byte) error, hash []byte) (*Signature, error) {
	inverseDPlus1, err := priv.inverseOfPrivateKeyPlus1(c)
	if err != nil {
		return nil, err
	}
	var (
		k, r, s *bigmod.Nat
		R       *sm2ec.SM2P256Point
	)

	// hash to int
	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	for {
		for {
			k, R, err = randomPoint(c, generate, false)
			if err != nil {
				return nil, err
			}
			Rx, err := R.BytesX()
			if err != nil {
				return nil, err
			}
			r, err = bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
			if err != nil {
				return nil, err
			}
			// r = [Rx + e]
			r.Add(e, c.N)

			// checks if r is zero or [r+k] is zero
			if r.IsZero() == 0 {
				t := bigmod.NewNat().Set(k).Add(r, c.N)
				if t.IsZero() == 0 {
					break
				}
			}
		}
		// s = [r * d]
		s, err = bigmod.NewNat().SetBytes(priv.d, c.N)
		if err != nil {
			return nil, err
		}
		s.Mul(r, c.N)
		// k = [k - s]
		k.Sub(s, c.N)
		// k = [(d+1)⁻¹ * (k - r * d)]
		k.Mul(inverseDPlus1, c.N)
		if k.IsZero() == 0 {
			break
		}
	}
	return &Signature{R: r.Bytes(c.N), S: k.Bytes(c.N)}, nil
}

func Verify(pub *PublicKey, hash []byte, sig *Signature) error {
	c := P256()
	Q, err := c.newPoint().SetBytes(pub.q)
	if err != nil {
		return err
	}
	r, err := bigmod.NewNat().SetBytes(sig.R, c.N)
	if err != nil {
		return err
	}
	if r.IsZero() == 1 {
		return errors.New("sm2: invalid signature: r is zero")
	}
	s, err := bigmod.NewNat().SetBytes(sig.S, c.N)
	if err != nil {
		return err
	}
	if s.IsZero() == 1 {
		return errors.New("sm2: invalid signature: s is zero")
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	// p₁ = [s]G
	p1, err := c.newPoint().ScalarBaseMult(s.Bytes(c.N))
	if err != nil {
		return err
	}

	// s = [r + s]
	s.Add(r, c.N)
	if s.IsZero() == 1 {
		return errors.New("sm2: invalid signature: r + s is zero")
	}

	// p₂ = [r+s]Q
	p2, err := Q.ScalarMult(Q, s.Bytes(c.N))
	if err != nil {
		return err
	}

	// BytesX returns an error for the point at infinity.
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return err
	}

	_, err = s.SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return err
	}
	s.Add(e, c.N)

	if s.Equal(r) != 1 {
		return errors.New("sm2: signature did not verify")
	}
	return nil
}

// RecoverPublicKeysFromSM2Signature attempts to recover the public keys from an SM2 signature.
// This function takes a hash and a signature as input and returns a slice of possible public keys
// that could have generated the given signature.
//
// Parameters:
// - hash: The hash of the message that was signed.
// - sig: The SM2 signature.
//
// Returns:
// - A slice of pointers to ecdsa.PublicKey, representing the possible public keys.
// - An error if the signature is invalid or if any other error occurs during the recovery process.
//
// The function performs the following steps:
// 1. Parses the signature to extract the r and s values.
// 2. Converts the hash to a big integer (Nat).
// 3. Computes the point p₁ = [-s]G.
// 4. Computes s = [r + s] and its modular inverse.
// 5. Computes the possible x-coordinates (Rx) for the point R.
// 6. For each possible Rx, computes the corresponding point R and derives the public key.
//
// Note: The function handles the case where there are one or two possible values for Rx,
// resulting in two or four possible public keys.
func RecoverPublicKeysFromSM2Signature(hash []byte, sig *Signature) ([]*PublicKey, error) {
	c := P256()
	r, err := bigmod.NewNat().SetBytes(sig.R, c.N)
	if err != nil || r.IsZero() == 1 {
		return nil, errInvalidSignature
	}
	s, err := bigmod.NewNat().SetBytes(sig.S, c.N)
	if err != nil || s.IsZero() == 1 {
		return nil, errInvalidSignature
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	// p₁ = [-s]G
	negS := bigmod.NewNat().ExpandFor(c.N).Sub(s, c.N)
	p1, err := c.newPoint().ScalarBaseMult(negS.Bytes(c.N))
	if err != nil {
		return nil, err
	}

	// s = [r + s]
	s.Add(r, c.N)
	if s.IsZero() == 1 {
		return nil, errInvalidSignature
	}
	// sBytes = (r+s)⁻¹
	sBytes, err := c.ordInverse(s.Bytes(c.N))
	if err != nil {
		return nil, err
	}

	// r = (Rx + e) mod N
	// Rx = r - e
	r.Sub(e, c.N)
	if r.IsZero() == 1 {
		return nil, errInvalidSignature
	}
	pointRx := make([]*bigmod.Nat, 0, 2)
	pointRx = append(pointRx, r)
	// check if Rx in (N, P), small probability event
	s.Set(r)
	s = s.Add(c.N.Nat(), c.P)
	if s.CmpGeq(c.N.Nat()) == 1 {
		pointRx = append(pointRx, s)
	}
	pubs := make([]*PublicKey, 0, 4)
	bytes := make([]byte, 32+1)
	compressFlags := []byte{compressed02, compressed03}
	// Rx has one or two possible values, so point R has two or four possible values
	var rBytes []byte
	for _, x := range pointRx {
		rBytes = x.Bytes(c.N)
		copy(bytes[1:], rBytes)
		for _, flag := range compressFlags {
			bytes[0] = flag
			// p0 = R
			p0, err := c.newPoint().SetBytes(bytes)
			if err != nil {
				return nil, err
			}
			// p0 = R - [s]G
			p0.Add(p0, p1)
			// Pub = [(r + s)⁻¹](R - [s]G)
			p0.ScalarMult(p0, sBytes)
			pubs = append(pubs, &PublicKey{curve: p256, q: p0.Bytes()})
		}
	}

	return pubs, nil
}
