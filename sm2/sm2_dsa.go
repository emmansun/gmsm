package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_subtle "crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
	"sync"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/randutil"
	_sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed.
var directSigning crypto.Hash = 0

// Signer is an interface for an opaque private key that can be used for
// signing operations. For example, an SM2 key kept in a hardware module.
// Deprecated: please use crypto.Signer directly.
type Signer interface {
	// Public returns the public key corresponding to the opaque,
	// private key.
	Public() crypto.PublicKey

	// SignWithSM2 signs raw message with the private key, possibly using entropy from
	// rand, and the user ID (UID). If the UID is not provided, a default UID (1234567812345678) is used.
	// The signature is generated using the SM2 algorithm.
	SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error)
}

// SM2SignerOption implements crypto.SignerOpts interface and is used for SM2-specific signing options.
// It is specific for SM2, used in private key's Sign method.
type SM2SignerOption struct {
	uid         []byte
	forceGMSign bool
}

// NewSM2SignerOption creates a SM2 specific signer option.
// forceGMSign - if use GM specific sign logic, if yes, should pass raw message to sign.
// uid - if forceGMSign is true, then you can pass uid, if no uid is provided, system will use default one.
func NewSM2SignerOption(forceGMSign bool, uid []byte) *SM2SignerOption {
	opt := &SM2SignerOption{
		uid:         uid,
		forceGMSign: forceGMSign,
	}
	if forceGMSign && len(uid) == 0 {
		opt.uid = defaultUID
	}
	return opt
}

// DefaultSM2SignerOpts uses default UID and forceGMSign is true.
var DefaultSM2SignerOpts = NewSM2SignerOption(true, nil)

func (*SM2SignerOption) HashFunc() crypto.Hash {
	return directSigning
}

var (
	errInvalidPrivateKey = errors.New("sm2: invalid private key")
	errInvalidPublicKey  = errors.New("sm2: invalid public key")
)

// PrivateKey represents an ECDSA SM2 private key.
// It embeds ecdsa.PrivateKey and includes additional fields for SM2-specific operations.
// It implements both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
	// inverseOfKeyPlus1 stores the modular inverse of (private key + 1) modulo the curve order.
	// It is computed lazily and cached using sync.Once to ensure it is only calculated once.
	inverseOfKeyPlus1     *bigmod.Nat
	inverseOfKeyPlus1Once sync.Once
}

// FromECPrivateKey convert an ecdsa private key to SM2 private key.
func (priv *PrivateKey) FromECPrivateKey(key *ecdsa.PrivateKey) (*PrivateKey, error) {
	if key.Curve != sm2ec.P256() {
		return nil, errors.New("sm2: not an SM2 curve private key")
	}
	// Copy the ECDSA private key fields to the SM2 private key
	priv.PrivateKey = *key
	return priv, nil
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && _subtle.ConstantTimeCompare(priv.D.Bytes(), xx.D.Bytes()) == 1
}

// Sign signs digest with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// The opts argument is currently used for SM2SignerOption checking only.
// If the opts argument is SM2SignerOption and its ForceGMSign is true,
// digest argument will be treated as raw data and UID will be taken from opts.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return SignASN1(rand, priv, digest, opts)
}

// SignWithSM2 signs uid, msg with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// Deprecated: please use Sign method directly.
func (priv *PrivateKey) SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error) {
	return priv.Sign(rand, msg, NewSM2SignerOption(true, uid))
}

// GenerateKey generates a new SM2 private key.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
//
// According GB/T 32918.1-2016, the private key must be in [1, n-2].
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	randutil.MaybeReadByte(rand)

	c := p256()
	k, Q, err := randomPoint(c, rand, true)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(Q)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// NewPrivateKey checks that key is valid and returns a SM2 PrivateKey.
//
// key - the private key byte slice, the length must be 32 for SM2.
//
// According GB/T 32918.1-2016, the private key must be in [1, n-2].
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	c := p256()
	if len(key) != c.N.Size() {
		return nil, errors.New("sm2: invalid private key size")
	}
	k, err := bigmod.NewNat().SetBytes(key, c.N)
	if err != nil || k.IsZero() == 1 || k.Equal(c.nMinus1) == 1 {
		return nil, errInvalidPrivateKey
	}
	p, err := c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c.curve
	priv.D = new(big.Int).SetBytes(k.Bytes(c.N))
	priv.PublicKey.X, priv.PublicKey.Y, err = c.pointToAffine(p)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// NewPrivateKeyFromInt creates a new SM2 private key from a given big integer.
// It returns an error if the provided key is nil.
func NewPrivateKeyFromInt(key *big.Int) (*PrivateKey, error) {
	if key == nil {
		return nil, errors.New("sm2: private key is nil")
	}
	keyBytes := make([]byte, p256().N.Size())
	return NewPrivateKey(key.FillBytes(keyBytes))
}

// NewPublicKey checks that the provided key is valid and returns an SM2 PublicKey.
//
// The key parameter is a byte slice representing the public key in uncompressed format.
// According to GB/T 32918.1-2016, the public key must be in the correct format and on the curve.
func NewPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	c := p256()
	// Reject the point at infinity and compressed encodings.
	// Points at infinity are invalid because they do not represent a valid point on the curve.
	// Compressed encodings are not supported by this implementation, so they are also rejected.
	if len(key) == 0 || key[0] != 4 {
		return nil, errInvalidPublicKey
	}
	// SetBytes also checks that the point is on the curve.
	p, err := c.newPoint().SetBytes(key)
	if err != nil {
		return nil, err
	}
	k := new(ecdsa.PublicKey)
	k.Curve = c.curve
	k.X, k.Y, err = c.pointToAffine(p)
	if err != nil {
		return nil, err
	}
	return k, nil
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5.
//
// This function will not use default UID even the uid argument is empty.
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
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
	writeCurveParams(md, pub.Curve)
	md.Write(bigIntToBytes(pub.Curve, pub.X))
	md.Write(bigIntToBytes(pub.Curve, pub.Y))
	// Return the calculated ZA value
	return md.Sum(nil), nil
}

// writeCurveParams writes the parameters of the given elliptic curve to the provided hash.Hash.
// It writes the following parameters in order:
// - a: P - 3 (where P is the prime specifying the base field of the curve)
// - B: the coefficient B of the curve equation
// - Gx: the x-coordinate of the base point G
// - Gy: the y-coordinate of the base point G
//
// Parameters:
// - md: the hash.Hash to write the curve parameters to
// - curve: the elliptic.Curve whose parameters are to be written
func writeCurveParams(md hash.Hash, curve elliptic.Curve) {
	a := new(big.Int).Sub(curve.Params().P, big.NewInt(3))
	md.Write(bigIntToBytes(curve, a))
	md.Write(bigIntToBytes(curve, curve.Params().B))
	md.Write(bigIntToBytes(curve, curve.Params().Gx))
	md.Write(bigIntToBytes(curve, curve.Params().Gy))
}

// bigIntToBytes converts a big integer value to a byte slice of the appropriate length for the given elliptic curve.
// The byte slice is zero-padded to the left if necessary to match the curve's byte length.
func bigIntToBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	byteArray := make([]byte, byteLen)
	value.FillBytes(byteArray)
	return byteArray
}

// CalculateSM2Hash calculates the SM2 hash for the given public key, data, and user ID (UID).
// If the UID is not provided, a default UID (1234567812345678) is used.
// The public key must be valid, otherwise will be panic.
// This function is used to calculate the hash value for SM2 signature.
func CalculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
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

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
//
// If the opts argument is instance of [*SM2SignerOption], and its ForceGMSign is true,
// then the hash will be treated as raw message.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if sm2Opts, ok := opts.(*SM2SignerOption); ok && sm2Opts.forceGMSign {
		newHash, err := CalculateSM2Hash(&priv.PublicKey, hash, sm2Opts.uid)
		if err != nil {
			return nil, err
		}
		hash = newHash
	}

	randutil.MaybeReadByte(rand)

	switch priv.Curve.Params() {
	case P256().Params():
		return signSM2EC(p256(), priv, rand, hash)
	default:
		return signLegacy(priv, rand, hash)
	}
}

// inverseOfPrivateKeyPlus1 calculates and returns the modular inverse of (private key + 1) modulo the curve order.
// It uses lazy initialization and caching to ensure the calculation is performed only once.
// If the private key is invalid, it returns an error.
func (priv *PrivateKey) inverseOfPrivateKeyPlus1(c *sm2Curve) (*bigmod.Nat, error) {
	var (
		err           error
		oneNat        = bigmod.NewNat().SetUint(1, c.N)
		inverseDPlus1 *bigmod.Nat
		dp1Bytes      []byte
	)
	priv.inverseOfKeyPlus1Once.Do(func() {
		inverseDPlus1, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err == nil {
			inverseDPlus1.Add(oneNat, c.N)
			if inverseDPlus1.IsZero() == 1 { // make sure private key is NOT N-1
				err = errInvalidPrivateKey
			} else {
				dp1Bytes, err = _sm2ec.P256OrdInverse(inverseDPlus1.Bytes(c.N))
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

// signSM2EC generates an SM2 digital signature using the provided private key and hash.
// It follows the SM2 signature algorithm as specified in the Chinese cryptographic standards.
//
// Parameters:
// - c: A pointer to the sm2Curve structure representing the elliptic curve parameters.
// - priv: A pointer to the PrivateKey structure containing the private key for signing.
// - rand: An io.Reader instance used to generate random values.
// - hash: A byte slice containing the hash of the message to be signed.
//
// Returns:
// - sig: A byte slice containing the generated signature.
// - err: An error value indicating any issues encountered during the signing process.
//
// The function performs the following steps:
// 1. Computes the inverse of (d + 1) where d is the private key.
// 2. Converts the hash to an integer.
// 3. Generates a random point on the elliptic curve and computes the signature components (r, s).
// 4. Ensures that the signature components are non-zero and valid.
// 5. Encodes the signature components into a byte slice and returns it.
func signSM2EC(c *sm2Curve, priv *PrivateKey, rand io.Reader, hash []byte) (sig []byte, err error) {
	inverseDPlus1, err := priv.inverseOfPrivateKeyPlus1(c)
	if err != nil {
		return nil, err
	}

	var (
		k, r, s *bigmod.Nat
		R       *_sm2ec.SM2P256Point
	)

	// hash to int
	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	for {
		for {
			k, R, err = randomPoint(c, rand, false)
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
		s, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
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

	return encodeSignature(r.Bytes(c.N), k.Bytes(c.N))
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

var ErrInvalidSignature = errors.New("sm2: invalid signature")

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness, in other words,
// the caller must pre-calculate the hash value.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	switch pub.Curve.Params() {
	case P256().Params():
		return verifySM2EC(p256(), pub, hash, sig)
	default:
		return verifyLegacy(pub, hash, sig)
	}
}

func verifySM2EC(c *sm2Curve, pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}

	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return false
	}

	r, err := bigmod.NewNat().SetBytes(rBytes, c.N)
	if err != nil || r.IsZero() == 1 {
		return false
	}
	s, err := bigmod.NewNat().SetBytes(sBytes, c.N)
	if err != nil || s.IsZero() == 1 {
		return false
	}

	e := bigmod.NewNat()
	hashToNat(c, e, hash)

	// p₁ = [s]G
	p1, err := c.newPoint().ScalarBaseMult(s.Bytes(c.N))
	if err != nil {
		return false
	}

	// s = [r + s]
	s.Add(r, c.N)
	if s.IsZero() == 1 {
		return false
	}

	// p₂ = [r+s]Q
	p2, err := Q.ScalarMult(Q, s.Bytes(c.N))
	if err != nil {
		return false
	}

	// BytesX returns an error for the point at infinity.
	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return false
	}

	_, err = s.SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return false
	}
	s.Add(e, c.N)

	return s.Equal(r) == 1
}

// VerifyASN1WithSM2 verifies the signature in ASN.1 encoding format sig of raw msg
// and uid using the public key, pub. The uid can be empty, meaning to use the default value.
//
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyASN1WithSM2(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool {
	digest, err := CalculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return VerifyASN1(pub, digest, sig)
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(&r) ||
		!inner.ReadASN1Integer(&s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1")
	}
	return r, s, nil
}

// hashToNat sets e to the left-most bits of hash, according to
// SEC 1, Section 4.1.3, point 5 and Section 4.1.4, point 3.
func hashToNat(c *sm2Curve, e *bigmod.Nat, hash []byte) {
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

// IsSM2PublicKey checks if the provided public key is an SM2 public key.
// It takes an interface{} as input and attempts to assert it to an *ecdsa.PublicKey.
// The function returns true if the assertion is successful and the public key's curve is SM2 P-256.
func IsSM2PublicKey(publicKey any) bool {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == sm2ec.P256()
}

// P256 returns sm2 curve signleton, this function is for backward compatibility.
func P256() elliptic.Curve {
	return sm2ec.P256()
}

// PublicKeyToECDH returns k as a [ecdh.PublicKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPublicKey], or if the
// Curve is not supported by ecdh.
func PublicKeyToECDH(k *ecdsa.PublicKey) (*ecdh.PublicKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	if !k.Curve.IsOnCurve(k.X, k.Y) {
		return nil, errInvalidPublicKey
	}
	return c.NewPublicKey(elliptic.Marshal(k.Curve, k.X, k.Y))
}

// ECDH returns k as a [ecdh.PrivateKey]. It returns an error if the key is
// invalid according to the definition of [ecdh.Curve.NewPrivateKey], or if the
// Curve is not supported by ecdh.
func (k *PrivateKey) ECDH() (*ecdh.PrivateKey, error) {
	c := curveToECDH(k.Curve)
	if c == nil {
		return nil, errors.New("sm2: unsupported curve by ecdh")
	}
	size := (k.Curve.Params().N.BitLen() + 7) / 8
	if k.D.BitLen() > size*8 {
		return nil, errInvalidPrivateKey
	}
	return c.NewPrivateKey(k.D.FillBytes(make([]byte, size)))
}

func curveToECDH(c elliptic.Curve) ecdh.Curve {
	switch c {
	case sm2ec.P256():
		return ecdh.P256()
	default:
		return nil
	}
}

// randomPoint returns a random scalar and the corresponding point using the
// procedure given in FIPS 186-4, Appendix B.5.2 (rejection sampling).
func randomPoint(c *sm2Curve, rand io.Reader, checkOrderMinus1 bool) (k *bigmod.Nat, p *_sm2ec.SM2P256Point, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, c.N.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		// Mask off any excess bits to increase the chance of hitting a value in
		// (0, N). These are the most dangerous lines in the package and maybe in
		// the library: a single bit of bias in the selection of nonces would likely
		// lead to key recovery, but no tests would fail. Look but DO NOT TOUCH.
		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if excess != 0 {
				panic("sm2: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		// Checking 0 < k <= N - 2.
		// None of this matters anyway because the chance of selecting
		// zero is cryptographically negligible.
		if _, err = k.SetBytes(b, c.N); err == nil && k.IsZero() == 0 && (!checkOrderMinus1 || k.Equal(c.nMinus1) == 0) {
			break
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}

	p, err = c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	return
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

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
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error) {
	c := p256()
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	r, err := bigmod.NewNat().SetBytes(rBytes, c.N)
	if err != nil || r.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}
	s, err := bigmod.NewNat().SetBytes(sBytes, c.N)
	if err != nil || s.IsZero() == 1 {
		return nil, ErrInvalidSignature
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
		return nil, ErrInvalidSignature
	}
	// sBytes = (r+s)⁻¹
	sBytes, err = _sm2ec.P256OrdInverse(s.Bytes(c.N))
	if err != nil {
		return nil, err
	}

	// r = (Rx + e) mod N
	// Rx = r - e
	r.Sub(e, c.N)
	if r.IsZero() == 1 {
		return nil, ErrInvalidSignature
	}
	pointRx := make([]*bigmod.Nat, 0, 2)
	pointRx = append(pointRx, r)
	// check if Rx in (N, P), small probability event
	s.Set(r)
	s = s.Add(c.N.Nat(), c.P)
	if s.CmpGeq(c.N.Nat()) == 1 {
		pointRx = append(pointRx, s)
	}
	pubs := make([]*ecdsa.PublicKey, 0, 4)
	bytes := make([]byte, 32+1)
	compressFlags := []byte{compressed02, compressed03}
	// Rx has one or two possible values, so point R has two or four possible values
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
			pub := new(ecdsa.PublicKey)
			pub.Curve = c.curve
			pub.X, pub.Y, err = c.pointToAffine(p0)
			if err != nil {
				return nil, err
			}
			pubs = append(pubs, pub)
		}
	}

	return pubs, nil
}

type sm2Curve struct {
	newPoint func() *_sm2ec.SM2P256Point
	curve    elliptic.Curve
	N        *bigmod.Modulus
	P        *bigmod.Modulus
	nMinus1  *bigmod.Nat
	nMinus2  []byte
}

// pointFromAffine is used to convert the PublicKey to a sm2 Point.
func (curve *sm2Curve) pointFromAffine(x, y *big.Int) (p *_sm2ec.SM2P256Point, err error) {
	bitSize := curve.curve.Params().BitSize
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return p, errors.New("negative coordinate")
	}
	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return p, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return curve.newPoint().SetBytes(buf)
}

// pointToAffine is used to convert a sm2 Point to a PublicKey.
func (curve *sm2Curve) pointToAffine(p *_sm2ec.SM2P256Point) (x, y *big.Int, err error) {
	out := p.Bytes()
	if len(out) == 1 && out[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("sm2: public key point is the infinity")
	}
	byteLen := (curve.curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(out[1 : 1+byteLen])
	y = new(big.Int).SetBytes(out[1+byteLen:])
	return x, y, nil
}

var p256Once sync.Once
var _p256 *sm2Curve

func p256() *sm2Curve {
	p256Once.Do(func() {
		_p256 = &sm2Curve{
			newPoint: func() *_sm2ec.SM2P256Point { return _sm2ec.NewSM2P256Point() },
		}
		precomputeParams(_p256, P256())
	})
	return _p256
}

func precomputeParams(c *sm2Curve, curve elliptic.Curve) {
	params := curve.Params()
	c.curve = curve
	c.N, _ = bigmod.NewModulus(params.N.Bytes())
	c.P, _ = bigmod.NewModulus(params.P.Bytes())
	c.nMinus1 = c.N.Nat().SubOne(c.N)
	c.nMinus2 = new(bigmod.Nat).Set(c.nMinus1).SubOne(c.N).Bytes(c.N)
}
