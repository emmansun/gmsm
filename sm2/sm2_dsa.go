package sm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	_subtle "crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
	"sync"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/cache"
	"github.com/emmansun/gmsm/internal/sm2"
	internalSM2EC "github.com/emmansun/gmsm/internal/sm2ec"
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
// If rand is nil, Sign produces a deterministic signature according to RFC 6979,
// using SM3 as the hash function for the HMAC-based deterministic nonce generation.
// When producing a deterministic signature, priv.Curve must be SM2 P-256.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if rand == nil {
		return SignDeterministic(priv, digest, opts)
	}
	return SignASN1(rand, priv, digest, opts)
}

// SignWithSM2 signs uid, msg with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// Deprecated: please use Sign method directly.
func (priv *PrivateKey) SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error) {
	return priv.Sign(rand, msg, NewSM2SignerOption(true, uid))
}

// SignMessage signs a message with the private key, reading randomness from rand.
// If opts is an instance of SM2SignerOption, it will use the UID from opts.
// This method is used to comply with the [crypto.MessageSigner] interface.
func (priv *PrivateKey) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	var uid []byte
	if sm2Opts, ok := opts.(*SM2SignerOption); ok {
		uid = sm2Opts.uid
	}
	return priv.SignWithSM2(rand, uid, msg)
}

// GenerateKey generates a new SM2 private key.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
//
// According GB/T 32918.1-2016, the private key must be in [1, n-2].
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	privateKey, err := sm2.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return privateKeyFromInternal(sm2ec.P256(), privateKey)
}

// NewPrivateKey checks that key is valid and returns a SM2 PrivateKey.
//
// key - the private key byte slice, the length must be 32 for SM2.
//
// According GB/T 32918.1-2016, the private key must be in [1, n-2].
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	q, err := internalSM2EC.NewSM2P256Point().ScalarBaseMult(key)
	if err != nil {
		return nil, err
	}
	k, err := sm2.NewPrivateKey(key, q.Bytes())
	if err != nil {
		return nil, err
	}
	return privateKeyFromInternal(sm2ec.P256(), k)
}

// ParseRawPrivateKey parses a private key encoded as a fixed-length big-endian
// integer, according to SEC 1, Version 2.0, Section 2.3.6 (sometimes referred
// to as the raw format). It returns an error if the value is not reduced modulo
// the curve's order minus one, or if it's zero.
//
// Note that private keys are more commonly encoded in ASN.1 or PKCS#8 format,
// which can be parsed with [smx509.ParseECPrivateKey] or
// [smx509.ParsePKCS8PrivateKey] (and [encoding/pem]).
func ParseRawPrivateKey(data []byte) (*PrivateKey, error) {
	return NewPrivateKey(data)
}

// NewPrivateKeyFromInt creates a new SM2 private key from a given big integer.
// It returns an error if the provided key is nil.
func NewPrivateKeyFromInt(key *big.Int) (*PrivateKey, error) {
	if key == nil {
		return nil, errors.New("sm2: private key is nil")
	}
	keyBytes := make([]byte, P256().Params().BitSize/8)
	return NewPrivateKey(key.FillBytes(keyBytes))
}

// NewPublicKey checks that the provided key is valid and returns an SM2 PublicKey.
//
// The key parameter is a byte slice representing the public key in uncompressed format.
// According to GB/T 32918.1-2016, the public key must be in the correct format and on the curve.
func NewPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	k, err := sm2.NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	return publicKeyFromInternal(sm2ec.P256(), k)
}

// ParseUncompressedPublicKey parses a public key encoded as an uncompressed
// point according to SEC 1, Version 2.0, Section 2.3.3 (also known as the X9.62
// uncompressed format). It returns an error if the point is not in uncompressed
// form, is not on the curve, or is the point at infinity.
//
// Note that public keys are more commonly encoded in DER (or PEM) format, which
// can be parsed with [smx509.ParsePKIXPublicKey] (and [encoding/pem]).
func ParseUncompressedPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	return NewPublicKey(data)
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5.
//
// This function will NOT use default UID even the uid argument is empty.
// Reference: GM/T 0009-2023 Chapter 8.1.
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	k, err := publicKeyToInternal(pub)
	if err != nil {
		return nil, err
	}
	cacheEntry, err := zaCache.Get(pub, func() (*zaCacheEntry, error) {
		return &zaCacheEntry{
			q:      append([]byte(nil), k.Bytes()...),
			values: make(map[string][]byte),
		}, nil
	}, func(entry *zaCacheEntry) bool {
		return subtle.ConstantTimeCompare(entry.q, k.Bytes()) == 1
	})
	if err != nil {
		return nil, err
	}
	uidKey := string(uid)
	cacheEntry.mu.Lock()
	if za, ok := cacheEntry.values[uidKey]; ok {
		cached := append([]byte(nil), za...)
		cacheEntry.mu.Unlock()
		return cached, nil
	}
	cacheEntry.mu.Unlock()

	za, err := sm2.CalculateZA(k, uid)
	if err != nil {
		return nil, err
	}
	cacheEntry.mu.Lock()
	if cacheEntry.values == nil {
		cacheEntry.values = make(map[string][]byte)
	}
	cacheEntry.values[uidKey] = append([]byte(nil), za...)
	cacheEntry.mu.Unlock()
	return za, nil
}

// CalculateSM2Hash calculates the SM2 hash for the given public key, data, and user ID (UID).
// If the UID is not provided, a default UID (1234567812345678) is used.
// The public key must be valid, otherwise will be panic.
// This function is used to calculate the hash value for SM2 signature.
// Reference: GM/T 0009-2023 Chapter 8.1 and 8.2.
func CalculateSM2Hash(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
	k, err := publicKeyToInternal(pub)
	if err != nil {
		return nil, err
	}
	return sm2.CalculateSM2Hash(k, data, uid)
}

func preprocessSigningHash(pub *ecdsa.PublicKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(hash) == 0 {
		return nil, errors.New("sm2: hash cannot be empty")
	}
	if sm2Opts, ok := opts.(*SM2SignerOption); ok && sm2Opts.forceGMSign {
		return CalculateSM2Hash(pub, hash, sm2Opts.uid)
	}
	return hash, nil
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
//
// For SM2 P-256, the signature is "hedged": the nonce is derived from
// HMAC-SM3(d || hash || rand), following draft-irtf-cfrg-det-sigs-with-noise-04,
// Section 4. This provides both RNG failure resistance (the nonce is bound to
// the private key and the hash, so even a broken RNG won't leak the key) and
// fault injection tolerance (the rand input makes each signature unique).
// For other curves, the signature uses a pure random nonce.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned signature does not depend deterministically on the bytes read from
// rand, and may change between calls and/or between versions.
//
// If the opts argument is instance of [*SM2SignerOption], and its ForceGMSign is true,
// then the hash will be treated as raw message.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	var err error
	hash, err = preprocessSigningHash(&priv.PublicKey, hash, opts)
	if err != nil {
		return nil, err
	}

	if priv.Curve.Params() != P256().Params() {
		return nil, errors.New("sm2: curve not supported by SignASN1")
	}

	internalPriv, err := privateKeyToInternal(priv)
	if err != nil {
		return nil, err
	}
	signature, err := sm2.Sign(rand, internalPriv, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(signature.R, signature.S)
}

// SignDeterministic generates a deterministic SM2 signature according to RFC 6979,
// using SM3 as the hash function for the HMAC-based deterministic nonce generation.
// This method eliminates the risk of random number generator failure and is
// widely used in blockchain, HSMs, and key custody scenarios.
// Note: This uses HMAC-SM3, not the GM/T 0105 DRBG, as it is a stateless
// deterministic derivation process rather than a random bit generator.
func SignDeterministic(priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	var err error
	hash, err = preprocessSigningHash(&priv.PublicKey, hash, opts)
	if err != nil {
		return nil, err
	}

	if priv.Curve.Params() != P256().Params() {
		return nil, errors.New("sm2: curve not supported by deterministic signatures")
	}

	internalPriv, err := privateKeyToInternal(priv)
	if err != nil {
		return nil, err
	}
	signature, err := sm2.SignDeterministic(internalPriv, hash)
	if err != nil {
		return nil, err
	}
	return encodeSignature(signature.R, signature.S)
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// SignASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Deprecated: please use SignASN1 instead, which returns ASN.1 encoded signature.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	key := new(PrivateKey)
	key.PrivateKey = *priv
	internalPriv, err := privateKeyToInternal(key)
	if err != nil {
		return nil, nil, err
	}
	signature, err := sm2.Sign(rand, internalPriv, hash)
	if err != nil {
		return nil, nil, err
	}
	r, s = new(big.Int), new(big.Int)
	r.SetBytes(signature.R)
	s.SetBytes(signature.S)
	return r, s, nil
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

func verifySignatureBytes(pub *ecdsa.PublicKey, hash, rBytes, sBytes []byte) bool {
	if pub.Curve.Params() != P256().Params() {
		return false
	}
	internalPub, err := publicKeyToInternal(pub)
	if err != nil {
		return false
	}
	return sm2.Verify(internalPub, hash, &sm2.Signature{R: rBytes, S: sBytes}) == nil
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness, in other words,
// the caller must pre-compute the hash value.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	return verifySignatureBytes(pub, hash, rBytes, sBytes)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness.
// Deprecated: please use VerifyASN1 instead, which takes ASN.1 encoded signature.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	return verifySignatureBytes(pub, hash, r.Bytes(), s.Bytes())
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
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	pubs, err := sm2.RecoverPublicKeysFromSM2Signature(hash, &sm2.Signature{R: rBytes, S: sBytes})
	if err != nil {
		return nil, err
	}
	results := make([]*ecdsa.PublicKey, 0, len(pubs))
	for _, pub := range pubs {
		internalPub, err := publicKeyFromInternal(P256(), pub)
		if err != nil {
			return nil, err
		}
		results = append(results, internalPub)
	}
	return results, nil
}

// sm2Hasher is a wrapper around a hash.Hash that includes the ZA value for SM2 hashing.
// It is used to perform SM2-specific hashing operations with the provided public key and user ID.
type sm2Hasher struct {
	inner hash.Hash
	za    []byte
}

// NewHash creates a new hash.Hash instance using the provided SM2 public key.
// It uses the default SM3 hash function and default user ID.
func NewHash(pub *ecdsa.PublicKey) (hash.Hash, error) {
	return NewHashWithUserID(pub, defaultUID)
}

// NewHashWithUserID creates a new hash.Hash instance using the provided SM2 public key and user ID.
// It internally uses the SM3 hash function.
func NewHashWithUserID(pub *ecdsa.PublicKey, userID []byte) (hash.Hash, error) {
	return NewHashWithHashAndUserID(pub, sm3.New, userID)
}

// NewHashWithHashAndUserID creates a new hash.Hash instance that incorporates SM2-specific
// hashing with the provided public key, inner hash and user ID.
// The returned hasher is reset before being returned.
func NewHashWithHashAndUserID(pub *ecdsa.PublicKey, h func() hash.Hash, userID []byte) (hash.Hash, error) {
	inner := h()
	za, err := CalculateZA(pub, userID)
	if err != nil {
		return nil, err
	}
	hasher := &sm2Hasher{inner: inner, za: za}
	hasher.Write(za)
	return hasher, nil
}

// Write writes the contents of p into the underlying hash function.
// It returns the number of bytes written from p (n) and any error encountered (err).
// This method satisfies the io.Writer interface.
func (s *sm2Hasher) Write(p []byte) (n int, err error) {
	return s.inner.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (s *sm2Hasher) Sum(b []byte) []byte {
	return s.inner.Sum(b)
}

// Reset clears the current state of the sm2Hasher and reinitializes it.
// It first resets the inner hash state and then writes the ZA value to it.
func (s *sm2Hasher) Reset() {
	s.inner.Reset()
	s.inner.Write(s.za)
}

// Size returns the size of the hash in bytes.
func (s *sm2Hasher) Size() int {
	return s.inner.Size()
}

// BlockSize returns the block size of the hash function in bytes.
// It delegates the call to the inner hash function's BlockSize method.
func (s *sm2Hasher) BlockSize() int {
	return s.inner.BlockSize()
}

func publicKeyFromInternal(curve elliptic.Curve, pub *sm2.PublicKey) (*ecdsa.PublicKey, error) {
	x, y, err := pointToAffine(curve, pub.Bytes())
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func privateKeyFromInternal(curve elliptic.Curve, priv *sm2.PrivateKey) (*PrivateKey, error) {
	pub, err := publicKeyFromInternal(curve, priv.PublicKey())
	if err != nil {
		return nil, err
	}
	return &PrivateKey{PrivateKey: ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(priv.Bytes())}}, nil
}

type zaCacheEntry struct {
	q      []byte
	values map[string][]byte
	mu     sync.Mutex
}

var (
	publicKeyCache cache.Cache[ecdsa.PublicKey, sm2.PublicKey]
	zaCache        cache.Cache[ecdsa.PublicKey, zaCacheEntry]
)

func publicKeyToInternal(pub *ecdsa.PublicKey) (*sm2.PublicKey, error) {
	if pub.Curve != P256() {
		return nil, errors.New("sm2: public key curve is not SM2 P256")
	}
	Q, err := pointFromAffine(pub.Curve, pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	return publicKeyCache.Get(pub, func() (*sm2.PublicKey, error) {
		return sm2.NewPublicKey(Q)
	}, func(k *sm2.PublicKey) bool {
		return subtle.ConstantTimeCompare(k.Bytes(), Q) == 1
	})
}

var privateKeyCache cache.Cache[PrivateKey, sm2.PrivateKey]

func privateKeyToInternal(priv *PrivateKey) (*sm2.PrivateKey, error) {
	if priv.Curve != P256() {
		return nil, errors.New("sm2: private key curve is not SM2 P256")
	}
	Q, err := pointFromAffine(priv.Curve, priv.X, priv.Y)
	if err != nil {
		return nil, err
	}
	// Reject values that would not get correctly encoded.
	if priv.D.BitLen() > priv.Curve.Params().N.BitLen() {
		return nil, errors.New("sm2: private key scalar too large")
	}
	if priv.D.Sign() <= 0 {
		return nil, errors.New("sm2: private key scalar is zero or negative")
	}

	size := (priv.Curve.Params().N.BitLen() + 7) / 8
	D := priv.D.FillBytes(make([]byte, size))

	return privateKeyCache.Get(priv, func() (*sm2.PrivateKey, error) {
		return sm2.NewPrivateKey(D, Q)
	}, func(k *sm2.PrivateKey) bool {
		return subtle.ConstantTimeCompare(k.PublicKey().Bytes(), Q) == 1 &&
			subtle.ConstantTimeCompare(k.Bytes(), D) == 1
	})
}

// pointFromAffine is used to convert the PublicKey to a nistec SetBytes input.
func pointFromAffine(curve elliptic.Curve, x, y *big.Int) ([]byte, error) {
	bitSize := curve.Params().BitSize
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return nil, errors.New("negative coordinate")
	}
	if x.BitLen() > bitSize || y.BitLen() > bitSize {
		return nil, errors.New("overflowing coordinate")
	}
	// Encode the coordinates and let [ecdsa.NewPublicKey] reject invalid points.
	byteLen := (bitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4 // uncompressed point
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen : 1+2*byteLen])
	return buf, nil
}

// pointToAffine is used to convert a nistec Bytes encoding to a PublicKey.
func pointToAffine(curve elliptic.Curve, p []byte) (x, y *big.Int, err error) {
	if len(p) == 1 && p[0] == 0 {
		// This is the encoding of the point at infinity.
		return nil, nil, errors.New("sm2: public key point is the infinity")
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	x = new(big.Int).SetBytes(p[1 : 1+byteLen])
	y = new(big.Int).SetBytes(p[1+byteLen:])
	return x, y, nil
}
