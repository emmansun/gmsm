// Package sm2 implements ShangMi(SM) sm2 digital signature, public key encryption and key exchange algorithms.
package sm2

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.182.4503&rep=rep1&type=pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf
//   [GM/T]: SM2 GB/T 32918.2-2016, GB/T 32918.4-2016
//

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_subtle "crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/randutil"
	_sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/kdf"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = compressed02 | 0x01
	hybrid06     byte = 0x06
	hybrid07     byte = hybrid06 | 0x01
)

// PrivateKey represents an ECDSA SM2 private key.
// It implemented both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
	// inverseOfkeyPlus1 is set under inverseOfkeyPlus1Once
	inverseOfkeyPlus1     *bigmod.Nat
	inverseOfkeyPlus1Once sync.Once
}

type pointMarshalMode byte

const (
	//MarshalUncompressed uncompressed mashal mode
	MarshalUncompressed pointMarshalMode = iota
	//MarshalCompressed compressed mashal mode
	MarshalCompressed
	//MarshalHybrid hybrid mashal mode
	MarshalHybrid
)

type ciphertextSplicingOrder byte

const (
	C1C3C2 ciphertextSplicingOrder = iota
	C1C2C3
)

type ciphertextEncoding byte

const (
	ENCODING_PLAIN ciphertextEncoding = iota
	ENCODING_ASN1
)

// EncrypterOpts encryption options
type EncrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	pointMarshalMode        pointMarshalMode
	ciphertextSplicingOrder ciphertextSplicingOrder
}

// DecrypterOpts decryption options
type DecrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	cipherTextSplicingOrder ciphertextSplicingOrder
}

// NewPlainEncrypterOpts creates a SM2 non-ASN1 encrypter options.
func NewPlainEncrypterOpts(marhsalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{ENCODING_PLAIN, marhsalMode, splicingOrder}
}

// NewPlainDecrypterOpts creates a SM2 non-ASN1 decrypter options.
func NewPlainDecrypterOpts(splicingOrder ciphertextSplicingOrder) *DecrypterOpts {
	return &DecrypterOpts{ENCODING_PLAIN, splicingOrder}
}

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	result := make([]byte, byteLen)
	value.FillBytes(result)
	return result
}

var defaultEncrypterOpts = &EncrypterOpts{ENCODING_PLAIN, MarshalUncompressed, C1C3C2}

var ASN1EncrypterOpts = &EncrypterOpts{ENCODING_ASN1, MarshalUncompressed, C1C3C2}

var ASN1DecrypterOpts = &DecrypterOpts{ENCODING_ASN1, C1C3C2}

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed.
var directSigning crypto.Hash = 0

// Signer SM2 special signer
type Signer interface {
	SignWithSM2(rand io.Reader, uid, msg []byte) ([]byte, error)
}

// SM2SignerOption implements crypto.SignerOpts interface.
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

// FromECPrivateKey convert an ecdsa private key to SM2 private key.
func (priv *PrivateKey) FromECPrivateKey(key *ecdsa.PrivateKey) (*PrivateKey, error) {
	if key.Curve != sm2ec.P256() {
		return nil, errors.New("sm2: it's NOT a sm2 curve private key")
	}
	priv.PrivateKey = *key
	return priv, nil
}

func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.PublicKey.Equal(&xx.PublicKey) && bigIntEqual(priv.D, xx.D)
}

// bigIntEqual reports whether a and b are equal leaking only their bit length
// through timing side-channels.
func bigIntEqual(a, b *big.Int) bool {
	return _subtle.ConstantTimeCompare(a.Bytes(), b.Bytes()) == 1
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

// Decrypt decrypts ciphertext msg to plaintext.
// The opts argument should be appropriate for the primitive used.
// Compliance with GB/T 32918.4-2016 chapter 7.
func (priv *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	var sm2Opts *DecrypterOpts
	sm2Opts, _ = opts.(*DecrypterOpts)
	return decrypt(priv, msg, sm2Opts)
}

const maxRetryLimit = 100

var (
	errCiphertextTooShort = errors.New("sm2: ciphertext too short")
)

// EncryptASN1 sm2 encrypt and output ASN.1 result, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return Encrypt(random, pub, msg, ASN1EncrypterOpts)
}

// Encrypt sm2 encrypt implementation, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	//A3, requirement is to check if h*P is infinite point, h is 1
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: public key point is the infinity")
	}
	if len(msg) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	switch pub.Curve.Params() {
	case P256().Params():
		return encryptSM2EC(p256(), pub, random, msg, opts)
	default:
		return encryptLegacy(random, pub, msg, opts)
	}
}

func encryptSM2EC(c *sm2Curve, pub *ecdsa.PublicKey, random io.Reader, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	var retryCount int = 0
	for {
		k, C1, err := randomPoint(c, random, false)
		if err != nil {
			return nil, err
		}
		C2, err := Q.ScalarMult(Q, k.Bytes(c.N))
		if err != nil {
			return nil, err
		}
		C2Bytes := C2.Bytes()[1:]
		c2 := kdf.Kdf(sm3.New(), C2Bytes, len(msg))
		if subtle.ConstantTimeAllZero(c2) {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}
		//A6, C2 = M + t;
		subtle.XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		md := sm3.New()
		md.Write(C2Bytes[:len(C2Bytes)/2])
		md.Write(msg)
		md.Write(C2Bytes[len(C2Bytes)/2:])
		c3 := md.Sum(nil)

		if opts.ciphertextEncoding == ENCODING_PLAIN {
			return encodingCiphertext(opts, C1, c2, c3)
		}
		return encodingCiphertextASN1(C1, c2, c3)
	}
}

func encodingCiphertext(opts *EncrypterOpts, C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	var c1 []byte
	switch opts.pointMarshalMode {
	case MarshalCompressed:
		c1 = C1.BytesCompressed()
	default:
		c1 = C1.Bytes()
	}

	if opts.ciphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	// c1 || c2 || c3
	return append(append(c1, c2...), c3...), nil
}

func encodingCiphertextASN1(C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	c1 := C1.Bytes()
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, c1[1:len(c1)/2+1])
		addASN1IntBytes(b, c1[len(c1)/2+1:])
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// GenerateKey generates a new SM2 private key.
//
// Most applications should use [crypto/rand.Reader] as rand. Note that the
// returned key does not depend deterministically on the bytes read from rand,
// and may change between calls and/or between versions.
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

// NewPrivateKeyFromInt checks that key is valid and returns a SM2 PrivateKey.
func NewPrivateKeyFromInt(key *big.Int) (*PrivateKey, error) {
	if key == nil {
		return nil, errors.New("sm2: invalid private key size")
	}
	keyBytes := make([]byte, p256().N.Size())
	return NewPrivateKey(key.FillBytes(keyBytes))
}

// NewPublicKey checks that key is valid and returns a PublicKey.
func NewPublicKey(key []byte) (*ecdsa.PublicKey, error) {
	c := p256()
	// Reject the point at infinity and compressed encodings.
	if len(key) == 0 || key[0] != 4 {
		return nil, errors.New("sm2: invalid public key")
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

// Decrypt sm2 decrypt implementation by default DecrypterOpts{C1C3C2}.
// Compliance with GB/T 32918.4-2016.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, nil)
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("sm2: decryption error")

func decrypt(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errCiphertextTooShort
	}
	switch priv.Curve.Params() {
	case P256().Params():
		return decryptSM2EC(p256(), priv, ciphertext, opts)
	default:
		return decryptLegacy(priv, ciphertext, opts)
	}
}

func decryptSM2EC(c *sm2Curve, priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	C1, c2, c3, err := parseCiphertext(c, ciphertext, opts)
	if err != nil {
		return nil, ErrDecryption
	}
	d, err := bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, ErrDecryption
	}

	C2, err := C1.ScalarMult(C1, d.Bytes(c.N))
	if err != nil {
		return nil, ErrDecryption
	}
	C2Bytes := C2.Bytes()[1:]
	msgLen := len(c2)
	msg := kdf.Kdf(sm3.New(), C2Bytes, msgLen)
	if subtle.ConstantTimeAllZero(c2) {
		return nil, ErrDecryption
	}

	//B5, calculate msg = c2 ^ t
	subtle.XORBytes(msg, c2, msg)

	md := sm3.New()
	md.Write(C2Bytes[:len(C2Bytes)/2])
	md.Write(msg)
	md.Write(C2Bytes[len(C2Bytes)/2:])
	u := md.Sum(nil)

	if _subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func parseCiphertext(c *sm2Curve, ciphertext []byte, opts *DecrypterOpts) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	bitSize := c.curve.Params().BitSize
	// Encode the coordinates and let SetBytes reject invalid points.
	byteLen := (bitSize + 7) / 8
	splicingOrder := C1C3C2
	if opts != nil {
		splicingOrder = opts.cipherTextSplicingOrder
	}

	b := ciphertext[0]
	switch b {
	case uncompressed:
		if len(ciphertext) <= 1+2*byteLen+sm3.Size {
			return nil, nil, nil, errCiphertextTooShort
		}
		C1, err := c.newPoint().SetBytes(ciphertext[:1+2*byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+2*byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case compressed02, compressed03:
		C1, err := c.newPoint().SetBytes(ciphertext[:1+byteLen])
		if err != nil {
			return nil, nil, nil, err
		}
		c2, c3 := parseCiphertextC2C3(ciphertext[1+byteLen:], splicingOrder)
		return C1, c2, c3, nil
	case byte(0x30):
		return parseCiphertextASN1(c, ciphertext)
	default:
		return nil, nil, nil, errors.New("sm2: invalid/unsupport ciphertext format")
	}
}

func parseCiphertextC2C3(ciphertext []byte, order ciphertextSplicingOrder) ([]byte, []byte) {
	if order == C1C3C2 {
		return ciphertext[sm3.Size:], ciphertext[:sm3.Size]
	}
	return ciphertext[:len(ciphertext)-sm3.Size], ciphertext[len(ciphertext)-sm3.Size:]
}

func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("sm2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

func parseCiphertextASN1(c *sm2Curve, ciphertext []byte) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	C1, err := c.pointFromAffine(x1, y1)
	if err != nil {
		return nil, nil, nil, err
	}
	return C1, c2, c3, nil
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5.
//
// This function will not use default UID even the uid argument is empty.
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("sm2: the uid is too long")
	}
	entla := uint16(uidLen) << 3
	md := sm3.New()
	md.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		md.Write(uid)
	}
	a := new(big.Int).Sub(pub.Params().P, big.NewInt(3))
	md.Write(toBytes(pub.Curve, a))
	md.Write(toBytes(pub.Curve, pub.Params().B))
	md.Write(toBytes(pub.Curve, pub.Params().Gx))
	md.Write(toBytes(pub.Curve, pub.Params().Gy))
	md.Write(toBytes(pub.Curve, pub.X))
	md.Write(toBytes(pub.Curve, pub.Y))
	return md.Sum(nil), nil
}

// CalculateSM2Hash calculates hash value for data including uid and public key parameters
// according standards.
//
// uid can be nil, then it will use default uid (1234567812345678)
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

func (priv *PrivateKey) inverseOfPrivateKeyPlus1(c *sm2Curve) (*bigmod.Nat, error) {
	var (
		err            error
		dp1Inv, oneNat *bigmod.Nat
		dp1Bytes       []byte
	)
	priv.inverseOfkeyPlus1Once.Do(func() {
		oneNat, _ = bigmod.NewNat().SetBytes(one.Bytes(), c.N)
		dp1Inv, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err == nil {
			dp1Inv.Add(oneNat, c.N)
			if dp1Inv.IsZero() == 1 { // make sure private key is NOT N-1
				err = errInvalidPrivateKey
			} else {
				dp1Bytes, err = _sm2ec.P256OrdInverse(dp1Inv.Bytes(c.N))
				if err == nil {
					priv.inverseOfkeyPlus1, err = bigmod.NewNat().SetBytes(dp1Bytes, c.N)
				}
			}
		}
	})
	if err != nil {
		return nil, errInvalidPrivateKey
	}
	return priv.inverseOfkeyPlus1, nil
}

func signSM2EC(c *sm2Curve, priv *PrivateKey, rand io.Reader, hash []byte) (sig []byte, err error) {
	// get/compute inv(d+1)
	dp1Inv, err := priv.inverseOfPrivateKeyPlus1(c)
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
			r.Add(e, c.N) // r = (Rx + e) mod N
			if r.IsZero() == 0 {
				t := bigmod.NewNat().Set(k)
				t.Add(r, c.N)
				if t.IsZero() == 0 { // if (r + k) != N then ok
					break
				}
			}
		}
		s, err = bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
		if err != nil {
			return nil, err
		}
		s.Mul(r, c.N)
		k.Sub(s, c.N)
		k.Mul(dp1Inv, c.N)
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

	t := bigmod.NewNat().Set(r)
	t.Add(s, c.N)
	if t.IsZero() == 1 {
		return false
	}

	p1, err := c.newPoint().ScalarBaseMult(s.Bytes(c.N))
	if err != nil {
		return false
	}
	p2, err := Q.ScalarMult(Q, t.Bytes(c.N))
	if err != nil {
		return false
	}

	Rx, err := p1.Add(p1, p2).BytesX()
	if err != nil {
		return false
	}

	v, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return false
	}

	v.Add(e, c.N)
	return v.Equal(r) == 1
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

// IsSM2PublicKey check if given public key is a SM2 public key or not
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
		return nil, errors.New("sm2: invalid public key")
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
		return nil, errors.New("sm2: invalid private key")
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

type sm2Curve struct {
	newPoint func() *_sm2ec.SM2P256Point
	curve    elliptic.Curve
	N        *bigmod.Modulus
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
	c.N, _ = bigmod.NewModulusFromBig(params.N)
	c.nMinus2 = new(big.Int).Sub(params.N, big.NewInt(2)).Bytes()
	c.nMinus1, _ = bigmod.NewNat().SetBytes(new(big.Int).Sub(params.N, big.NewInt(1)).Bytes(), c.N)
}

var errInvalidPrivateKey = errors.New("sm2: invalid private key")
