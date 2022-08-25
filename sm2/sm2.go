// Package sm2 handle shangmi sm2 digital signature and public key encryption algorithm and its curve implementation
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/internal/randutil"
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

// A invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// A combinedMult implements fast combined multiplication for verification.
type combinedMult interface {
	// CombinedMult returns [s1]G + [s2]P where G is the generator.
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

// PrivateKey represents an ECDSA SM2 private key.
// It implemented both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
	ecdsa.PrivateKey
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
	CiphertextEncoding      ciphertextEncoding
	PointMarshalMode        pointMarshalMode
	CiphertextSplicingOrder ciphertextSplicingOrder
}

// DecrypterOpts decryption options
type DecrypterOpts struct {
	CiphertextEncoding      ciphertextEncoding
	CipherTextSplicingOrder ciphertextSplicingOrder
}

func NewPlainEncrypterOpts(marhsalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{ENCODING_PLAIN, marhsalMode, splicingOrder}
}

func NewPlainDecrypterOpts(splicingOrder ciphertextSplicingOrder) *DecrypterOpts {
	return &DecrypterOpts{ENCODING_PLAIN, splicingOrder}
}

func (mode pointMarshalMode) mashal(curve elliptic.Curve, x, y *big.Int) []byte {
	switch mode {
	case MarshalCompressed:
		return elliptic.MarshalCompressed(curve, x, y)
	case MarshalHybrid:
		buffer := elliptic.Marshal(curve, x, y)
		buffer[0] = byte(y.Bit(0)) | hybrid06
		return buffer
	default:
		return elliptic.Marshal(curve, x, y)
	}
}

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	result := make([]byte, byteLen)
	value.FillBytes(result)
	return result
}

func bytes2Point(curve elliptic.Curve, bytes []byte) (*big.Int, *big.Int, int, error) {
	if len(bytes) < 1+(curve.Params().BitSize/8) {
		return nil, nil, 0, fmt.Errorf("sm2: invalid bytes length %d", len(bytes))
	}
	format := bytes[0]
	byteLen := (curve.Params().BitSize + 7) >> 3
	switch format {
	case uncompressed, hybrid06, hybrid07: // what's the hybrid format purpose?
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point uncompressed/hybrid form bytes length %d", len(bytes))
		}
		data := make([]byte, 1+byteLen*2)
		data[0] = uncompressed
		copy(data[1:], bytes[1:1+byteLen*2])
		x, y := sm2ec.Unmarshal(curve, data)
		if x == nil || y == nil {
			return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case compressed02, compressed03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("sm2: invalid point compressed form bytes length %d", len(bytes))
		}
		// Make sure it's NIST curve or SM2 P-256 curve
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, sm2ec.P256().Params().Name) {
			// y² = x³ - 3x + b, prime curves
			x, y := sm2ec.UnmarshalCompressed(curve, bytes[:1+byteLen])
			if x == nil || y == nil {
				return nil, nil, 0, fmt.Errorf("sm2: point is not on curve %s", curve.Params().Name)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("sm2: unsupport point form %d, curve %s", format, curve.Params().Name)
	}
	return nil, nil, 0, fmt.Errorf("sm2: unknown point form %d", format)
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
	UID         []byte
	ForceGMSign bool
}

// NewSM2SignerOption create a SM2 specific signer option.
// forceGMSign - if use GM specific sign logic, if yes, should pass raw message to sign.
// uid - if forceGMSign is true, then you can pass uid, if no uid is provided, system will use default one.
func NewSM2SignerOption(forceGMSign bool, uid []byte) *SM2SignerOption {
	opt := &SM2SignerOption{
		UID:         uid,
		ForceGMSign: forceGMSign,
	}
	if forceGMSign && len(uid) == 0 {
		opt.UID = defaultUID
	}
	return opt
}

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
	return priv.PublicKey.Equal(&xx.PublicKey) && priv.D.Cmp(xx.D) == 0
}

// Sign signs digest with priv, reading randomness from rand. Compliance with GB/T 32918.2-2016.
// The opts argument is currently used for SM2SignerOption checking only.
// If the opts argument is SM2SignerOption and its ForceGMSign is true,
// digest argument will be treated as raw data and UID will be taken from opts.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses can use the SignASN1 function in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var r, s *big.Int
	var err error
	if sm2Opts, ok := opts.(*SM2SignerOption); ok && sm2Opts.ForceGMSign {
		r, s, err = SignWithSM2(rand, &priv.PrivateKey, sm2Opts.UID, digest)
	} else {
		r, s, err = Sign(rand, &priv.PrivateKey, digest)
	}
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
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

var (
	one = new(big.Int).SetInt64(1)
)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8) // (N + 64) / 8 = （256 + 64） / 8
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b) // 5.Convert returned_bits to the (non-negtive) integrer c
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one) // 6. k = (c mod (n-1)) + 1, here n = params.N
	return
}

const maxRetryLimit = 100

func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	md := sm3.New()
	md.Write(toBytes(curve, x2))
	md.Write(msg)
	md.Write(toBytes(curve, y2))
	return md.Sum(nil)
}

func mashalASN1Ciphertext(x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(x1)
		b.AddASN1BigInt(y1)
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// EncryptASN1 sm2 encrypt and output ASN.1 result, compliance with GB/T 32918.4-2016.
func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return Encrypt(random, pub, msg, ASN1EncrypterOpts)
}

// Encrypt sm2 encrypt implementation, compliance with GB/T 32918.4-2016.
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)
	if msgLen == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	//A3, requirement is to check if h*P is infinite point, h is 1
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: invalid public key")
	}
	for {
		//A1, generate random k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := opts.PointMarshalMode.mashal(curve, x1, y1)

		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		var kdfCount int = 0
		c2 := kdf.Kdf(sm3.New(), append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if subtle.ConstantTimeAllZero(c2) {
			kdfCount++
			if kdfCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", kdfCount)
			}
			continue
		}

		//A6, C2 = M + t;
		subtle.XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		c3 := calculateC3(curve, x2, y2, msg)

		if opts.CiphertextEncoding == ENCODING_PLAIN {
			if opts.CiphertextSplicingOrder == C1C3C2 {
				// c1 || c3 || c2
				return append(append(c1, c3...), c2...), nil
			}
			// c1 || c2 || c3
			return append(append(c1, c2...), c3...), nil
		}
		// ASN.1 format will force C3 C2 order
		return mashalASN1Ciphertext(x1, y1, c2, c3)
	}
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := sm2ec.P256()
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// Decrypt sm2 decrypt implementation by default DecrypterOpts{C1C3C2}.
// Compliance with GB/T 32918.4-2016.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, nil)
}

func decryptASN1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	return rawDecrypt(priv, x1, y1, c2, c3)
}

func rawDecrypt(priv *PrivateKey, x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	curve := priv.Curve
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	msg := kdf.Kdf(sm3.New(), append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if subtle.ConstantTimeAllZero(c2) {
		return nil, errors.New("sm2: invalid cipher text")
	}

	//B5, calculate msg = c2 ^ t
	subtle.XORBytes(msg, c2, msg)

	u := calculateC3(curve, x2, y2, msg)
	for i := 0; i < sm3.Size; i++ {
		if c3[i] != u[i] {
			return nil, errors.New("sm2: invalid hash value")
		}
	}
	return msg, nil
}

func decrypt(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	splicingOrder := C1C3C2
	if opts != nil {
		if opts.CiphertextEncoding == ENCODING_ASN1 {
			return decryptASN1(priv, ciphertext)
		}
		splicingOrder = opts.CipherTextSplicingOrder
	}
	if ciphertext[0] == 0x30 {
		return decryptASN1(priv, ciphertext)
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("sm2: invalid ciphertext length")
	}
	curve := priv.Curve
	// B1, get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	//B4, calculate t=KDF(x2||y2, klen)
	var c2, c3 []byte
	if splicingOrder == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}

	return rawDecrypt(priv, x1, y1, c2, c3)
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

// ASN1Ciphertext2Plain utility method to convert ASN.1 encoding ciphertext to plain encoding format
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext((ciphertext))
	if err != nil {
		return nil, err
	}
	curve := sm2ec.P256()
	c1 := opts.PointMarshalMode.mashal(curve, x1, y1)
	if opts.CiphertextSplicingOrder == C1C3C2 {
		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
	// c1 || c2 || c3
	return append(append(c1, c2...), c3...), nil
}

// PlainCiphertext2ASN1 utility method to convert plain encoding ciphertext to ASN.1 encoding format
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	if ciphertext[0] == 0x30 {
		return nil, errors.New("sm2: invalid plain encoding ciphertext")
	}
	curve := sm2ec.P256()
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("sm2: invalid ciphertext length")
	}
	// get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c2, c3 []byte

	if from == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}
	return mashalASN1Ciphertext(x1, y1, c2, c3)
}

// AdjustCiphertextSplicingOrder utility method to change c2 c3 order
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	curve := sm2ec.P256()
	if from == to {
		return ciphertext, nil
	}
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(curve.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("sm2: invalid ciphertext length")
	}

	// get C1, and check C1
	_, _, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	var c1, c2, c3 []byte

	c1 = ciphertext[:c3Start]
	if from == C1C3C2 {
		c2 = ciphertext[c3Start+sm3.Size:]
		c3 = ciphertext[c3Start : c3Start+sm3.Size]
	} else {
		c2 = ciphertext[c3Start : ciphertextLen-sm3.Size]
		c3 = ciphertext[ciphertextLen-sm3.Size:]
	}

	result := make([]byte, ciphertextLen)
	copy(result, c1)
	if to == C1C3C2 {
		// c1 || c3 || c2
		copy(result[c3Start:], c3)
		copy(result[c3Start+sm3.Size:], c2)
	} else {
		// c1 || c2 || c3
		copy(result[c3Start:], c2)
		copy(result[ciphertextLen-sm3.Size:], c3)
	}
	return result, nil
}

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

const (
	aesIV = "IV for ECDSA CTR"
)

var errZeroParam = errors.New("zero parameter")

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// SignASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	randutil.MaybeReadByte(rand)

	// We use SDK's nouce generation implementation here.
	//
	// This implementation derives the nonce from an AES-CTR CSPRNG keyed by:
	//
	//    SHA2-512(priv.D || entropy || hash)[:32]
	//
	// The CSPRNG key is indifferentiable from a random oracle as shown in
	// [Coron], the AES-CTR stream is indifferentiable from a random oracle
	// under standard cryptographic assumptions (see [Larsson] for examples).
	//
	// [Coron]: https://cs.nyu.edu/~dodis/ps/merkle.pdf
	// [Larsson]: https://web.archive.org/web/20040719170906/https://www.nada.kth.se/kurser/kth/2D1441/semteo03/lecturenotes/assump.pdf

	// Get 256 bits of entropy from rand.
	entropy := make([]byte, 32)

	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	return signGeneric(priv, &csprng, hash)
}

func signGeneric(priv *ecdsa.PrivateKey, csprng *cipher.StreamReader, hash []byte) (r, s *big.Int, err error) {
	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	e := hashToInt(hash, c)
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes()) // (x, y) = k*G
			r.Add(r, e)                                 // r = x + e
			r.Mod(r, N)                                 // r = (x + e) mod N
			if r.Sign() != 0 {
				t := new(big.Int).Add(r, k)
				if t.Cmp(N) != 0 { // if r != 0 && (r + k) != N then ok
					break
				}
			}
		}
		s = new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, s)
		dp1 := new(big.Int).Add(priv.D, one)

		var dp1Inv *big.Int

		if in, ok := priv.Curve.(invertible); ok {
			dp1Inv = in.Inverse(dp1)
		} else {
			dp1Inv = fermatInverse(dp1, N) // N != 0
		}

		s.Mul(s, dp1Inv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA).
// Compliance with GB/T 32918.2-2016 5.5
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	return calculateZA(pub, uid)
}

// calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func calculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
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

// SignWithSM2 follow sm2 dsa standards for hash part, compliance with GB/T 32918.2-2016.
func SignWithSM2(rand io.Reader, priv *ecdsa.PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := calculateZA(&priv.PublicKey, uid)
	if err != nil {
		return nil, nil, err
	}
	md := sm3.New()
	md.Write(za)
	md.Write(msg)

	return Sign(rand, priv, md.Sum(nil))
}

// SignASN1 signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the ASN.1 encoded signature.
// It invokes priv.Sign directly.
func SignASN1(rand io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.Sign(rand, hash, opts)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, c)
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)
	}

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// VerifyASN1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness.
func VerifyASN1(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return Verify(pub, hash, r, s)
}

// VerifyWithSM2 verifies the signature in r, s of raw msg and uid using the public key, pub.
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyWithSM2(pub *ecdsa.PublicKey, uid, msg []byte, r, s *big.Int) bool {
	if len(uid) == 0 {
		uid = defaultUID
	}
	za, err := calculateZA(pub, uid)
	if err != nil {
		return false
	}
	md := sm3.New()
	md.Write(za)
	md.Write(msg)
	return Verify(pub, md.Sum(nil), r, s)
}

// VerifyASN1WithSM2 verifies the signature in ASN.1 encoding format sig of raw msg
// and uid using the public key, pub.
//
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyASN1WithSM2(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool {
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return false
	}
	return VerifyWithSM2(pub, uid, msg, r, s)
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

// IsSM2PublicKey check if given public key is a SM2 public key or not
func IsSM2PublicKey(publicKey interface{}) bool {
	pub, ok := publicKey.(*ecdsa.PublicKey)
	return ok && pub.Curve == sm2ec.P256()
}

// P256 return sm2 curve signleton, this function is for backward compatibility.
func P256() elliptic.Curve {
	return sm2ec.P256()
}
