package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	_subtle "crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file contains a math/big implementation of SM2 DSA/Encryption that is only used for
// deprecated custom curves.

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

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. Most applications should use
// SignASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	key := new(PrivateKey)
	key.PrivateKey = *priv
	sig, err := SignASN1(rand, key, hash, nil)
	if err != nil {
		return nil, nil, err
	}

	r, s = new(big.Int), new(big.Int)
	var inner cryptobyte.String
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		return nil, nil, errors.New("invalid ASN.1 from SignASN1")
	}
	return r, s, nil
}

func signLegacy(priv *PrivateKey, rand io.Reader, hash []byte) (sig []byte, err error) {
	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	var k, r, s *big.Int
	e := hashToInt(hash, c)
	for {
		for {
			k, err = randFieldElement(c, rand)
			if err != nil {
				return nil, err
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

	return encodeSignature(r.Bytes(), s.Bytes())
}

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

// SignWithSM2 follow sm2 dsa standards for hash part, compliance with GB/T 32918.2-2016.
func SignWithSM2(rand io.Reader, priv *ecdsa.PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	digest, err := CalculateSM2Hash(&priv.PublicKey, msg, uid)
	if err != nil {
		return nil, nil, err
	}

	return Sign(rand, priv, digest)
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid. Most applications should
// use VerifyASN1 instead of dealing directly with r, s.
//
// Compliance with GB/T 32918.2-2016 regardless it's SM2 curve or not.
// Caller should make sure the hash's correctness.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	sig, err := encodeSignature(r.Bytes(), s.Bytes())
	if err != nil {
		return false
	}
	return VerifyASN1(pub, hash, sig)
}

func verifyLegacy(pub *ecdsa.PublicKey, hash, sig []byte) bool {
	rBytes, sBytes, err := parseSignature(sig)
	if err != nil {
		return false
	}
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)

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

// VerifyWithSM2 verifies the signature in r, s of raw msg and uid using the public key, pub.
// It returns value records whether the signature is valid. Compliance with GB/T 32918.2-2016.
func VerifyWithSM2(pub *ecdsa.PublicKey, uid, msg []byte, r, s *big.Int) bool {
	digest, err := CalculateSM2Hash(pub, msg, uid)
	if err != nil {
		return false
	}
	return Verify(pub, digest, r, s)
}

var (
	one = new(big.Int).SetInt64(1)
)

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	// See randomPoint for notes on the algorithm. This has to match, or s390x
	// signatures will come out different from other architectures, which will
	// break TLS recorded tests.
	for {
		N := c.Params().N
		b := make([]byte, (N.BitLen()+7)/8)
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}
		if excess := len(b)*8 - N.BitLen(); excess > 0 {
			b[0] >>= excess
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() != 0 && k.Cmp(N) < 0 {
			return
		}
	}
}

func encryptLegacy(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)

	var retryCount int = 0
	for {
		//A1, generate random k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := opts.pointMarshalMode.mashal(curve, x1, y1)

		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		c2 := sm3.Kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if subtle.ConstantTimeAllZero(c2) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
			}
			continue
		}

		//A6, C2 = M + t;
		subtle.XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		c3 := calculateC3(curve, x2, y2, msg)

		if opts.ciphertextEncoding == ENCODING_PLAIN {
			if opts.ciphertextSplicingOrder == C1C3C2 {
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
	c1 := opts.pointMarshalMode.mashal(curve, x1, y1)
	if opts.ciphertextSplicingOrder == C1C3C2 {
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
		return nil, errCiphertextTooShort
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
		return nil, errCiphertextTooShort
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

func decryptASN1(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, ErrDecryption
	}
	return rawDecrypt(priv, x1, y1, c2, c3)
}

func rawDecrypt(priv *PrivateKey, x1, y1 *big.Int, c2, c3 []byte) ([]byte, error) {
	curve := priv.Curve
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())
	msgLen := len(c2)
	msg := sm3.Kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if subtle.ConstantTimeAllZero(c2) == 1 {
		return nil, ErrDecryption
	}

	//B5, calculate msg = c2 ^ t
	subtle.XORBytes(msg, c2, msg)

	u := calculateC3(curve, x2, y2, msg)
	if _subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

func decryptLegacy(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	splicingOrder := C1C3C2
	if opts != nil {
		if opts.ciphertextEncoding == ENCODING_ASN1 {
			return decryptASN1(priv, ciphertext)
		}
		splicingOrder = opts.cipherTextSplicingOrder
	}
	if ciphertext[0] == 0x30 {
		return decryptASN1(priv, ciphertext)
	}
	ciphertextLen := len(ciphertext)
	curve := priv.Curve
	// B1, get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, ErrDecryption
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
