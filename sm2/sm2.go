package sm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/sm3"
)

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = 0x03
	mixed06      byte = 0x06
	mixed07      byte = 0x07
)

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	ecdsa.PrivateKey
}

// Sign signs digest with priv, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface,
// should be the hash function used to digest the message.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign function in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, &priv.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

///////////////// below code ship from golan crypto/ecdsa ////////////////////
var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

///////////////////////////////////////////////////////////////////////////////////
func kdf(z []byte, len int) ([]byte, bool) {
	limit := (len + sm3.Size - 1) >> sm3.SizeBitSize
	sm3Hasher := sm3.New()
	var countBytes [4]byte
	var ct uint32 = 1
	k := make([]byte, len+sm3.Size-1)
	for i := 0; i < limit; i++ {
		binary.BigEndian.PutUint32(countBytes[:], ct)
		sm3Hasher.Write(z)
		sm3Hasher.Write(countBytes[:])
		copy(k[i*sm3.Size:], sm3Hasher.Sum(nil))
		ct++
		sm3Hasher.Reset()
	}
	for i := 0; i < len; i++ {
		if k[i] != 0 {
			return k[:len], true
		}
	}
	return k, false
}

func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	hasher := sm3.New()
	hasher.Write(toBytes(curve, x2))
	hasher.Write(msg)
	hasher.Write(toBytes(curve, y2))
	return hasher.Sum(nil)
}

// Encrypt sm2 encrypt implementation
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)
	for {
		//A1, generate random k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := point2UncompressedBytes(curve, x1, y1)

		//A3, skipped
		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if !success {
			fmt.Println("A5, failed to get valid t")
			continue
		}

		//A6, C2 = M + t;
		c2 := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			c2[i] = msg[i] ^ t[i]
		}

		//A7, C3 = hash(x2||M||y2)
		c3 := calculateC3(curve, x2, y2, msg)

		// c1 || c3 || c2
		return append(append(c1, c3...), c2...), nil
	}
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256()
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

// Decrypt sm2 decrypt implementation
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("invalid ciphertext length")
	}
	curve := priv.Curve
	// B1, get C1, and check C1
	x1, y1, c3Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}

	//B2 is ignored
	//B3, calculate x2, y2
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())

	//B4, calculate t=KDF(x2||y2, klen)
	c2 := ciphertext[c3Start+sm3.Size:]
	msgLen := len(c2)
	t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if !success {
		return nil, errors.New("invalid cipher text")
	}

	//B5, calculate msg = c2 ^ t
	msg := make([]byte, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c2[i] ^ t[i]
	}

	//B6, calculate hash and compare it
	c3 := ciphertext[c3Start : c3Start+sm3.Size]
	u := calculateC3(curve, x2, y2, msg)
	for i := 0; i < sm3.Size; i++ {
		if c3[i] != u[i] {
			return nil, errors.New("invalid hash value")
		}
	}

	return msg, nil
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
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

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	if !strings.EqualFold(priv.Params().Name, P256().Params().Name) {
		return ecdsa.Sign(rand, priv, hash)
	}
	maybeReadByte(rand)

	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
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
		dp1Inv := new(big.Int).ModInverse(dp1, N)
		s.Mul(s, dp1Inv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}

var defaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

// CalculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
func CalculateZA(pub *ecdsa.PublicKey, uid []byte) ([]byte, error) {
	uidLen := len(uid)
	if uidLen >= 0x2000 {
		return nil, errors.New("the uid is too long")
	}
	entla := uint16(uidLen) << 3
	hasher := sm3.New()
	hasher.Write([]byte{byte(entla >> 8), byte(entla)})
	if uidLen > 0 {
		hasher.Write(uid)
	}
	a := new(big.Int).Sub(pub.Params().P, big.NewInt(3))
	hasher.Write(toBytes(pub.Curve, a))
	hasher.Write(toBytes(pub.Curve, pub.Params().B))
	hasher.Write(toBytes(pub.Curve, pub.Params().Gx))
	hasher.Write(toBytes(pub.Curve, pub.Params().Gy))
	hasher.Write(toBytes(pub.Curve, pub.X))
	hasher.Write(toBytes(pub.Curve, pub.Y))
	return hasher.Sum(nil), nil
}

// SignWithSM2 follow sm2 dsa standards for hash part
func SignWithSM2(rand io.Reader, priv *ecdsa.PrivateKey, uid, msg []byte) (r, s *big.Int, err error) {
	za, err := CalculateZA(&priv.PublicKey, uid)
	if err != nil {
		return nil, nil, err
	}
	hasher := sm3.New()
	hasher.Write(za)
	hasher.Write(msg)

	return Sign(rand, priv, hasher.Sum(nil))
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	if strings.EqualFold(pub.Params().Name, P256().Params().Name) {
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
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)

		x.Add(x, e)
		x.Mod(x, N)
		return x.Cmp(r) == 0
	}
	return ecdsa.Verify(pub, hash, r, s)
}

// VerifyWithSM2 verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func VerifyWithSM2(pub *ecdsa.PublicKey, uid, msg []byte, r, s *big.Int) bool {
	za, err := CalculateZA(pub, uid)
	if err != nil {
		return false
	}
	hasher := sm3.New()
	hasher.Write(za)
	hasher.Write(msg)
	return Verify(pub, hasher.Sum(nil), r, s)
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
