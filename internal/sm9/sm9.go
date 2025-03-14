// Package sm9 implements ShangMi(SM) sm9 digital signature, encryption and key exchange algorithms.
package sm9

import (
	"crypto"
	goSubtle "crypto/subtle"
	"errors"
	"io"

	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/internal/randutil"
	"github.com/emmansun/gmsm/internal/sm3"
	"github.com/emmansun/gmsm/internal/sm9/bn256"
	"github.com/emmansun/gmsm/internal/subtle"
)

// SM9 ASN.1 format reference: Information security technology - SM9 cryptographic algorithm application specification
var (
	orderNat *bigmod.Modulus
)

func init() {
	orderNat, _ = bigmod.NewModulus(bn256.OrderBytes)
}

type hashMode byte

const (
	// hashmode used in h1: 0x01
	H1 hashMode = 1 + iota
	// hashmode used in h2: 0x02
	H2
)

// hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func hash(z []byte, h hashMode) *bigmod.Nat {
	md := sm3.New()
	var ha [64]byte
	var countBytes [4]byte
	var ct uint32 = 1

	byteorder.BEPutUint32(countBytes[:], ct)
	md.Write([]byte{byte(h)})
	md.Write(z)
	md.Write(countBytes[:])
	copy(ha[:], md.Sum(nil))
	ct++
	md.Reset()

	byteorder.BEPutUint32(countBytes[:], ct)
	md.Write([]byte{byte(h)})
	md.Write(z)
	md.Write(countBytes[:])
	copy(ha[sm3.Size:], md.Sum(nil))

	return bigmod.NewNat().SetOverflowedBytes(ha[:40], orderNat)
}

func hashH1(z []byte) *bigmod.Nat {
	return hash(z, H1)
}

func hashH2(z []byte) *bigmod.Nat {
	return hash(z, H2)
}

func randomScalar(rand io.Reader) (k *bigmod.Nat, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, orderNat.Size())
		if _, err = io.ReadFull(rand, b); err != nil {
			return
		}

		// Mask off any excess bits to increase the chance of hitting a value in
		// (0, N). These are the most dangerous lines in the package and maybe in
		// the library: a single bit of bias in the selection of nonces would likely
		// lead to key recovery, but no tests would fail. Look but DO NOT TOUCH.
		if excess := len(b)*8 - orderNat.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if excess != 0 {
				panic("sm9: internal error: unexpectedly masking off bits")
			}
			b[0] >>= excess
		}

		// FIPS 186-4 makes us check k <= N - 2 and then add one.
		// Checking 0 < k <= N - 1 is strictly equivalent.
		// None of this matters anyway because the chance of selecting
		// zero is cryptographically negligible.
		if _, err = k.SetBytes(b, orderNat); err == nil && k.IsZero() == 0 {
			break
		}
	}
	return
}

// Sign signs digest with user's DSA key, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface.
//
// The signature is randomized. Most applications should use [crypto/rand.Reader]
// as rand. Note that the returned signature does not depend deterministically on
// the bytes read from rand, and may change between calls and/or between versions.
func (priv *SignPrivateKey) Sign(rand io.Reader, hash []byte, opts crypto.SignerOpts) (h []byte, S []byte, err error) {
	var (
		hNat *bigmod.Nat
		s    *bn256.G1
	)
	randutil.MaybeReadByte(rand)
	for {
		r, err := randomScalar(rand)
		if err != nil {
			return nil, nil, err
		}

		w, err := priv.SignMasterPublicKey.ScalarBaseMult(r.Bytes(orderNat))
		if err != nil {
			return nil, nil, err
		}

		buffer := append(append([]byte{}, hash...), w.Marshal()...)

		hNat = hashH2(buffer)
		r.Sub(hNat, orderNat)

		if r.IsZero() == 0 { // r != 0
			s, err = new(bn256.G1).ScalarMult(priv.PrivateKey, r.Bytes(orderNat))
			if err != nil {
				return nil, nil, err
			}
			break
		}
	}
	h = hNat.Bytes(orderNat)
	S = s.MarshalUncompressed()
	return
}

// Verify checks the validity of a signature using the provided parameters.
func (pub *SignMasterPublicKey) Verify(uid []byte, hid byte, hash, h, S []byte) bool {
	sPoint := new(bn256.G1)
	if len(S) == len(bn256.OrderMinus1Bytes)+1 && S[0] != 0x04 {
		return false
	}
	_, err := sPoint.Unmarshal(S[1:])
	if err != nil || !sPoint.IsOnCurve() {
		return false
	}
	hNat, err := bigmod.NewNat().SetBytes(h, orderNat)
	if err != nil || hNat.IsZero() == 1 {
		return false
	}
	t, err := pub.ScalarBaseMult(hNat.Bytes(orderNat))
	if err != nil {
		return false
	}

	// user sign public key p generation
	p := pub.GenerateUserPublicKey(uid, hid)

	u := bn256.Pair(sPoint, p)
	w := new(bn256.GT).Add(u, t)

	var buffer []byte
	buffer = append(append(buffer, hash...), w.Marshal()...)
	h2 := hashH2(buffer)

	return h2.Equal(hNat) == 1
}

// WrapKey generates a wrapped key and its corresponding ciphertext.
//
// Parameters:
// - rand: an io.Reader used to generate random values.
// - uid: a byte slice representing the user ID.
// - hid: a byte representing the hash ID.
// - kLen: an integer specifying the desired key length.
//
// Returns:
// - A byte slice containing the generated key.
// - A byte slice containing the uncompressed ciphertext.
// - An error if any occurs during the key wrapping process.
func (pub *EncryptMasterPublicKey) WrapKey(rand io.Reader, uid []byte, hid byte, kLen int) (key []byte, cipher []byte, err error) {
	q := pub.GenerateUserPublicKey(uid, hid)
	var (
		r *bigmod.Nat
		w *bn256.GT
		c *bn256.G1
	)
	for {
		r, err = randomScalar(rand)
		if err != nil {
			return nil, nil, err
		}

		rBytes := r.Bytes(orderNat)
		c, err = new(bn256.G1).ScalarMult(q, rBytes)
		if err != nil {
			return nil, nil, err
		}

		w, err = pub.ScalarBaseMult(rBytes)
		if err != nil {
			return nil, nil, err
		}
		var buffer []byte
		buffer = append(buffer, c.Marshal()...)
		buffer = append(buffer, w.Marshal()...)
		buffer = append(buffer, uid...)

		key = sm3.Kdf(buffer, kLen)
		if subtle.ConstantTimeAllZero(key) == 0 {
			break
		}
	}
	cipher = c.MarshalUncompressed()
	return
}

// UnwrapKey decrypts the given cipher text using the private key and user ID (uid).
// It returns the decrypted key of the specified length (kLen) or an error if decryption fails.
func (priv *EncryptPrivateKey) UnwrapKey(uid, cipher []byte, kLen int) (key []byte, err error) {
	numBytes := 2 * len(bn256.OrderBytes)
	if len(cipher) == numBytes+1 {
		if cipher[0] != 0x04 {
			return nil, ErrDecryption
		}
		cipher = cipher[1:]
	}
	if len(cipher) != numBytes {
		return nil, ErrDecryption
	}
	p := new(bn256.G1)
	_, err = p.Unmarshal(cipher)
	if err != nil || !p.IsOnCurve() {
		return nil, ErrDecryption
	}

	w := bn256.Pair(p, priv.PrivateKey)

	var buffer []byte
	buffer = append(buffer, cipher...)
	buffer = append(buffer, w.Marshal()...)
	buffer = append(buffer, uid...)

	key = sm3.Kdf(buffer, kLen)
	if subtle.ConstantTimeAllZero(key) == 1 {
		return nil, ErrDecryption
	}
	return
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("sm9: decryption error")

// KeyExchange represents key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> RepondKeyExchange -> transmission -> ConfirmInitiator
type KeyExchange struct {
	genSignature bool               // control the optional sign/verify step triggered by responsder
	keyLength    int                // key length
	privateKey   *EncryptPrivateKey // owner's encryption private key
	uid          []byte             // owner uid
	peerUID      []byte             // peer uid
	r            *bigmod.Nat        // random which will be used to compute secret
	secret       []byte             // generated secret which will be passed to peer
	peerSecret   []byte             // received peer's secret
	g1           *bn256.GT          // internal state which will be used when compute the key and signature
	g2           *bn256.GT          // internal state which will be used when compute the key and signature
	g3           *bn256.GT          // internal state which will be used when compute the key and signature
}

// NewKeyExchange creates one new KeyExchange object
func (priv *EncryptPrivateKey) NewKeyExchange(uid, peerUID []byte, keyLen int, genSignature bool) *KeyExchange {
	ke := &KeyExchange{}
	ke.genSignature = genSignature
	ke.keyLength = keyLen
	ke.privateKey = priv
	ke.uid = uid
	ke.peerUID = peerUID
	return ke
}

// Destroy clears all internal state and Ephemeral private/public keys
func (ke *KeyExchange) Destroy() {
	if ke.r != nil {
		ke.r.SetBytes([]byte{0}, orderNat)
	}
	if ke.g1 != nil {
		ke.g1.SetOne()
	}
	if ke.g2 != nil {
		ke.g2.SetOne()
	}
	if ke.g3 != nil {
		ke.g3.SetOne()
	}
}

func initKeyExchange(ke *KeyExchange, hid byte, r *bigmod.Nat) {
	pubB := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
	ke.r = r
	rA, err := new(bn256.G1).ScalarMult(pubB, ke.r.Bytes(orderNat))
	if err != nil {
		panic(err)
	}
	ke.secret = rA.MarshalUncompressed()
}

// InitKeyExchange generates random with responder uid, for initiator's step A1-A4
func (ke *KeyExchange) InitKeyExchange(rand io.Reader, hid byte) ([]byte, error) {
	r, err := randomScalar(rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, hid, r)
	return ke.secret, nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
	var buffer []byte
	hash := sm3.New()
	hash.Write(ke.g2.Marshal())
	hash.Write(ke.g3.Marshal())
	if isResponder {
		hash.Write(ke.peerUID)
		hash.Write(ke.uid)
		hash.Write(ke.peerSecret[1:])
		hash.Write(ke.secret[1:])
	} else {
		hash.Write(ke.uid)
		hash.Write(ke.peerUID)
		hash.Write(ke.secret[1:])
		hash.Write(ke.peerSecret[1:])
	}
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{prefix})
	hash.Write(ke.g1.Marshal())
	hash.Write(buffer)
	return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) ([]byte, error) {
	var buffer []byte
	if isResponder {
		buffer = append(buffer, ke.peerUID...)
		buffer = append(buffer, ke.uid...)
		buffer = append(buffer, ke.peerSecret[1:]...)
		buffer = append(buffer, ke.secret[1:]...)
	} else {
		buffer = append(buffer, ke.uid...)
		buffer = append(buffer, ke.peerUID...)
		buffer = append(buffer, ke.secret[1:]...)
		buffer = append(buffer, ke.peerSecret[1:]...)
	}
	buffer = append(buffer, ke.g1.Marshal()...)
	buffer = append(buffer, ke.g2.Marshal()...)
	buffer = append(buffer, ke.g3.Marshal()...)

	return sm3.Kdf(buffer, ke.keyLength), nil
}

func respondKeyExchange(ke *KeyExchange, hid byte, r *bigmod.Nat, rA []byte) ([]byte, []byte, error) {
	numBytes := 2 * len(bn256.OrderBytes)
	if len(rA) != numBytes+1 || rA[0] != 0x04 {
		return nil, nil, errors.New("sm9: invalid initiator's ephemeral public key")
	}
	rP := new(bn256.G1)
	_, err := rP.Unmarshal(rA[1:])
	if err != nil || !rP.IsOnCurve() {
		return nil, nil, errors.New("sm9: invalid initiator's ephemeral public key")
	}
	ke.peerSecret = rA
	pubA := ke.privateKey.GenerateUserPublicKey(ke.peerUID, hid)
	ke.r = r
	rBytes := r.Bytes(orderNat)
	rB, err := new(bn256.G1).ScalarMult(pubA, rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.secret = rB.MarshalUncompressed()

	ke.g1 = bn256.Pair(rP, ke.privateKey.PrivateKey)
	ke.g3 = &bn256.GT{}
	g3, err := bn256.ScalarMultGT(ke.g1, rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.g3 = g3

	g2, err := ke.privateKey.EncryptMasterPublicKey.ScalarBaseMult(rBytes)
	if err != nil {
		return nil, nil, err
	}
	ke.g2 = g2

	if !ke.genSignature {
		return ke.secret, nil, nil
	}

	return ke.secret, ke.sign(true, 0x82), nil
}

// RespondKeyExchange when responder receive rA, for responder's step B1-B7
func (ke *KeyExchange) RespondKeyExchange(rand io.Reader, hid byte, rA []byte) ([]byte, []byte, error) {
	r, err := randomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, hid, r, rA)
}

// ConfirmResponder for initiator's step A5-A7
func (ke *KeyExchange) ConfirmResponder(rB, sB []byte) ([]byte, []byte, error) {
	numBytes := 2 * len(bn256.OrderBytes)
	if len(rB) != numBytes+1 || rB[0] != 0x04 {
		return nil, nil, errors.New("sm9: invalid responder's ephemeral public key")
	}
	pB := new(bn256.G1)
	_, err := pB.Unmarshal(rB[1:])
	if err != nil || !pB.IsOnCurve() {
		return nil, nil, errors.New("sm9: invalid responder's ephemeral public key")
	}
	// step 5
	ke.peerSecret = rB
	g1, err := ke.privateKey.EncryptMasterPublicKey.ScalarBaseMult(ke.r.Bytes(orderNat))
	if err != nil {
		return nil, nil, err
	}
	ke.g1 = g1
	ke.g2 = bn256.Pair(pB, ke.privateKey.PrivateKey)
	ke.g3 = &bn256.GT{}
	g3, err := bn256.ScalarMultGT(ke.g2, ke.r.Bytes(orderNat))
	if err != nil {
		return nil, nil, err
	}
	ke.g3 = g3
	// step 6, verify signature
	if len(sB) > 0 {
		signature := ke.sign(false, 0x82)
		if goSubtle.ConstantTimeCompare(signature, sB) != 1 {
			return nil, nil, errors.New("sm9: invalid responder's signature")
		}
	}
	key, err := ke.generateSharedKey(false)
	if err != nil {
		return nil, nil, err
	}
	if !ke.genSignature {
		return key, nil, nil
	}
	return key, ke.sign(false, 0x83), nil
}

// ConfirmInitiator for responder's step B8
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) ([]byte, error) {
	if s1 != nil {
		buffer := ke.sign(true, 0x83)
		if goSubtle.ConstantTimeCompare(buffer, s1) != 1 {
			return nil, errors.New("sm9: invalid initiator's signature")
		}
	}
	return ke.generateSharedKey(true)
}
