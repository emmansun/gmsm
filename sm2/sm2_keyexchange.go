package sm2

import (
	"crypto/ecdsa"
	goSubtle "crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm3"
)

// Point represent point on curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// KeyExchange key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> RepondKeyExchange -> transmission -> ConfirmInitiator
type KeyExchange struct {
	genSignature bool             // control the optional sign/verify step triggered by responsder
	keyLength    int              // key length
	privateKey   *PrivateKey      // owner's encryption private key
	uid          []byte           // owner uid
	peerUID      []byte           // peer uid
	peerPub      *ecdsa.PublicKey // peer public key
	r            *big.Int         // random which will be used to compute secret
	secret       Point            // generated secret which will be passed to peer
	peerSecret   Point            // received peer's secret
	w2           *big.Int         // internal state which will be used when compute the key and signature
	w2Minus1     *big.Int         // internal state which will be used when compute the key and signature
	v            Point            // internal state which will be used when compute the key and signature
	key          []byte           // key will be used after key agreement
}

// GetKey return key after key agreement
func (ke *KeyExchange) GetKey() []byte {
	return ke.key
}

// NewKeyExchange create one new KeyExchange object
func NewKeyExchange(priv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) *KeyExchange {
	ke := &KeyExchange{}
	ke.genSignature = genSignature
	ke.peerPub = peerPub
	ke.keyLength = keyLen
	ke.privateKey = priv
	ke.uid = uid
	ke.peerUID = peerUID
	w := (priv.Params().N.BitLen()+1)/2 - 1
	x2 := big.NewInt(2)
	ke.w2 = x2
	x2.Lsh(x2, uint(w))
	x2minus1 := (&big.Int{}).Sub(x2, big.NewInt(1))
	ke.w2Minus1 = x2minus1

	return ke
}

func initKeyExchange(ke *KeyExchange, r *big.Int) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
}

// InitKeyExchange generate random with responder uid, for initiator's step A1-A3
func (ke *KeyExchange) InitKeyExchange(rand io.Reader) (*Point, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, r)
	return &ke.secret, nil
}

func respondKeyExchange(ke *KeyExchange, r *big.Int, rA *Point) (*Point, []byte, error) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r

	t := (&big.Int{}).And(ke.w2Minus1, ke.secret.X)
	t.Add(ke.w2, t)
	t.Mul(t, ke.r)
	t.Add(t, ke.privateKey.D)
	t.Mod(t, ke.privateKey.Params().N)

	x1 := (&big.Int{}).And(ke.w2Minus1, ke.peerSecret.X)
	x1.Add(ke.w2, x1)

	x3, y3 := ke.privateKey.ScalarMult(ke.peerSecret.X, ke.peerSecret.Y, x1.Bytes())
	x3, y3 = ke.privateKey.Add(ke.peerPub.X, ke.peerPub.Y, x3, y3)
	ke.v.X, ke.v.Y = ke.privateKey.ScalarMult(x3, y3, t.Bytes())
	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, nil, errors.New("sm2: key exchange fail")
	}

	var buffer []byte
	zA, err := calculateZA(ke.peerPub, ke.peerUID)
	if err != nil {
		return nil, nil, err
	}
	zB, err := calculateZA(&ke.privateKey.PublicKey, ke.uid)
	if err != nil {
		return nil, nil, err
	}
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.X)...)
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.Y)...)
	buffer = append(buffer, zA...)
	buffer = append(buffer, zB...)
	key, _ := sm3.Kdf(buffer, ke.keyLength)
	ke.key = key

	if !ke.genSignature {
		return &ke.secret, nil, nil
	}

	hash := sm3.New()
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	hash.Write(zA)
	hash.Write(zB)
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	hash.Write(toBytes(ke.privateKey, ke.secret.X))
	hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{0x02})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	buffer = hash.Sum(nil)

	return &ke.secret, buffer, nil
}

// RepondKeyExchange when responder receive rA, for responder's step B1-B8
func (ke *KeyExchange) RepondKeyExchange(rand io.Reader, rA *Point) (*Point, []byte, error) {
	if !ke.privateKey.IsOnCurve(rA.X, rA.Y) {
		return nil, nil, errors.New("sm2: received invalid random from initiator")
	}
	ke.peerSecret = *rA
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, r, rA)
}

// ConfirmResponder for initiator's step A4-A10
func (ke *KeyExchange) ConfirmResponder(rB *Point, sB []byte) ([]byte, error) {
	if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
		return nil, errors.New("sm2: received invalid random from responder")
	}
	hash := sm3.New()

	ke.peerSecret = *rB

	t := (&big.Int{}).And(ke.w2Minus1, ke.secret.X)
	t.Add(ke.w2, t)
	t.Mul(t, ke.r)
	t.Add(t, ke.privateKey.D)
	t.Mod(t, ke.privateKey.Params().N)

	x2 := (&big.Int{}).And(ke.w2Minus1, ke.peerSecret.X)
	x2.Add(ke.w2, x2)

	x3, y3 := ke.privateKey.ScalarMult(ke.peerSecret.X, ke.peerSecret.Y, x2.Bytes())
	x3, y3 = ke.privateKey.Add(ke.peerPub.X, ke.peerPub.Y, x3, y3)
	ke.v.X, ke.v.Y = ke.privateKey.ScalarMult(x3, y3, t.Bytes())

	if ke.v.X.Sign() == 0 && ke.v.Y.Sign() == 0 {
		return nil, errors.New("sm2: key exchange fail")
	}

	var buffer []byte
	zA, err := calculateZA(&ke.privateKey.PublicKey, ke.uid)
	if err != nil {
		return nil, err
	}
	zB, err := calculateZA(ke.peerPub, ke.peerUID)
	if err != nil {
		return nil, err
	}
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.X)...)
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.Y)...)
	buffer = append(buffer, zA...)
	buffer = append(buffer, zB...)
	key, _ := sm3.Kdf(buffer, ke.keyLength)
	ke.key = key

	if len(sB) > 0 {
		hash.Write(toBytes(ke.privateKey, ke.v.X))
		hash.Write(zA)
		hash.Write(zB)
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
		buffer = hash.Sum(nil)
		hash.Reset()
		hash.Write([]byte{0x02})
		hash.Write(toBytes(ke.privateKey, ke.v.Y))
		hash.Write(buffer)
		buffer = hash.Sum(nil)
		hash.Reset()
		if goSubtle.ConstantTimeCompare(buffer, sB) != 1 {
			return nil, errors.New("sm2: verify responder's signature fail")
		}
	}
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	hash.Write(zA)
	hash.Write(zB)
	hash.Write(toBytes(ke.privateKey, ke.secret.X))
	hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{0x03})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	buffer = hash.Sum(nil)

	return buffer, nil
}

// ConfirmInitiator for responder's step B10
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) error {
	hash := sm3.New()
	var buffer []byte
	zB, err := calculateZA(&ke.privateKey.PublicKey, ke.uid)
	if err != nil {
		return err
	}
	zA, err := calculateZA(ke.peerPub, ke.peerUID)
	if err != nil {
		return err
	}
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	hash.Write(zA)
	hash.Write(zB)
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
	hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	hash.Write(toBytes(ke.privateKey, ke.secret.X))
	hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{0x03})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	buffer = hash.Sum(nil)
	if goSubtle.ConstantTimeCompare(buffer, s1) != 1 {
		return errors.New("sm2: verify initiator's signature fail")
	}
	return nil
}
