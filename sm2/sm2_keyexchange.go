package sm2

import (
	"crypto/ecdsa"
	goSubtle "crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm3"
)

// KeyExchange key exchange struct, include internal stat in whole key exchange flow.
// Initiator's flow will be: NewKeyExchange -> InitKeyExchange -> transmission -> ConfirmResponder
// Responder's flow will be: NewKeyExchange -> waiting ... -> RepondKeyExchange -> transmission -> ConfirmInitiator
type KeyExchange struct {
	genSignature bool             // control the optional sign/verify step triggered by responsder
	keyLength    int              // key length
	privateKey   *PrivateKey      // owner's encryption private key
	z            []byte           // owner identifiable id
	peerPub      *ecdsa.PublicKey // peer public key
	peerZ        []byte           // peer identifiable id
	r            *big.Int         // Ephemeral Private Key, random which will be used to compute secret
	secret       *ecdsa.PublicKey // Ephemeral Public Key, generated secret which will be passed to peer
	peerSecret   *ecdsa.PublicKey // received peer's secret, Ephemeral Public Key
	w2           *big.Int         // internal state which will be used when compute the key and signature, 2^w
	w2Minus1     *big.Int         // internal state which will be used when compute the key and signature, 2^w – 1
	v            *ecdsa.PublicKey // internal state which will be used when compute the key and signature, u/v
	key          []byte           // shared key will be used after key agreement
}

// GetSharedKey return shared key after key agreement
func (ke *KeyExchange) GetSharedKey() []byte {
	return ke.key
}

// NewKeyExchange create one new KeyExchange object
func NewKeyExchange(priv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) (ke *KeyExchange, err error) {
	ke = &KeyExchange{}
	ke.genSignature = genSignature
	ke.peerPub = peerPub
	ke.keyLength = keyLen
	ke.privateKey = priv
	w := (priv.Params().N.BitLen()+1)/2 - 1
	x2 := big.NewInt(2)
	ke.w2 = x2
	x2.Lsh(x2, uint(w))
	x2minus1 := (&big.Int{}).Sub(x2, big.NewInt(1))
	ke.w2Minus1 = x2minus1

	ke.z, err = calculateZA(&ke.privateKey.PublicKey, uid)
	if err != nil {
		return nil, err
	}
	ke.peerZ, err = calculateZA(ke.peerPub, peerUID)
	if err != nil {
		return nil, err
	}
	ke.secret = &ecdsa.PublicKey{}
	ke.secret.Curve = priv.PublicKey.Curve
	ke.peerSecret = &ecdsa.PublicKey{}
	ke.peerSecret.Curve = peerPub.Curve
	ke.v = &ecdsa.PublicKey{}
	ke.v.Curve = priv.PublicKey.Curve

	return
}

func initKeyExchange(ke *KeyExchange, r *big.Int) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
}

// InitKeyExchange generate random with responder uid, for initiator's step A1-A3
func (ke *KeyExchange) InitKeyExchange(rand io.Reader) (*ecdsa.PublicKey, error) {
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, err
	}
	initKeyExchange(ke, r)
	return ke.secret, nil
}

func (ke *KeyExchange) sign(isResponder bool, prefix byte) []byte {
	var buffer []byte
	hash := sm3.New()
	hash.Write(toBytes(ke.privateKey, ke.v.X))
	if isResponder {
		hash.Write(ke.peerZ)
		hash.Write(ke.z)
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
	} else {
		hash.Write(ke.z)
		hash.Write(ke.peerZ)
		hash.Write(toBytes(ke.privateKey, ke.secret.X))
		hash.Write(toBytes(ke.privateKey, ke.secret.Y))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.X))
		hash.Write(toBytes(ke.privateKey, ke.peerSecret.Y))
	}
	buffer = hash.Sum(nil)
	hash.Reset()
	hash.Write([]byte{prefix})
	hash.Write(toBytes(ke.privateKey, ke.v.Y))
	hash.Write(buffer)
	return hash.Sum(nil)
}

func (ke *KeyExchange) generateSharedKey(isResponder bool) {
	var buffer []byte
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.X)...)
	buffer = append(buffer, toBytes(ke.privateKey, ke.v.Y)...)
	if isResponder {
		buffer = append(buffer, ke.peerZ...)
		buffer = append(buffer, ke.z...)
	} else {
		buffer = append(buffer, ke.z...)
		buffer = append(buffer, ke.peerZ...)
	}
	key, _ := sm3.Kdf(buffer, ke.keyLength)
	ke.key = key
}

func respondKeyExchange(ke *KeyExchange, r *big.Int, rA *ecdsa.PublicKey) (*ecdsa.PublicKey, []byte, error) {
	ke.secret.X, ke.secret.Y = ke.privateKey.ScalarBaseMult(r.Bytes())
	ke.r = r
	// Calculate tB
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

	ke.generateSharedKey(true)

	if !ke.genSignature {
		return ke.secret, nil, nil
	}

	return ke.secret, ke.sign(true, 0x02), nil
}

// RepondKeyExchange when responder receive rA, for responder's step B1-B8
func (ke *KeyExchange) RepondKeyExchange(rand io.Reader, rA *ecdsa.PublicKey) (*ecdsa.PublicKey, []byte, error) {
	if !ke.privateKey.IsOnCurve(rA.X, rA.Y) {
		return nil, nil, errors.New("sm2: received invalid random from initiator")
	}
	ke.peerSecret = rA
	r, err := randFieldElement(ke.privateKey, rand)
	if err != nil {
		return nil, nil, err
	}
	return respondKeyExchange(ke, r, rA)
}

// ConfirmResponder for initiator's step A4-A10
func (ke *KeyExchange) ConfirmResponder(rB *ecdsa.PublicKey, sB []byte) ([]byte, error) {
	if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
		return nil, errors.New("sm2: received invalid random from responder")
	}
	ke.peerSecret = rB
	// Calcualte tA
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
	ke.generateSharedKey(false)
	if len(sB) > 0 {
		buffer := ke.sign(false, 0x02)
		if goSubtle.ConstantTimeCompare(buffer, sB) != 1 {
			return nil, errors.New("sm2: verify responder's signature fail")
		}
	}
	return ke.sign(false, 0x03), nil
}

// ConfirmInitiator for responder's step B10
func (ke *KeyExchange) ConfirmInitiator(s1 []byte) error {
	buffer := ke.sign(true, 0x03)
	if goSubtle.ConstantTimeCompare(buffer, s1) != 1 {
		return errors.New("sm2: verify initiator's signature fail")
	}
	return nil
}
