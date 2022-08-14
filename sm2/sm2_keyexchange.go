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
//
// 在部分场景中，在初始  KeyExchange 时暂时没有对端的公开信息（如公钥、UID），这些信息可能需要在后续的交换中得到。
// 这种情况下，可设置 peerPub、peerUID 参数为 nil，并在合适的时候通过 KeyExchange.SetPeerParameters 方法配置相关参数。
// 注意 KeyExchange.SetPeerParameters 方法必须要在 KeyExchange.RepondKeyExchange 或 KeyExchange.RepondKeyExchange 方法之前调用。
func NewKeyExchange(priv *PrivateKey, peerPub *ecdsa.PublicKey, uid, peerUID []byte, keyLen int, genSignature bool) (ke *KeyExchange, err error) {
	ke = &KeyExchange{}
	ke.genSignature = genSignature

	ke.keyLength = keyLen
	ke.privateKey = priv
	w := (priv.Params().N.BitLen()+1)/2 - 1
	x2 := big.NewInt(2)
	ke.w2 = x2
	x2.Lsh(x2, uint(w))
	x2minus1 := (&big.Int{}).Sub(x2, big.NewInt(1))
	ke.w2Minus1 = x2minus1

	if len(uid) == 0 {
		uid = defaultUID
	}
	ke.z, err = calculateZA(&ke.privateKey.PublicKey, uid)
	if err != nil {
		return nil, err
	}

	err = ke.SetPeerParameters(peerPub, peerUID)
	if err != nil {
		return nil, err
	}

	ke.secret = &ecdsa.PublicKey{}
	ke.secret.Curve = priv.PublicKey.Curve

	ke.v = &ecdsa.PublicKey{}
	ke.v.Curve = priv.PublicKey.Curve

	return
}

// SetPeerParameters 设置对端公开信息，该方法用于某些初期状态无法取得对端公开参数的场景。
// 例如：在TLCP协议中，基于SM2算法ECDHE过程。
//
// 注意该方法仅在 NewKeyExchange 没有提供 peerPub、peerUID参数时允许被调用，
// 且该方法只能调用一次不可重复调用，若多次调用或peerPub、peerUID已经存在则会发生错误。
func (ke *KeyExchange) SetPeerParameters(peerPub *ecdsa.PublicKey, peerUID []byte) error {
	if peerPub == nil {
		return nil
	}
	if len(peerUID) == 0 {
		peerUID = defaultUID
	}
	if ke.peerPub != nil {
		return errors.New("sm2: 'peerPub' already exists, please do not set it")
	}

	var err error
	ke.peerPub = peerPub
	ke.peerZ, err = calculateZA(ke.peerPub, peerUID)
	if err != nil {
		return err
	}
	ke.peerSecret = &ecdsa.PublicKey{}
	ke.peerSecret.Curve = peerPub.Curve
	return nil
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
	if ke.peerPub == nil {
		return nil, nil, errors.New("sm2: peer public not set, you probable need call KeyExchange.SetPeerParameters")
	}
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
	if ke.peerPub == nil {
		return nil, errors.New("sm2: peer public not set, you probable need call KeyExchange.SetPeerParameters")
	}
	if !ke.privateKey.IsOnCurve(rB.X, rB.Y) {
		return nil, errors.New("sm2: received invalid random from responder")
	}
	ke.peerSecret = rB
	// Calculate tA
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
