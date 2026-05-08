// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package tls13 provides TLS 1.3 key exchange primitives, including hybrid
// post-quantum key exchange combining classical ECDH with ML-KEM, as defined in
// RFC 8446 and draft-ietf-tls-hybrid-design.
package tls13

import (
	"crypto/ecdh"
	"errors"
	"io"

	gmecdh "github.com/emmansun/gmsm/ecdh"
	"github.com/emmansun/gmsm/mlkem"
)

// CurveID identifies a TLS 1.3 key exchange group.
type CurveID uint16

const (
	// Pure ECDH named groups (RFC 8446, Section 4.2.7).
	CurveX25519 CurveID = 0x001D // X25519
	CurveP256   CurveID = 0x0017 // secp256r1
	CurveP384   CurveID = 0x0018 // secp384r1
	CurveP521   CurveID = 0x0019 // secp521r1
	CurveSM2    CurveID = 0x0029 // curveSM2, RFC 8998

	// Hybrid ECDH + ML-KEM named groups (draft-ietf-tls-hybrid-design).
	// X25519MLKEM768 places the ML-KEM-768 share first, per Section 3.2.
	X25519MLKEM768     CurveID = 0x11ec
	SecP256r1MLKEM768  CurveID = 0x11eb
	SecP384r1MLKEM1024 CurveID = 0x11ed
	SM2MLKEM768        CurveID = 0x11ee
)

// mlkemDecapKey is the internal interface for an ML-KEM decapsulation key.
type mlkemDecapKey interface {
	EncapsulationKeyBytes() []byte
	Decapsulate(ciphertext []byte) (sharedSecret []byte, err error)
}

// mlkemEncapKey is the internal interface for performing ML-KEM encapsulation.
type mlkemEncapKey interface {
	Encapsulate(rand io.Reader) (sharedKey, ciphertext []byte, err error)
}

// ClassicalKeyPair abstracts a classical ephemeral key pair. The public key
// bytes are in the format expected by the peer (uncompressed point for EC
// curves, raw scalar for X25519).
type ClassicalKeyPair interface {
	PublicKeyBytes() []byte
	ECDH(remotePubBytes []byte) (sharedSecret []byte, err error)
}

// classicalKEX abstracts the classical component of a key exchange.
type classicalKEX interface {
	publicKeySize() int
	generateKeyPair(rand io.Reader) (ClassicalKeyPair, error)
	serverECDH(rand io.Reader, clientPubBytes []byte) (sharedSecret, serverPubBytes []byte, err error)
}

// KeySharePrivateKeys holds private key material for a TLS 1.3 key exchange.
// For pure ECDH, MLKEM is nil.
type KeySharePrivateKeys struct {
	ECDHE ClassicalKeyPair
	MLKEM mlkemDecapKey
}

// KeyExchange implements a TLS 1.3 named-group key exchange (pure ECDH or hybrid).
type KeyExchange interface {
	// KeyShares generates key share material for the TLS ClientHello.
	KeyShares(rand io.Reader) (priv *KeySharePrivateKeys, clientKeyShare []byte, err error)

	// ServerSharedSecret computes the shared secret and the server's key share
	// from the client's key share (ServerHello).
	ServerSharedSecret(rand io.Reader, clientKeyShare []byte) (sharedSecret, serverKeyShare []byte, err error)

	// ClientSharedSecret computes the shared secret from the server's key share.
	ClientSharedSecret(priv *KeySharePrivateKeys, serverKeyShare []byte) (sharedSecret []byte, err error)
}

// HybridKeyExchange is an alias for [KeyExchange], kept for compatibility.
type HybridKeyExchange = KeyExchange

func newMLKEM768DecapKey(seed []byte) (mlkemDecapKey, error) {
	dk, err := mlkem.NewDecapsulationKeyFromSeed768(seed)
	if err != nil {
		return nil, err
	}
	return &decapKey768{dk}, nil
}

func newMLKEM768EncapKey(b []byte) (mlkemEncapKey, error) {
	ek, err := mlkem.NewEncapsulationKey768(b)
	if err != nil {
		return nil, err
	}
	return &encapKey768{ek}, nil
}

// NewKeyExchange returns a [KeyExchange] for the given named group, or an error
// if the named group is not supported.
func NewKeyExchange(id CurveID) (KeyExchange, error) {
	switch id {
	// --- pure ECDH ---
	// Public key sizes are TLS key_share payload sizes:
	// X25519 = 32-byte u-coordinate; P-256/P-384/P-521 and SM2 =
	// uncompressed SEC1 point 0x04||X||Y (65/97/133/65 bytes).
	case CurveX25519:
		return &ecdhKEX{classical: &stdlibCurveKEX{curve: ecdh.X25519(), pubKeySize: 32}}, nil
	case CurveP256:
		return &ecdhKEX{classical: &stdlibCurveKEX{curve: ecdh.P256(), pubKeySize: 65}}, nil
	case CurveP384:
		return &ecdhKEX{classical: &stdlibCurveKEX{curve: ecdh.P384(), pubKeySize: 97}}, nil
	case CurveP521:
		return &ecdhKEX{classical: &stdlibCurveKEX{curve: ecdh.P521(), pubKeySize: 133}}, nil
	case CurveSM2:
		return &ecdhKEX{classical: &sm2CurveKEX{curve: gmecdh.P256()}}, nil

	// --- hybrid ---
	case X25519MLKEM768:
		return &hybridKEX{
			classical:           &stdlibCurveKEX{curve: ecdh.X25519(), pubKeySize: 32},
			mlkemFirst:          true,
			mlkemPublicKeySize:  mlkem.EncapsulationKeySize768,
			mlkemCiphertextSize: mlkem.CiphertextSize768,
			newMLKEMDecapKey:    newMLKEM768DecapKey,
			newMLKEMEncapKey:    newMLKEM768EncapKey,
		}, nil
	case SecP256r1MLKEM768:
		return &hybridKEX{
			classical:           &stdlibCurveKEX{curve: ecdh.P256(), pubKeySize: 65},
			mlkemFirst:          false,
			mlkemPublicKeySize:  mlkem.EncapsulationKeySize768,
			mlkemCiphertextSize: mlkem.CiphertextSize768,
			newMLKEMDecapKey:    newMLKEM768DecapKey,
			newMLKEMEncapKey:    newMLKEM768EncapKey,
		}, nil
	case SecP384r1MLKEM1024:
		return &hybridKEX{
			classical:           &stdlibCurveKEX{curve: ecdh.P384(), pubKeySize: 97},
			mlkemFirst:          false,
			mlkemPublicKeySize:  mlkem.EncapsulationKeySize1024,
			mlkemCiphertextSize: mlkem.CiphertextSize1024,
			newMLKEMDecapKey: func(seed []byte) (mlkemDecapKey, error) {
				dk, err := mlkem.NewDecapsulationKeyFromSeed1024(seed)
				if err != nil {
					return nil, err
				}
				return &decapKey1024{dk}, nil
			},
			newMLKEMEncapKey: func(b []byte) (mlkemEncapKey, error) {
				ek, err := mlkem.NewEncapsulationKey1024(b)
				if err != nil {
					return nil, err
				}
				return &encapKey1024{ek}, nil
			},
		}, nil
	case SM2MLKEM768:
		return &hybridKEX{
			classical:           &sm2CurveKEX{curve: gmecdh.P256()},
			mlkemFirst:          false,
			mlkemPublicKeySize:  mlkem.EncapsulationKeySize768,
			mlkemCiphertextSize: mlkem.CiphertextSize768,
			newMLKEMDecapKey:    newMLKEM768DecapKey,
			newMLKEMEncapKey:    newMLKEM768EncapKey,
		}, nil
	default:
		return nil, errors.New("tls13: unsupported named group")
	}
}

// NewHybridKeyExchange returns a [KeyExchange] for the given hybrid named group.
//
// Deprecated: use [NewKeyExchange].
func NewHybridKeyExchange(id CurveID) (KeyExchange, error) {
	return NewKeyExchange(id)
}

// --- pure ECDH ---

type ecdhKEX struct{ classical classicalKEX }

func (ke *ecdhKEX) KeyShares(rand io.Reader) (*KeySharePrivateKeys, []byte, error) {
	kp, err := ke.classical.generateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	return &KeySharePrivateKeys{ECDHE: kp}, kp.PublicKeyBytes(), nil
}

func (ke *ecdhKEX) ServerSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, []byte, error) {
	shared, serverPub, err := ke.classical.serverECDH(rand, clientKeyShare)
	if err != nil {
		return nil, nil, err
	}
	return shared, serverPub, nil
}

func (ke *ecdhKEX) ClientSharedSecret(priv *KeySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	return priv.ECDHE.ECDH(serverKeyShare)
}

// --- hybrid ECDH + ML-KEM ---

// hybridKEX implements KeyExchange for a specific ECDH curve + ML-KEM pair.
type hybridKEX struct {
	classical classicalKEX
	// mlkemFirst controls both key share ordering and shared secret ordering:
	//   true  (X25519MLKEM768):     share = mlkem‖ecdh, secret = mlkem‖ecdh
	//   false (other hybrid groups): share = ecdh‖mlkem, secret = ecdh‖mlkem
	mlkemFirst          bool
	mlkemPublicKeySize  int
	mlkemCiphertextSize int
	newMLKEMDecapKey    func(seed []byte) (mlkemDecapKey, error)
	newMLKEMEncapKey    func(b []byte) (mlkemEncapKey, error)
}

// --- stdlibCurveKEX: classicalKEX backed by crypto/ecdh ---

type stdlibCurveKEX struct {
	curve      ecdh.Curve
	pubKeySize int
}

func (s *stdlibCurveKEX) publicKeySize() int { return s.pubKeySize }

func (s *stdlibCurveKEX) generateKeyPair(rand io.Reader) (ClassicalKeyPair, error) {
	priv, err := s.curve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &stdlibKeyPair{curve: s.curve, priv: priv}, nil
}

func (s *stdlibCurveKEX) serverECDH(rand io.Reader, clientPubBytes []byte) ([]byte, []byte, error) {
	serverPriv, err := s.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	clientPub, err := s.curve.NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, nil, err
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, nil, err
	}
	return shared, serverPriv.PublicKey().Bytes(), nil
}

type stdlibKeyPair struct {
	curve ecdh.Curve
	priv  *ecdh.PrivateKey
}

func (k *stdlibKeyPair) PublicKeyBytes() []byte { return k.priv.PublicKey().Bytes() }

func (k *stdlibKeyPair) ECDH(remotePubBytes []byte) ([]byte, error) {
	remotePub, err := k.curve.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(remotePub)
}

// --- sm2CurveKEX: classicalKEX backed by github.com/emmansun/gmsm/ecdh (SM2) ---

// SM2 uncompressed public key: 04 || 32-byte x || 32-byte y = 65 bytes.
const sm2PublicKeySize = 65

type sm2CurveKEX struct{ curve gmecdh.Curve }

func (s *sm2CurveKEX) publicKeySize() int { return sm2PublicKeySize }

func (s *sm2CurveKEX) generateKeyPair(rand io.Reader) (ClassicalKeyPair, error) {
	priv, err := s.curve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &sm2KeyPair{curve: s.curve, priv: priv}, nil
}

func (s *sm2CurveKEX) serverECDH(rand io.Reader, clientPubBytes []byte) ([]byte, []byte, error) {
	serverPriv, err := s.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	clientPub, err := s.curve.NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, nil, err
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, nil, err
	}
	return shared, serverPriv.PublicKey().Bytes(), nil
}

type sm2KeyPair struct {
	curve gmecdh.Curve
	priv  *gmecdh.PrivateKey
}

func (k *sm2KeyPair) PublicKeyBytes() []byte { return k.priv.PublicKey().Bytes() }

func (k *sm2KeyPair) ECDH(remotePubBytes []byte) ([]byte, error) {
	remotePub, err := k.curve.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(remotePub)
}

// KeyShares generates client key share material.
// The returned clientKeyShare bytes are formatted according to the curve ID:
//   - X25519MLKEM768:     ML-KEM-768 encapsulation key ‖ X25519 public key
//   - SecP256r1MLKEM768:  P-256 public key ‖ ML-KEM-768 encapsulation key
//   - SecP384r1MLKEM1024: P-384 public key ‖ ML-KEM-1024 encapsulation key
//   - SM2MLKEM768:        SM2 public key ‖ ML-KEM-768 encapsulation key
func (ke *hybridKEX) KeyShares(rand io.Reader) (*KeySharePrivateKeys, []byte, error) {
	ecdhPriv, err := ke.classical.generateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}

	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}
	mlkemPriv, err := ke.newMLKEMDecapKey(seed)
	if err != nil {
		return nil, nil, err
	}

	priv := &KeySharePrivateKeys{
		ECDHE: ecdhPriv,
		MLKEM: mlkemPriv,
	}

	ecdhPub := ecdhPriv.PublicKeyBytes()
	mlkemPub := mlkemPriv.EncapsulationKeyBytes()

	var clientKeyShare []byte
	if ke.mlkemFirst {
		clientKeyShare = append(mlkemPub, ecdhPub...)
	} else {
		clientKeyShare = append(ecdhPub, mlkemPub...)
	}
	return priv, clientKeyShare, nil
}

// ServerSharedSecret computes the shared secret from the client's key share
// and returns the server's key share bytes.
// The returned serverKeyShare uses the same ordering as clientKeyShare.
func (ke *hybridKEX) ServerSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, []byte, error) {
	ecdhSize := ke.classical.publicKeySize()
	expectedLen := ecdhSize + ke.mlkemPublicKeySize
	if len(clientKeyShare) != expectedLen {
		return nil, nil, errors.New("tls13: invalid client key share length")
	}

	var ecdhShareData, mlkemShareData []byte
	if ke.mlkemFirst {
		mlkemShareData = clientKeyShare[:ke.mlkemPublicKeySize]
		ecdhShareData = clientKeyShare[ke.mlkemPublicKeySize:]
	} else {
		ecdhShareData = clientKeyShare[:ecdhSize]
		mlkemShareData = clientKeyShare[ecdhSize:]
	}

	// Classical ECDH server side
	ecdhSharedSecret, ecdhServerPub, err := ke.classical.serverECDH(rand, ecdhShareData)
	if err != nil {
		return nil, nil, err
	}

	// ML-KEM server side: encapsulate using the client's encapsulation key
	mlkemEncapKey, err := ke.newMLKEMEncapKey(mlkemShareData)
	if err != nil {
		return nil, nil, err
	}
	mlkemSharedKey, mlkemCiphertext, err := mlkemEncapKey.Encapsulate(rand)
	if err != nil {
		return nil, nil, err
	}

	// Shared secret ordering mirrors key share ordering (draft-ietf-tls-hybrid-design).
	sharedSecret := make([]byte, len(mlkemSharedKey)+len(ecdhSharedSecret))
	if ke.mlkemFirst {
		copy(sharedSecret, mlkemSharedKey)
		copy(sharedSecret[len(mlkemSharedKey):], ecdhSharedSecret)
	} else {
		copy(sharedSecret, ecdhSharedSecret)
		copy(sharedSecret[len(ecdhSharedSecret):], mlkemSharedKey)
	}

	var serverKeyShare []byte
	if ke.mlkemFirst {
		serverKeyShare = append(mlkemCiphertext, ecdhServerPub...)
	} else {
		serverKeyShare = append(ecdhServerPub, mlkemCiphertext...)
	}
	return sharedSecret, serverKeyShare, nil
}

// ClientSharedSecret computes the shared secret from the server's key share.
func (ke *hybridKEX) ClientSharedSecret(priv *KeySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	ecdhSize := ke.classical.publicKeySize()
	expectedLen := ecdhSize + ke.mlkemCiphertextSize
	if len(serverKeyShare) != expectedLen {
		return nil, errors.New("tls13: invalid server key share length")
	}

	var ecdhShareData, mlkemShareData []byte
	if ke.mlkemFirst {
		mlkemShareData = serverKeyShare[:ke.mlkemCiphertextSize]
		ecdhShareData = serverKeyShare[ke.mlkemCiphertextSize:]
	} else {
		ecdhShareData = serverKeyShare[:ecdhSize]
		mlkemShareData = serverKeyShare[ecdhSize:]
	}

	ecdhSharedSecret, err := priv.ECDHE.ECDH(ecdhShareData)
	if err != nil {
		return nil, err
	}

	mlkemSharedKey, err := priv.MLKEM.Decapsulate(mlkemShareData)
	if err != nil {
		return nil, err
	}

	sharedSecret := make([]byte, len(mlkemSharedKey)+len(ecdhSharedSecret))
	if ke.mlkemFirst {
		copy(sharedSecret, mlkemSharedKey)
		copy(sharedSecret[len(mlkemSharedKey):], ecdhSharedSecret)
	} else {
		copy(sharedSecret, ecdhSharedSecret)
		copy(sharedSecret[len(ecdhSharedSecret):], mlkemSharedKey)
	}
	return sharedSecret, nil
}

// --- concrete adapters for gmsm ML-KEM types ---

type decapKey768 struct{ dk *mlkem.DecapsulationKey768 }

func (d *decapKey768) EncapsulationKeyBytes() []byte {
	return d.dk.EncapsulationKey().Bytes()
}

func (d *decapKey768) Decapsulate(ct []byte) ([]byte, error) { return d.dk.Decapsulate(ct) }

type decapKey1024 struct{ dk *mlkem.DecapsulationKey1024 }

func (d *decapKey1024) EncapsulationKeyBytes() []byte {
	return d.dk.EncapsulationKey().Bytes()
}

func (d *decapKey1024) Decapsulate(ct []byte) ([]byte, error) { return d.dk.Decapsulate(ct) }

type encapKey768 struct{ ek *mlkem.EncapsulationKey768 }

func (e *encapKey768) Encapsulate(rand io.Reader) ([]byte, []byte, error) {
	return e.ek.Encapsulate(rand)
}

type encapKey1024 struct{ ek *mlkem.EncapsulationKey1024 }

func (e *encapKey1024) Encapsulate(rand io.Reader) ([]byte, []byte, error) {
	return e.ek.Encapsulate(rand)
}
