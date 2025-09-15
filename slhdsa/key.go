// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"github.com/emmansun/gmsm/sm3"
)

type PublicKey struct {
	seed           [maxN]byte
	root           [maxN]byte
	params         *params
	md             hash.Hash
	mdBig          hash.Hash
	mdBigFactory   func() hash.Hash
	shake          *sha3.SHAKE
	addressCreator func() adrsOperations
	h              hashOperations
}

type PrivateKey struct {
	PublicKey
	seed [maxN]byte
	prf  [maxN]byte
}

// Bytes returns the byte representation of the PublicKey.
// It combines the seed and root fields of the PublicKey.
func (pk *PublicKey) Bytes() []byte {
	var key [2 * maxN]byte
	copy(key[:], pk.seed[:pk.params.n])
	copy(key[pk.params.n:], pk.root[:pk.params.n])
	return key[:2*pk.params.n]
}

func (pk *PublicKey) Equal(x any) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pk.params == xx.params && subtle.ConstantTimeCompare(pk.seed[:pk.params.n], xx.seed[:pk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(pk.root[:pk.params.n], xx.root[:pk.params.n]) == 1
}

// Bytes serializes the PrivateKey into a byte slice.
func (sk *PrivateKey) Bytes() []byte {
	var key [4 * maxN]byte
	keySlice := key[:]
	copy(keySlice, sk.seed[:sk.params.n])
	keySlice = keySlice[sk.params.n:]
	copy(keySlice, sk.prf[:sk.params.n])
	keySlice = keySlice[sk.params.n:]
	copy(keySlice, sk.PublicKey.seed[:sk.params.n])
	keySlice = keySlice[sk.params.n:]
	copy(keySlice, sk.root[:sk.params.n])
	return key[:4*sk.params.n]
}

// Public returns the public key of the private key.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return &sk.PublicKey
}

func (sk *PrivateKey) Equal(x any) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return sk.params == xx.params && subtle.ConstantTimeCompare(sk.seed[:sk.params.n], xx.seed[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.prf[:sk.params.n], xx.prf[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.PublicKey.seed[:sk.params.n], xx.PublicKey.seed[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.root[:sk.params.n], xx.root[:sk.params.n]) == 1
}

// GenerateKey generates a new private key based on the provided parameters.
// It initializes the key structure, fills the necessary fields with provided entropy,
// and computes the root node for the XMSS tree.
func GenerateKey(rand io.Reader, params *params) (*PrivateKey, error) {
	priv := &PrivateKey{}
	if err := initKey(params, &priv.PublicKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, priv.seed[:params.n]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, priv.prf[:params.n]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, priv.PublicKey.seed[:params.n]); err != nil {
		return nil, err
	}
	return generateKeyInernal(priv.seed[:params.n], priv.prf[:params.n], priv.PublicKey.seed[:params.n], params)
}

// NewPrivateKey creates a new PrivateKey instance from the provided priv.seed||priv.prf||pub.seed||pub.root and parameters.
// The function validates the length of the input byte slice and initializes the PrivateKey structure,
// including its PublicKey field. It also verifies the integrity of the key by comparing the root hash
// with the expected value. If any validation or initialization step fails, an error is returned.
func NewPrivateKey(bytes []byte, params *params) (*PrivateKey, error) {
	if len(bytes) != 4*int(params.n) {
		return nil, errors.New("slhdsa: invalid key length")
	}
	priv, err := generateKeyInernal(bytes[:params.n], bytes[params.n:2*params.n], bytes[2*params.n:3*params.n], params)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(priv.root[:params.n], bytes[3*params.n:]) != 1 {
		return nil, errors.New("slhdsa: invalid key")
	}
	return priv, nil
}

// NewPublicKey creates a new PublicKey instance from the provided seed||root and parameters.
// Note this method can NOT verify the validity of the public key.
func NewPublicKey(bytes []byte, params *params) (*PublicKey, error) {
	if len(bytes) != 2*int(params.n) {
		return nil, errors.New("slhdsa: invalid key length")
	}
	pub := &PublicKey{}
	if err := initKey(params, pub); err != nil {
		return nil, err
	}
	copy(pub.seed[:], bytes[:params.n])
	copy(pub.root[:], bytes[params.n:2*params.n])
	return pub, nil
}

func generateKeyInernal(skSeed, skPRF, pkSeed []byte, params *params) (*PrivateKey, error) {
	priv := &PrivateKey{}
	if err := initKey(params, &priv.PublicKey); err != nil {
		return nil, err
	}
	if len(skSeed) != int(params.n) || len(skPRF) != int(params.n) || len(pkSeed) != int(params.n) {
		return nil, errors.New("slhdsa: invalid seed/prf length")
	}
	copy(priv.seed[:], skSeed)
	copy(priv.prf[:], skPRF)
	copy(priv.PublicKey.seed[:], pkSeed)
	adrs := priv.addressCreator()
	adrs.setLayerAddress(params.d - 1)
	tmpBuf := make([]byte, params.n*params.len)
	priv.xmssNode(priv.root[:], tmpBuf, 0, params.hm, adrs)
	return priv, nil
}

func initKey(params *params, key *PublicKey) error {
	switch params {
	case &SLHDSA128SmallSHA2, &SLHDSA128FastSHA2:
		key.md = sha256.New()
		key.mdBig = key.md
		key.mdBigFactory = sha256.New
		key.h = sha2Operations{}
		key.addressCreator = newAdrsC
	case &SLHDSA128SmallSM3, &SLHDSA128FastSM3:
		key.md = sm3.New()
		key.mdBig = key.md
		key.mdBigFactory = sm3.New
		key.h = sha2Operations{}
		key.addressCreator = newAdrsC
	case &SLHDSA192SmallSHA2, &SLHDSA192FastSHA2, &SLHDSA256SmallSHA2, &SLHDSA256FastSHA2:
		key.md = sha256.New()
		key.mdBig = sha512.New()
		key.mdBigFactory = sha512.New
		key.h = sha2Operations{}
		key.addressCreator = newAdrsC
	case &SLHDSA128SmallSHAKE, &SLHDSA128FastSHAKE, &SLHDSA192SmallSHAKE, &SLHDSA192FastSHAKE, &SLHDSA256SmallSHAKE, &SLHDSA256FastSHAKE:
		key.shake = sha3.NewSHAKE256()
		key.h = shakeOperations{}
		key.addressCreator = newAdrs
	default:
		return errors.New("slhdsa: unsupported parameters")
	}
	key.params = params
	return nil
}
