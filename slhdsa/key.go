// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"crypto"
	"crypto/sha3"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
)

// PublicKey represents an SLH-DSA public key.
// It contains the public seed and root value along with the parameter set
// and cryptographic operations needed for signature verification.
type PublicKey struct {
	seed           [maxN]byte            // Public seed used in hash operations
	root           [maxN]byte            // Root of the XMSS hypertree
	params         *params               // Parameter set (algorithm variant and security level)
	md             hash.Hash             // Hash function for normal operations
	mdBig          hash.Hash             // Hash function for operations requiring larger output
	mdBigFactory   func() hash.Hash      // Factory function to create new mdBig instances, also used in prfMsg
	shake          *sha3.SHAKE           // SHAKE instance for SHAKE-based variants
	addressCreator func() adrsOperations // Factory function to create address objects
	h              hashOperations        // Hash operations interface for the specific variant
}

// PrivateKey represents an SLH-DSA private key.
// It contains the secret seed and PRF value, along with the corresponding public key.
type PrivateKey struct {
	PublicKey
	seed [maxN]byte // Secret seed used to generate WOTS+ and FORS secret values
	prf  [maxN]byte // PRF key used in randomized signing
}

// Bytes returns the byte representation of the PublicKey.
// It combines the seed and root fields of the PublicKey.
func (pk *PublicKey) Bytes() []byte {
	var key [2 * maxN]byte
	copy(key[:], pk.seed[:pk.params.n])
	copy(key[pk.params.n:], pk.root[:pk.params.n])
	return key[:2*pk.params.n]
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pk.params == xx.params && subtle.ConstantTimeCompare(pk.seed[:pk.params.n], xx.seed[:pk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(pk.root[:pk.params.n], xx.root[:pk.params.n]) == 1
}

// ParameterSet returns the parameter set name of the public key.
// For example: "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f", etc.
func (pk *PublicKey) ParameterSet() string {
	return pk.params.alg
}

// String returns a string representation of the public key's parameter set.
func (pk *PublicKey) String() string {
	return pk.params.alg
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

func (sk *PrivateKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return sk.params == xx.params && subtle.ConstantTimeCompare(sk.seed[:sk.params.n], xx.seed[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.prf[:sk.params.n], xx.prf[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.PublicKey.seed[:sk.params.n], xx.PublicKey.seed[:sk.params.n]) == 1 &&
		subtle.ConstantTimeCompare(sk.root[:sk.params.n], xx.root[:sk.params.n]) == 1
}

// ParameterSet returns the parameter set name of the private key.
// For example: "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f", etc.
func (sk *PrivateKey) ParameterSet() string {
	return sk.params.alg
}

// String returns a string representation of the private key's parameter set.
func (sk *PrivateKey) String() string {
	return sk.params.alg
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
	key.params = params

	if params.isShake {
		// SHAKE-based variants
		key.shake = sha3.NewSHAKE256()
		key.h = shakeOperations{}
		key.addressCreator = newAdrs
		return nil
	}

	// Traditional hash-based variants (SHA2 or SM3)
	key.addressCreator = newAdrsC
	key.h = traditionalHashOperations{}
	key.md = params.mdFactory()
	key.mdBig = params.mdBigFactory()
	key.mdBigFactory = params.mdBigFactory
	return nil
}
