// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"crypto"
	"errors"

	"github.com/emmansun/gmsm/internal/bigmod"
)

// SignDeterministic generates a deterministic SM2 signature according to RFC 6979,
// using SM3 as the hash function for the HMAC-based deterministic nonce generation.
// This method eliminates the risk of random number generator failure and is
// widely used in blockchain, HSMs, and key custody scenarios.
// Note: This uses HMAC-SM3, not the GM/T 0105 DRBG, as it is a stateless
// deterministic derivation process rather than a random bit generator.
func SignDeterministic(priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(hash) == 0 {
		return nil, errors.New("sm2: hash cannot be empty")
	}
	if sm2Opts, ok := opts.(*SM2SignerOption); ok && sm2Opts.forceGMSign {
		newHash, err := CalculateSM2Hash(&priv.PublicKey, hash, sm2Opts.uid)
		if err != nil {
			return nil, err
		}
		hash = newHash
	}

	switch priv.Curve.Params() {
	case P256().Params():
		c := p256()
		d := bigIntToBytes(c.curve, priv.D)
		drbg := newDRBG(d, bits2octets(c, hash), nil) // RFC 6979, Section 3.3
		return signSM2EC(c, priv, drbgRandFunc(drbg), hash)
	default:
		return nil, errors.New("sm2: curve not supported by deterministic signatures")
	}
}

// bits2octets as specified in FIPS 186-5, Appendix B.2.4 or RFC 6979,
// Section 2.3.4. See RFC 6979, Section 3.5 for the rationale.
func bits2octets(c *sm2Curve, hash []byte) []byte {
	e := bigmod.NewNat()
	hashToNat(c, e, hash)
	return e.Bytes(c.N)
}

func drbgRandFunc(drbg *hmacDRBG) func([]byte) error {
	return func(b []byte) error {
		drbg.Generate(b)
		return nil
	}
}
