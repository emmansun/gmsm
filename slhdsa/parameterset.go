// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import "io"

const (
	MAX_N         = 32
	MAX_M         = 49
	MAX_K         = 35
	MAX_A         = 9
	MAX_K_TIMES_A = MAX_K * MAX_A
	MAX_WOTS_LEN  = 2*MAX_N + 3

	MAX_CONTEXT_LEN = 255
)

type params struct {
	alg              string
	isShake          int
	isSM3            int
	n                uint32 // Security parameter (Hash output size in bytes) (16, 24, 32)
	len              uint32 // 2*n + 3
	h                uint32 // The total height of the tree (63, 64, 66, 68). #keypairs = 2^h
	d                uint32 // The number of tree layers (7, 8, 17, 22)
	hm               uint32 // The height (h') of each merkle tree. (h = hm * d )
	a                uint32 // Height of a FORS tree
	k                uint32 // The number of FORS trees
	m                uint32 // The size of H_MSG() output
	securityCategory uint32
	sigLen           int
	pkLen            int
}

// sigLen = (1+k*(1+a)+d*(hm+len))*n
var (
	SLHDSA128SmallSHA2 = params{alg: "SLH-DSA-SHA2-128s", isShake: 0, isSM3: 0, n: 16, len: 35, h: 63, d: 7, hm: 9, a: 12, k: 14, m: 30,
		securityCategory: 1, sigLen: 7856, pkLen: 32}
	SLHDSA128SmallSM3 = params{alg: "SLH-DSA-SM3-128s", isShake: 0, isSM3: 1, n: 16, len: 35, h: 63, d: 7, hm: 9, a: 12, k: 14, m: 30,
		securityCategory: 1, sigLen: 7856, pkLen: 32}
	SLHDSA128SmallSHAKE = params{alg: "SLH-DSA-SHAKE-128s", isShake: 1, isSM3: 0, n: 16, len: 35, h: 63, d: 7, hm: 9, a: 12, k: 14, m: 30,
		securityCategory: 1, sigLen: 7856, pkLen: 32}
	SLHDSA128FastSHA2 = params{alg: "SLH-DSA-SHA2-128f", isShake: 0, isSM3: 0, n: 16, len: 35, h: 66, d: 22, hm: 3, a: 6, k: 33, m: 34,
		securityCategory: 1, sigLen: 17088, pkLen: 32}
	SLHDSA128FastSM3 = params{alg: "SLH-DSA-SM3-128f", isShake: 0, isSM3: 10, n: 16, len: 35, h: 66, d: 22, hm: 3, a: 6, k: 33, m: 34,
		securityCategory: 1, sigLen: 17088, pkLen: 32}
	SLHDSA128FastSHAKE = params{alg: "SLH-DSA-SHAKE-128f", isShake: 1, isSM3: 0, n: 16, len: 35, h: 66, d: 22, hm: 3, a: 6, k: 33, m: 34,
		securityCategory: 1, sigLen: 17088, pkLen: 32}
	SLHDSA192SmallSHA2 = params{alg: "SLH-DSA-SHA2-192s", isShake: 0, isSM3: 0, n: 24, len: 51, h: 63, d: 7, hm: 9, a: 14, k: 17, m: 39,
		securityCategory: 3, sigLen: 16224, pkLen: 48}
	SLHDSA192SmallSHAKE = params{alg: "SLH-DSA-SHAKE-192s", isShake: 1, isSM3: 0, n: 24, len: 51, h: 63, d: 7, hm: 9, a: 14, k: 17, m: 39,
		securityCategory: 3, sigLen: 16224, pkLen: 48}
	SLHDSA192FastSHA2 = params{alg: "SLH-DSA-SHA2-192f", isShake: 0, isSM3: 0, n: 24, len: 51, h: 66, d: 22, hm: 3, a: 8, k: 33, m: 42,
		securityCategory: 3, sigLen: 35664, pkLen: 48}
	SLHDSA192FastSHAKE = params{alg: "SLH-DSA-SHAKE-192f", isShake: 1, isSM3: 0, n: 24, len: 51, h: 66, d: 22, hm: 3, a: 8, k: 33, m: 42,
		securityCategory: 3, sigLen: 35664, pkLen: 48}
	SLHDSA256SmallSHA2 = params{alg: "SLH-DSA-SHA2-256s", isShake: 0, isSM3: 0, n: 32, len: 67, h: 64, d: 8, hm: 8, a: 14, k: 22, m: 47,
		securityCategory: 5, sigLen: 29792, pkLen: 64}
	SLHDSA256SmallSHAKE = params{alg: "SLH-DSA-SHAKE-256s", isShake: 1, isSM3: 0, n: 32, len: 67, h: 64, d: 8, hm: 8, a: 14, k: 22, m: 47,
		securityCategory: 5, sigLen: 29792, pkLen: 64}
	SLHDSA256FastSHA2 = params{alg: "SLH-DSA-SHA2-256f", isShake: 0, isSM3: 0, n: 32, len: 67, h: 68, d: 17, hm: 4, a: 9, k: 35, m: 49,
		securityCategory: 5, sigLen: 49856, pkLen: 64}
	SLHDSA256FastSHAKE = params{alg: "SLH-DSA-SHAKE-256f", isShake: 1, isSM3: 0, n: 32, len: 67, h: 68, d: 17, hm: 4, a: 9, k: 35, m: 49,
		securityCategory: 5, sigLen: 49856, pkLen: 64}
)

var parameterSets = map[string]*params{
	"SLH-DSA-SHA2-128s":  &SLHDSA128SmallSHA2,
	"SLH-DSA-SHA2-128f":  &SLHDSA128FastSHA2,
	"SLH-DSA-SHA2-192s":  &SLHDSA192SmallSHA2,
	"SLH-DSA-SHA2-192f":  &SLHDSA192FastSHA2,
	"SLH-DSA-SHA2-256s":  &SLHDSA256SmallSHA2,
	"SLH-DSA-SHA2-256f":  &SLHDSA256FastSHA2,
	"SLH-DSA-SM3-128s":   &SLHDSA128SmallSM3,
	"SLH-DSA-SM3-128f":   &SLHDSA128FastSM3,
	"SLH-DSA-SHAKE-128s": &SLHDSA128SmallSHAKE,
	"SLH-DSA-SHAKE-128f": &SLHDSA128FastSHAKE,
	"SLH-DSA-SHAKE-192s": &SLHDSA192SmallSHAKE,
	"SLH-DSA-SHAKE-192f": &SLHDSA192FastSHAKE,
	"SLH-DSA-SHAKE-256s": &SLHDSA256SmallSHAKE,
	"SLH-DSA-SHAKE-256f": &SLHDSA256FastSHAKE,
}

func GetParameterSet(name string) (*params, bool) {
	if p, ok := parameterSets[name]; ok {
		return p, true
	}
	return nil, false
}

func (p *params) Equal(x any) bool {
	if x == nil {
		return false
	}
	if p2, ok := x.(*params); ok {
		return p.alg == p2.alg && p.isShake == p2.isShake && p.isSM3 == p2.isSM3 &&
			p.n == p2.n && p.h == p2.h && p.d == p2.d && p.hm == p2.hm &&
			p.a == p2.a && p.k == p2.k && p.m == p2.m &&
			p.securityCategory == p2.securityCategory &&
			p.sigLen == p2.sigLen && p.pkLen == p2.pkLen
	}
	return false
}

func (p *params) mdLen() int {
	return int(p.k*p.a+7) >> 3
}

func (p *params) treeIdxLen() int {
	return int(p.h-p.hm+7) >> 3 // 7 or 8 bytes
}

func (p *params) treeIdxMask() uint64 {
	return (1 << (p.h - p.hm)) - 1
}

func (p *params) leafIdxLen() int {
	return int(p.hm+7) >> 3 // 1 or 2 bytes
}

func (p *params) leafIdxMask() uint64 {
	return (1 << p.hm) - 1
}

func (p *params) String() string {
	return p.alg
}

// GenerateKey generates a new private key using the provided random source and the parameters
// specified by the receiver.
func (p *params) GenerateKey(rand io.Reader) (*PrivateKey, error) {
	return GenerateKey(rand, p)
}

// NewPublicKey creates a new PublicKey instance from the provided byte slice using the current parameter set.
func (p *params) NewPublicKey(bytes []byte) (*PublicKey, error) {
	return NewPublicKey(bytes, p)
}

// NewPrivateKey creates a new PrivateKey instance using the provided byte slice and the current parameter set.
func (p *params) NewPrivateKey(bytes []byte) (*PrivateKey, error) {
	return NewPrivateKey(bytes, p)
}
