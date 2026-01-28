// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"hash"
	"io"

	"github.com/emmansun/gmsm/sm3"
)

const (
	maxN       = 32
	maxM       = 49
	maxK       = 35
	maxA       = 9
	maxKTimesA = maxK * maxA
	maxWotsLen = 2*maxN + 3

	maxContextLen = 255
)

type params struct {
	alg              string
	oid              asn1.ObjectIdentifier
	isShake          bool
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
	mdBigFactory     func() hash.Hash
	mdFactory        func() hash.Hash
}

// paramsBuilder is a builder for creating params instances
type paramsBuilder struct {
	p params
}

// NewParamsBuilder creates a new paramsBuilder
func NewParamsBuilder() *paramsBuilder {
	return &paramsBuilder{
		p: params{},
	}
}

// withAlgorithm sets the algorithm name
func (b *paramsBuilder) withAlgorithm(alg string) *paramsBuilder {
	b.p.alg = alg
	return b
}

// withOID sets the OID for the parameter set
func (b *paramsBuilder) withOID(oid asn1.ObjectIdentifier) *paramsBuilder {
	b.p.oid = oid
	return b
}

// withShake sets whether SHAKE is used
func (b *paramsBuilder) withShake(isShake bool) *paramsBuilder {
	b.p.isShake = isShake
	return b
}

// withMdFactory sets the hash factory
func (b *paramsBuilder) withMdFactory(factory, bigFactory func() hash.Hash) *paramsBuilder {
	b.p.mdFactory = factory
	b.p.mdBigFactory = bigFactory
	b.p.isShake = false
	return b
}

// withN sets the security parameter
func (b *paramsBuilder) withN(n uint32) *paramsBuilder {
	b.p.n = n
	b.p.len = 2*n + 3
	return b
}

// withH sets the total height of the tree
func (b *paramsBuilder) withH(h uint32) *paramsBuilder {
	b.p.h = h
	return b
}

// withD sets the number of tree layers
func (b *paramsBuilder) withD(d uint32) *paramsBuilder {
	b.p.d = d
	return b
}

// withHm sets the height of each merkle tree
func (b *paramsBuilder) withHm(hm uint32) *paramsBuilder {
	b.p.hm = hm
	return b
}

// withA sets the height of a FORS tree
func (b *paramsBuilder) withA(a uint32) *paramsBuilder {
	b.p.a = a
	return b
}

// withK sets the number of FORS trees
func (b *paramsBuilder) withK(k uint32) *paramsBuilder {
	b.p.k = k
	return b
}

// withM sets the size of H_MSG() output
func (b *paramsBuilder) withM(m uint32) *paramsBuilder {
	b.p.m = m
	return b
}

// withSecurityCategory sets the security category
func (b *paramsBuilder) withSecurityCategory(cat uint32) *paramsBuilder {
	b.p.securityCategory = cat
	return b
}

// build creates the final params instance and calculates derived values
func (b *paramsBuilder) build() params {
	// Calculate sigLen: (1+k*(1+a)+d*(hm+len))*n
	b.p.sigLen = int((1 + b.p.k*(1+b.p.a) + b.p.d*(b.p.hm+b.p.len)) * b.p.n)
	// Calculate pkLen: 2*n
	b.p.pkLen = int(2 * b.p.n)
	return b.p
}

// sigLen = (1+k*(1+a)+d*(hm+len))*n
var (
	SLHDSA128SmallSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-128s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}).withMdFactory(sha256.New, sha256.New).
				withN(16).withH(63).withD(7).withHm(9).withA(12).withK(14).withM(30).
				withSecurityCategory(1).build()
	SLHDSA128SmallSM3 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SM3-128s").withMdFactory(sm3.New, sm3.New).
				withN(16).withH(63).withD(7).withHm(9).withA(12).withK(14).withM(30).
				withSecurityCategory(1).build()
	SLHDSA128SmallSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-128s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 26}).withShake(true).
				withN(16).withH(63).withD(7).withHm(9).withA(12).withK(14).withM(30).
				withSecurityCategory(1).build()
	SLHDSA128FastSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-128f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 21}).withMdFactory(sha256.New, sha256.New).
				withN(16).withH(66).withD(22).withHm(3).withA(6).withK(33).withM(34).
				withSecurityCategory(1).build()
	SLHDSA128FastSM3 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SM3-128f").withMdFactory(sm3.New, sm3.New).
				withN(16).withH(66).withD(22).withHm(3).withA(6).withK(33).withM(34).
				withSecurityCategory(1).build()
	SLHDSA128FastSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-128f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 27}).withShake(true).
				withN(16).withH(66).withD(22).withHm(3).withA(6).withK(33).withM(34).
				withSecurityCategory(1).build()
	SLHDSA192SmallSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-192s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 22}).withMdFactory(sha256.New, sha512.New).
				withN(24).withH(63).withD(7).withHm(9).withA(14).withK(17).withM(39).
				withSecurityCategory(3).build()
	SLHDSA192SmallSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-192s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 28}).withShake(true).
				withN(24).withH(63).withD(7).withHm(9).withA(14).withK(17).withM(39).
				withSecurityCategory(3).build()
	SLHDSA192FastSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-192f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 23}).withMdFactory(sha256.New, sha512.New).
				withN(24).withH(66).withD(22).withHm(3).withA(8).withK(33).withM(42).
				withSecurityCategory(3).build()
	SLHDSA192FastSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-192f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 29}).withShake(true).
				withN(24).withH(66).withD(22).withHm(3).withA(8).withK(33).withM(42).
				withSecurityCategory(3).build()
	SLHDSA256SmallSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-256s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 24}).withMdFactory(sha256.New, sha512.New).
				withN(32).withH(64).withD(8).withHm(8).withA(14).withK(22).withM(47).
				withSecurityCategory(5).build()
	SLHDSA256SmallSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-256s").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 30}).withShake(true).
				withN(32).withH(64).withD(8).withHm(8).withA(14).withK(22).withM(47).
				withSecurityCategory(5).build()
	SLHDSA256FastSHA2 = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHA2-256f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 25}).withMdFactory(sha256.New, sha512.New).
				withN(32).withH(68).withD(17).withHm(4).withA(9).withK(35).withM(49).
				withSecurityCategory(5).build()
	SLHDSA256FastSHAKE = NewParamsBuilder().
				withAlgorithm("SLH-DSA-SHAKE-256f").withOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 31}).withShake(true).
				withN(32).withH(68).withD(17).withHm(4).withA(9).withK(35).withM(49).
				withSecurityCategory(5).build()
)

var parameterSets = map[string]*params{
	SLHDSA128SmallSHA2.alg:  &SLHDSA128SmallSHA2,
	SLHDSA128FastSHA2.alg:   &SLHDSA128FastSHA2,
	SLHDSA192SmallSHA2.alg:  &SLHDSA192SmallSHA2,
	SLHDSA192FastSHA2.alg:   &SLHDSA192FastSHA2,
	SLHDSA256SmallSHA2.alg:  &SLHDSA256SmallSHA2,
	SLHDSA256FastSHA2.alg:   &SLHDSA256FastSHA2,
	SLHDSA128SmallSM3.alg:   &SLHDSA128SmallSM3,
	SLHDSA128FastSM3.alg:    &SLHDSA128FastSM3,
	SLHDSA128SmallSHAKE.alg: &SLHDSA128SmallSHAKE,
	SLHDSA128FastSHAKE.alg:  &SLHDSA128FastSHAKE,
	SLHDSA192SmallSHAKE.alg: &SLHDSA192SmallSHAKE,
	SLHDSA192FastSHAKE.alg:  &SLHDSA192FastSHAKE,
	SLHDSA256SmallSHAKE.alg: &SLHDSA256SmallSHAKE,
	SLHDSA256FastSHAKE.alg:  &SLHDSA256FastSHAKE,
}

func GetParameterSet(name string) (*params, bool) {
	if p, ok := parameterSets[name]; ok {
		return p, true
	}
	return nil, false
}

func GetParameterSetByOID(oid asn1.ObjectIdentifier) (*params, bool) {
	for _, p := range parameterSets {
		if p.oid.Equal(oid) {
			return p, true
		}
	}
	return nil, false
}

func (p *params) Equal(x any) bool {
	if x == nil {
		return false
	}
	if p2, ok := x.(*params); ok {
		return p.alg == p2.alg && p.isShake == p2.isShake &&
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

// OID returns the ASN.1 Object Identifier for this parameter set per RFC 9909.
func (p *params) OID() asn1.ObjectIdentifier {
	return p.oid
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
