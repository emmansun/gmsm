// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

// Package mldsa implements the quantum-resistant digital signature algorithm
// ML-DSA (Module-Lattice-Based Digital Signature Standard) as specified in [NIST FIPS 204].
//
// This implementations referenced OpenSSL's implementation of ML-DSA and part of Golang ML-KEM
// [OpenSSL ML-DSA]: https://github.com/openssl/openssl/blob/master/crypto/ml_dsa
// [Golang ML-KEM]: https://github.com/golang/go/blob/master/src/crypto/internal/fips140/mlkem
//
// [NIST FIPS 204]: https://doi.org/10.6028/NIST.FIPS.204
package mldsa

import (
	"crypto"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"
	"sync"
)

const (
	// ML-DSA global constants.
	n           = 256     // # of coefficients in the polynomials
	q           = 8380417 // 2^23 - 2^13 + 1
	qMinus1Div2 = (q - 1) / 2
	d           = 13 // # of dropped bits from t

	encodingSize10 = n * 10 / 8 // encoding size for bitlen=10
	encodingSize3  = n * 3 / 8  // encoding size for bitlen=3
	encodingSize4  = n * 4 / 8  // encoding size for bitlen=4
	encodingSize6  = n * 6 / 8  // encoding size for bitlen=6
	encodingSize13 = n * 13 / 8 // encoding size for bitlen=13
	encodingSize18 = n * 18 / 8 // encoding size for bitlen=18
	encodingSize20 = n * 20 / 8 // encoding size for bitlen=20

	SeedSize = 32

	gamma2QMinus1Div88 = (q - 1) / 88 // low-order rounding range for ML-DSA-44
	gamma2QMinus1Div32 = (q - 1) / 32 // low-order rounding range for ML-DSA-65 and ML-DSA-87

	gamma1TwoPower17 = 1 << 17 // coefficient range of y for ML-DSA-44
	gamma1TwoPower19 = 1 << 19 // coefficient range of y for ML-DSA-65 and ML-DSA-87

	eta2         = 2 // private key range for ML-DSA-44 and ML-DSA-87
	bitLenOfETA2 = 3
	eta4         = 4 // private key range for ML-DSA-65
	bitLenOfETA4 = 4

	lambda128 = 128 // collision strengh of c tilde for ML-DSA-44
	lambda192 = 192 // collision strength of c tilde for ML-DSA-65
	lambda256 = 256 // collision strength of c tilde for ML-DSA-87

	tau39 = 39 // security parameter for ML-DSA-44
	tau49 = 49 // security parameter for ML-DSA-65
	tau60 = 60 // security parameter for ML-DSA-87

	omega80 = 80 // max# of 1 in the hint for ML-DSA-44
	omega55 = 55 // max# of 1 in the hint for ML-DSA-65
	omega75 = 75 // max# of 1 in the hint for ML-DSA-87
)

// ML-DSA-44 parameters.
const (
	k44    = 4
	l44    = 4
	beta44 = eta2 * tau39

	PublicKeySize44  = 32 + 32*k44*10
	PrivateKeySize44 = 32 + 32 + 64 + 32*((k44+l44)*bitLenOfETA2+d*k44)

	sigEncodedLen44 = lambda128/4 + encodingSize18*l44 + omega80 + k44
)

// ML-DSA-65 parameters.
const (
	k65    = 6
	l65    = 5
	beta65 = eta4 * tau49

	PublicKeySize65  = 32 + 32*k65*10
	PrivateKeySize65 = 32 + 32 + 64 + 32*((k65+l65)*bitLenOfETA4+d*k65)

	sigEncodedLen65 = lambda192/4 + encodingSize20*l65 + omega55 + k65
)

// ML-DSA-87 parameters.
const (
	k87    = 8
	l87    = 7
	beta87 = eta2 * tau60

	PublicKeySize87  = 32 + 32*k87*10
	PrivateKeySize87 = 32 + 32 + 64 + 32*((k87+l87)*bitLenOfETA2+d*k87)

	sigEncodedLen87 = lambda256/4 + encodingSize20*l87 + omega75 + k87
)

// A PrivateKey44 is the private key for the ML-DSA-44 signature scheme.
type PrivateKey44 struct {
	rho        [32]byte         // public random seed
	k          [32]byte         // private random seed for signing
	tr         [64]byte         // pre-cached public key Hash, H(pk, 64)
	s1         [l44]ringElement // private secret of size L with short coefficients (-4..4) or (-2..2)
	s2         [k44]ringElement // private secret of size K with short coefficients (-4..4) or (-2..2)
	t0         [k44]ringElement // the Polynomial encoding of the 13 LSB of each coefficient of the uncompressed public key polynomial t. This is saved as part of the private key.
	s1NTTCache [l44]nttElement
	s2NTTCache [k44]nttElement
	t0NTTCache [k44]nttElement
	a          [k44 * l44]nttElement // a is generated and stored in NTT representation
	nttOnce    sync.Once
}

func (sk *PrivateKey44) ensureNTT() {
	sk.nttOnce.Do(func() {
		for i := range sk.s1NTTCache {
			sk.s1NTTCache[i] = ntt(sk.s1[i])
		}
		for i := range sk.s2NTTCache {
			sk.s2NTTCache[i] = ntt(sk.s2[i])
		}
		for i := range sk.t0NTTCache {
			sk.t0NTTCache[i] = ntt(sk.t0[i])
		}
	})
}

// A Key44 is the key pair for the ML-DSA-44 signature scheme.
type Key44 struct {
	PrivateKey44
	xi [32]byte         // input seed
	t1 [k44]ringElement // the Polynomial encoding of the 10 MSB of each coefficient of the uncompressed public key polynomial t. This is saved as part of the public key.
}

// A PublicKey44 is the public key for the ML-DSA-44 signature scheme.
type PublicKey44 struct {
	rho       [32]byte
	t1        [k44]ringElement
	tr        [64]byte // H(pk, 64), need to further check if public key requires it
	tNTTCache [k44]nttElement
	a         [k44 * l44]nttElement // a is generated and stored in NTT representation
	nttOnce   sync.Once
}

// PublicKey generates and returns the corresponding public key for the given
// Key44 instance.
func (sk *Key44) PublicKey() *PublicKey44 {
	return &PublicKey44{
		rho: sk.rho,
		t1:  sk.t1,
		tr:  sk.tr,
		a:   sk.a,
	}
}

func (pk *PublicKey44) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey44)
	if !ok {
		return false
	}
	return pk.rho == xx.rho && pk.t1 == xx.t1
}

// Bytes converts the PublicKey44 instance into a byte slice.
// See FIPS 204, Algorithm 22, pkEncode()
func (pk *PublicKey44) Bytes() []byte {
	// The actual logic is in a separate function to outline this allocation.
	b := make([]byte, 0, PublicKeySize44)
	return pk.bytes(b)
}

func (pk *PublicKey44) bytes(b []byte) []byte {
	b = append(b, pk.rho[:]...)
	for _, f := range pk.t1 {
		b = simpleBitPack10Bits(b, f)
	}
	return b
}

func (pk *PublicKey44) ensureNTT() {
	pk.nttOnce.Do(func() {
		t := pk.t1
		for i := range k44 {
			for j := range t[i] {
				t[i][j] <<= d
			}
			pk.tNTTCache[i] = ntt(t[i])
		}
	})
}

// Bytes returns the byte representation of the PrivateKey44.
// It copies the internal seed (xi) into a fixed-size byte array
// and returns it as a slice.
func (sk *Key44) Bytes() []byte {
	var b [SeedSize]byte
	copy(b[:], sk.xi[:])
	return b[:]
}

// Bytes converts the PrivateKey44 instance into a byte slice.
// See FIPS 204, Algorithm 24, skEncode()
func (sk *PrivateKey44) Bytes() []byte {
	b := make([]byte, 0, PrivateKeySize44)
	return sk.bytes(b)
}

func (sk *PrivateKey44) bytes(b []byte) []byte {
	b = append(b, sk.rho[:]...)
	b = append(b, sk.k[:]...)
	b = append(b, sk.tr[:]...)
	for _, f := range sk.s1 {
		b = bitPackSigned2(b, f)
	}
	for _, f := range sk.s2 {
		b = bitPackSigned2(b, f)
	}
	for _, f := range sk.t0 {
		b = bitPackSigned4096(b, f)
	}
	return b
}

func (sk *PrivateKey44) Equal(x any) bool {
	xx, ok := x.(*PrivateKey44)
	if !ok {
		return false
	}
	return sk.rho == xx.rho && sk.k == xx.k && sk.tr == xx.tr &&
		sk.s1 == xx.s1 && sk.s2 == xx.s2 && sk.t0 == xx.t0
}

// GenerateKey44 generates a new Key44 (ML-DSA-44) using the provided random source.
func GenerateKey44(rand io.Reader) (*Key44, error) {
	// The actual logic is in a separate function to outline this allocation.
	sk := &Key44{}
	return generateKey44(sk, rand)
}

func generateKey44(sk *Key44, rand io.Reader) (*Key44, error) {
	// Generate a random seed.
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	dsaKeyGen44(sk, &seed)
	return sk, nil
}

// NewKey44 creates a new instance of Key44 using the provided seed.
func NewKey44(seed []byte) (*Key44, error) {
	// The actual logic is in a separate function to outline this allocation.
	sk := &Key44{}
	return newPrivateKey44FromSeed(sk, seed)
}

func newPrivateKey44FromSeed(sk *Key44, seed []byte) (*Key44, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("mldsa: invalid seed length")
	}
	xi := (*[32]byte)(seed)
	dsaKeyGen44(sk, xi)
	return sk, nil
}

func dsaKeyGen44(sk *Key44, xi *[32]byte) {
	sk.xi = *xi
	H := sha3.NewSHAKE256()
	H.Write(xi[:])
	H.Write([]byte{k44})
	H.Write([]byte{l44})
	K := make([]byte, 128)
	H.Read(K)
	rho, rho1 := K[:32], K[32:96]
	K = K[96:]

	sk.rho = [32]byte(rho)
	sk.k = [32]byte(K)

	s1 := &sk.s1
	s2 := &sk.s2
	// Algorithm 33, ExpandS
	for s := byte(0); s < l44; s++ {
		s1[s] = rejBoundedPoly(rho1, eta2, 0, s)
	}
	for r := byte(0); r < k44; r++ {
		s2[r] = rejBoundedPoly(rho1, eta2, 0, r+l44)
	}

	// Using rho generate A' = A in NTT form
	A := &sk.a
	// Algorithm 32, ExpandA
	for r := byte(0); r < k44; r++ {
		for s := byte(0); s < l44; s++ {
			A[r*l44+s] = rejNTTPoly(rho, s, r)
		}
	}

	// t = NTT_inv(A' * NTT(s1)) + s2
	var s1NTT [l44]nttElement
	var nttT [k44]nttElement
	for i := range s1 {
		s1NTT[i] = ntt(s1[i])
	}
	for i := range nttT {
		for j := range s1NTT {
			nttT[i] = polyAdd(nttT[i], nttMul(s1NTT[j], A[i*l44+j]))
		}
	}
	var t [k44]ringElement
	t0 := &sk.t0
	t1 := &sk.t1
	for i := range nttT {
		t[i] = polyAdd(inverseNTT(nttT[i]), s2[i])
		// compress t
		for j := range n {
			t1[i][j], t0[i][j] = power2Round(t[i][j])
		}
	}
	H.Reset()
	ek := sk.PublicKey().Bytes()
	H.Write(ek)
	H.Read(sk.tr[:])
}

// NewPublicKey44 decode an public key from its encoded form.
// See FIPS 204, Algorithm 23 pkDecode()
func NewPublicKey44(b []byte) (*PublicKey44, error) {
	// The actual logic is in a separate function to outline this allocation.
	pk := &PublicKey44{}
	return parsePublicKey44(pk, b)
}

// See FIPS 204, Algorithm 23 pkDecode()
func parsePublicKey44(pk *PublicKey44, b []byte) (*PublicKey44, error) {
	if len(b) != PublicKeySize44 {
		return nil, errors.New("mldsa: invalid public key length")
	}

	H := sha3.NewSHAKE256()
	H.Write(b)
	H.Read(pk.tr[:])

	copy(pk.rho[:], b[:32])
	b = b[32:]
	for i := range k44 {
		simpleBitUnpack10Bits(b, &pk.t1[i])
		b = b[encodingSize10:]
	}

	A := &pk.a
	rho := pk.rho[:]
	// Algorithm 32, ExpandA
	for r := byte(0); r < k44; r++ {
		for s := byte(0); s < l44; s++ {
			A[r*l44+s] = rejNTTPoly(rho, s, r)
		}
	}
	return pk, nil
}

// NewPrivateKey44 decode an private key from its encoded form.
// See FIPS 204, Algorithm 25 skDecode()
func NewPrivateKey44(b []byte) (*PrivateKey44, error) {
	// The actual logic is in a separate function to outline this allocation.
	sk := &PrivateKey44{}
	return parsePrivateKey44(sk, b)
}

// See FIPS 204, Algorithm 25 skDecode()
// Decode a private key from its encoded form.
func parsePrivateKey44(sk *PrivateKey44, b []byte) (*PrivateKey44, error) {
	if len(b) != PrivateKeySize44 {
		return nil, errors.New("mldsa: invalid private key length")
	}
	copy(sk.rho[:], b[:32])
	copy(sk.k[:], b[32:64])
	copy(sk.tr[:], b[64:128])
	b = b[128:]
	for i := range l44 {
		f, err := bitUnpackSigned2(b)
		if err != nil {
			return nil, err
		}
		sk.s1[i] = f
		b = b[encodingSize3:]
	}
	for i := range k44 {
		f, err := bitUnpackSigned2(b)
		if err != nil {
			return nil, err
		}
		sk.s2[i] = f
		b = b[encodingSize3:]
	}
	for i := range k44 {
		bitUnpackSigned4096(b, &sk.t0[i])
		b = b[encodingSize13:]
	}
	A := &sk.a
	rho := sk.rho[:]
	// Algorithm 32, ExpandA
	for r := byte(0); r < k44; r++ {
		for s := byte(0); s < l44; s++ {
			A[r*l44+s] = rejNTTPoly(rho, s, r)
		}
	}
	return sk, nil
}

// Sign generates a digital signature for the given message and context using the private key.
// It uses a random seed generated from the provided random source.
//
// Parameters:
//   - rand: An io.Reader used to generate a random seed for signing.
//   - message: The message to be signed. Must not be empty.
//   - context: An optional context for domain separation. Must not exceed 255 bytes.
//
// Returns:
//   - A byte slice containing the generated signature.
//   - An error if the message is empty, the context is too long, or if there is an issue
//     reading from the random source.
//
// Note:
//   - The function uses SHAKE256 from the SHA-3 family for hashing.
//   - The signing process involves generating a unique seed and a hash-based
//     message digest (mu) before delegating to the internal signing function.
func (sk *PrivateKey44) Sign(rand io.Reader, message, context []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("mldsa: empty message")
	}
	if len(context) > 255 {
		return nil, errors.New("mldsa: context too long")
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}
	H := sha3.NewSHAKE256()
	H.Write(sk.tr[:])
	H.Write([]byte{0, byte(len(context))})
	if len(context) > 0 {
		H.Write(context)
	}
	H.Write(message)
	var mu [64]byte
	H.Read(mu[:])

	return sk.signInternal(seed[:], mu[:])
}

// SignWithPreHash generates a digital signature for the given message
// using the private key and additional context. It uses a given hashing algorithm
// from the OID to pre-hash the message before signing.
// It is similar to Sign but allows for pre-hashing the message.
func (sk *PrivateKey44) SignWithPreHash(rand io.Reader, message, context []byte, oid asn1.ObjectIdentifier) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("mldsa: empty message")
	}
	if len(context) > 255 {
		return nil, errors.New("mldsa: context too long")
	}
	preHashValue, err := preHash(oid, message)
	if err != nil {
		return nil, err
	}
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, err
	}

	H := sha3.NewSHAKE256()
	H.Write(sk.tr[:])
	H.Write([]byte{1, byte(len(context))})
	if len(context) > 0 {
		H.Write(context)
	}
	H.Write(preHashValue)
	var mu [64]byte
	H.Read(mu[:])

	return sk.signInternal(seed[:], mu[:])
}

// See FIPS 204, Algorithm 7 ML-DSA.Sign_internal()
func (sk *PrivateKey44) signInternal(seed, mu []byte) ([]byte, error) {
	var rho2 [64 + 2]byte
	H := sha3.NewSHAKE256()
	H.Write(sk.k[:])
	H.Write(seed[:])
	H.Write(mu[:])
	H.Read(rho2[:64])
	A := &sk.a

	sk.ensureNTT()
	zNormThreshold := int(gamma1TwoPower17 - beta44)
	r0NormThreshold := int(gamma2QMinus1Div88 - beta44)

	// rejection sampling loop
	for kappa := 0; ; kappa = kappa + l44 {
		// expand mask
		var (
			y    [l44]ringElement
			yNTT [l44]nttElement
		)
		for i := range l44 {
			index := kappa + i
			rho2[64] = byte(index)
			rho2[65] = byte(index >> 8)
			y[i] = expandMask(rho2[:], gamma1TwoPower17)
		}
		// compute y in NTT form
		for i := range l44 {
			yNTT[i] = ntt(y[i])
		}
		// compute w and w1
		var (
			w, w1 [k44]ringElement
			wNTT  [k44]nttElement
		)
		for i := range w {
			for j := range yNTT {
				wNTT[i] = polyAdd(wNTT[i], nttMul(yNTT[j], A[i*l44+j]))
			}
			w[i] = inverseNTT(wNTT[i])
			// high bits
			for j := range w[i] {
				w1[i][j] = fieldElement(compressHighBits(w[i][j], gamma2QMinus1Div88))
			}
		}
		// commitment hash
		var (
			cTilde    [lambda128 / 4]byte
			w1Encoded [encodingSize6]byte
		)
		H.Reset()
		H.Write(mu[:])
		for i := range k44 {
			simpleBitPack6Bits(w1Encoded[:0], w1[i])
			H.Write(w1Encoded[:])
		}
		H.Read(cTilde[:])
		// verifier's challenge
		cNTT := ntt(sampleInBall(cTilde[:], tau39))

		var (
			cs1 [l44]ringElement
			cs2 [k44]ringElement
			z   [l44]ringElement
			r0  [k44][n]int32
		)
		// compute <<cs1>> and z = <<cs1>> + y
		for i := range l44 {
			cs1[i] = inverseNTT(nttMul(cNTT, sk.s1NTTCache[i]))
			z[i] = polyAdd(cs1[i], y[i])
		}
		// compute <<cs2>> and r0 = LowBits(w - <<cs2>>)
		for i := range k44 {
			cs2[i] = inverseNTT(nttMul(cNTT, sk.s2NTTCache[i]))
			for j := range cs2[i] {
				_, r0[i][j] = decompose(fieldSub(w[i][j], cs2[i][j]), gamma2QMinus1Div88)
			}
		}
		zNorm := vectorInfinityNorm(z[:], 0)
		r0Norm := vectorInfinityNormSigned(r0[:], 0)

		// if zNorm >= gamma1 - beta || r0Norm >= gamma2 - beta, then continue
		if subtle.ConstantTimeLessOrEq(zNormThreshold, zNorm)|subtle.ConstantTimeLessOrEq(r0NormThreshold, r0Norm) == 1 {
			continue
		}
		// compute <<ct0>>
		var ct0 [k44]ringElement
		for i := range k44 {
			ct0[i] = inverseNTT(nttMul(cNTT, sk.t0NTTCache[i]))
		}
		// compute infinity norm of <<ct0>>
		ct0Norm := vectorInfinityNorm(ct0[:], 0)
		// make hint
		var hints [k44]ringElement
		vectorMakeHint(ct0[:], cs2[:], w[:], hints[:], gamma2QMinus1Div88)
		// if the number of 1 in the hint is greater than omega or the infinity norm of <<ct0>> >= gamma2, then continue
		if (subtle.ConstantTimeLessOrEq(int(omega80+1), vectorCountOnes(hints[:])) | subtle.ConstantTimeLessOrEq(gamma2QMinus1Div88, ct0Norm)) == 1 {
			continue
		}
		// signature encoding
		sig := make([]byte, 0, sigEncodedLen44)
		sig = append(sig, cTilde[:]...)
		for i := range l44 {
			sig = bitPackSignedTwoPower17(sig, z[i])
		}
		return hintBitPack(sig, hints[:], omega80), nil
	}
}

// Verify checks the validity of a given signature for a message and context
// using the public key.
func (pk *PublicKey44) Verify(sig []byte, message, context []byte) bool {
	if len(message) == 0 {
		return false
	}
	if len(context) > 255 {
		return false
	}
	if len(sig) != sigEncodedLen44 {
		return false
	}
	H := sha3.NewSHAKE256()
	H.Write(pk.tr[:])
	H.Write([]byte{0, byte(len(context))})
	if len(context) > 0 {
		H.Write(context)
	}
	H.Write(message)
	var mu [64]byte
	H.Read(mu[:])

	return pk.verifyInternal(sig, mu[:])
}

// VerifyWithPreHash verifies a signature using a message and additional context.
// It uses a given hashing algorithm from the OID to pre-hash the message before verifying.
func (pk *PublicKey44) VerifyWithPreHash(sig []byte, message, context []byte, oid asn1.ObjectIdentifier) bool {
	if len(message) == 0 {
		return false
	}
	if len(context) > 255 {
		return false
	}
	if len(sig) != sigEncodedLen44 {
		return false
	}
	preHashValue, err := preHash(oid, message)
	if err != nil {
		return false
	}
	H := sha3.NewSHAKE256()
	H.Write(pk.tr[:])
	H.Write([]byte{1, byte(len(context))})
	if len(context) > 0 {
		H.Write(context)
	}
	H.Write(preHashValue)
	var mu [64]byte
	H.Read(mu[:])

	return pk.verifyInternal(sig, mu[:])
}

// See FIPS 204, Algorithm 8 ML-DSA.Verify_internal()
func (pk *PublicKey44) verifyInternal(sig, mu []byte) bool {
	// Decode the signature
	cTilde := sig[:lambda128/4]
	sig = sig[lambda128/4:]

	var (
		z    [l44]ringElement
		zNTT [l44]nttElement
	)
	for i := range l44 {
		bitUnpackSignedTwoPower17(sig, &z[i])
		zNTT[i] = ntt(z[i])
		sig = sig[encodingSize18:]
	}
	zNorm := vectorInfinityNorm(z[:], 0)
	var hints [k44]ringElement
	if !hintBitUnpack(sig, hints[:], omega80) {
		return false
	}
	// verifier's challenge
	cNTT := ntt(sampleInBall(cTilde[:], tau39))

	pk.ensureNTT()
	// tNTT = tNTTCache*cNTT
	var tNTT [k44]nttElement
	for i := range k44 {
		tNTT[i] = nttMul(pk.tNTTCache[i], cNTT)
	}

	var (
		w1, wApprox [k44]ringElement
		zNTTMulA    [k44]nttElement
	)
	for i := range k44 {
		for j := range l44 {
			zNTTMulA[i] = polyAdd(zNTTMulA[i], nttMul(zNTT[j], pk.a[i*l44+j]))
		}
		zNTTMulA[i] = polySub(zNTTMulA[i], tNTT[i])
		wApprox[i] = inverseNTT(zNTTMulA[i])
	}

	H := sha3.NewSHAKE256()
	H.Write(mu[:])
	var w1Encoded [encodingSize6]byte
	for i := range k44 {
		for j := range wApprox[i] {
			w1[i][j] = useHint(hints[i][j], wApprox[i][j], gamma2QMinus1Div88)
		}
		simpleBitPack6Bits(w1Encoded[:0], w1[i])
		H.Write(w1Encoded[:])
	}
	var cTilde1 [lambda128 / 4]byte
	H.Read(cTilde1[:])
	return subtle.ConstantTimeLessOrEq(int(gamma1TwoPower17-beta44), zNorm) == 0 &&
		subtle.ConstantTimeCompare(cTilde[:], cTilde1[:]) == 1
}
