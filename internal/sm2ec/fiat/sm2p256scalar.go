// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code generated by generate.go. DO NOT EDIT.

package fiat

import (
	"crypto/subtle"
	"errors"
)

// SM2P256OrderElement is an integer modulo 2^256 - 2^224 - 188730267045675049073202170516080344797.
//
// The zero value is a valid zero element.
type SM2P256OrderElement struct {
	// Values are represented internally always in the Montgomery domain, and
	// converted in Bytes and SetBytes.
	x sm2p256scalarMontgomeryDomainFieldElement
}

const sm2p256scalarElementLen = 32

type sm2p256scalarUntypedFieldElement = [4]uint64

// One sets e = 1, and returns e.
func (e *SM2P256OrderElement) One() *SM2P256OrderElement {
	sm2p256scalarSetOne(&e.x)
	return e
}

// Equal returns 1 if e == t, and zero otherwise.
func (e *SM2P256OrderElement) Equal(t *SM2P256OrderElement) int {
	eBytes := e.Bytes()
	tBytes := t.Bytes()
	return subtle.ConstantTimeCompare(eBytes, tBytes)
}

// IsZero returns 1 if e == 0, and zero otherwise.
func (e *SM2P256OrderElement) IsZero() int {
	zero := make([]byte, sm2p256scalarElementLen)
	eBytes := e.Bytes()
	return subtle.ConstantTimeCompare(eBytes, zero)
}

// Set sets e = t, and returns e.
func (e *SM2P256OrderElement) Set(t *SM2P256OrderElement) *SM2P256OrderElement {
	e.x = t.x
	return e
}

// Bytes returns the 32-byte big-endian encoding of e.
func (e *SM2P256OrderElement) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var out [sm2p256scalarElementLen]byte
	return e.bytes(&out)
}

func (e *SM2P256OrderElement) bytes(out *[sm2p256scalarElementLen]byte) []byte {
	var tmp sm2p256scalarNonMontgomeryDomainFieldElement
	sm2p256scalarFromMontgomery(&tmp, &e.x)
	sm2p256scalarToBytes(out, (*sm2p256scalarUntypedFieldElement)(&tmp))
	sm2p256scalarInvertEndianness(out[:])
	return out[:]
}

// SetBytes sets e = v, where v is a big-endian 32-byte encoding, and returns e.
// If v is not 32 bytes or it encodes a value higher than 2^256 - 2^224 - 188730267045675049073202170516080344797,
// SetBytes returns nil and an error, and e is unchanged.
func (e *SM2P256OrderElement) SetBytes(v []byte) (*SM2P256OrderElement, error) {
	if len(v) != sm2p256scalarElementLen {
		return nil, errors.New("invalid SM2P256OrderElement encoding")
	}
	/*
	// Check for non-canonical encodings (p + k, 2p + k, etc.) by comparing to
	// the encoding of -1 mod p, so p - 1, the highest canonical encoding.
	var minusOneEncoding = new(SM2P256OrderElement).Sub(
		new(SM2P256OrderElement), new(SM2P256OrderElement).One()).Bytes()
	for i := range v {
		if v[i] < minusOneEncoding[i] {
			break
		}
		if v[i] > minusOneEncoding[i] {
			return nil, errors.New("invalid SM2P256OrderElement encoding")
		}
	}*/
	var in [sm2p256scalarElementLen]byte
	copy(in[:], v)
	sm2p256scalarInvertEndianness(in[:])
	var tmp sm2p256scalarNonMontgomeryDomainFieldElement
	sm2p256scalarFromBytes((*sm2p256scalarUntypedFieldElement)(&tmp), &in)
	sm2p256scalarToMontgomery(&e.x, &tmp)
	return e, nil
}

// Add sets e = t1 + t2, and returns e.
func (e *SM2P256OrderElement) Add(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	sm2p256scalarAdd(&e.x, &t1.x, &t2.x)
	return e
}

// Sub sets e = t1 - t2, and returns e.
func (e *SM2P256OrderElement) Sub(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	sm2p256scalarSub(&e.x, &t1.x, &t2.x)
	return e
}

// Mul sets e = t1 * t2, and returns e.
func (e *SM2P256OrderElement) Mul(t1, t2 *SM2P256OrderElement) *SM2P256OrderElement {
	sm2p256scalarMul(&e.x, &t1.x, &t2.x)
	return e
}

// Square sets e = t * t, and returns e.
func (e *SM2P256OrderElement) Square(t *SM2P256OrderElement) *SM2P256OrderElement {
	sm2p256scalarSquare(&e.x, &t.x)
	return e
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *SM2P256OrderElement) Select(a, b *SM2P256OrderElement, cond int) *SM2P256OrderElement {
	sm2p256scalarSelectznz((*sm2p256scalarUntypedFieldElement)(&v.x), sm2p256scalarUint1(cond),
		(*sm2p256scalarUntypedFieldElement)(&b.x), (*sm2p256scalarUntypedFieldElement)(&a.x))
	return v
}

func sm2p256scalarInvertEndianness(v []byte) {
	for i := 0; i < len(v)/2; i++ {
		v[i], v[len(v)-1-i] = v[len(v)-1-i], v[i]
	}
}
