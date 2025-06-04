// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package mldsa

import (
	"crypto/sha3"
	"crypto/subtle"
)

// Algorithm 30
func rejNTTPoly(rho []byte, s, r byte) nttElement {
	G := sha3.NewSHAKE128()
	G.Write(rho)
	G.Write([]byte{s, r})

	const blockSize = 168 // SHAKE128 block size in bytes
	var buf [blockSize]byte

	var a nttElement
	var j int

	for {
		G.Read(buf[:])
		for i := 0; i < blockSize; i += 3 {
			// Algorithm 14, CoeffFromThreeBytes()
			d := uint32(buf[i]) | uint32(buf[i+1])<<8 | ((uint32(buf[i+2]) & 0x7f) << 16)
			if d < q {
				a[j] = fieldElement(d)
				j++
			}
			if j >= n {
				return a
			}
		}
	}
}

// This is a constant time version of n % 5
// Note that 0xFFFF / 5 = 0x3333, 2 is added to make an over-estimate of 1/5
// and then we divide by (0xFFFF + 1)
//
// from openssl
func constantMod5(n uint32) uint32 {
	return ((n) - 5*(0x3335*(n)>>16))
}

// rejBoundedPoly uses a seed value to generate a polynomial with coefficients in the
// range of ((q-eta)..0..eta) using rejection sampling. eta is either 2 or 4.
// SHAKE256 is used to absorb the seed, and then samples are squeezed.
// See FIPS 204, Algorithm 31, RejBoundedPoly()
func rejBoundedPoly(rho []byte, eta int, highByte, lowByte byte) ringElement {
	H := sha3.NewSHAKE256()
	H.Write(rho)
	H.Write([]byte{lowByte, highByte})

	const blockSize = 136 // SHAKE256 block size in bytes
	var buf [blockSize]byte
	var a ringElement
	var offset, j int

	H.Read(buf[:])

	for {
		z0 := buf[offset] & 0xf
		z1 := buf[offset] >> 4
		offset++

		if eta == 2 {
			if subtle.ConstantTimeByteEq(z0, 15) == 0 {
				a[j] = fieldSub(2, fieldElement(constantMod5(uint32(z0))))
				j++
				if j >= n {
					break
				}
			}
			if subtle.ConstantTimeByteEq(z1, 15) == 0 {
				a[j] = fieldSub(2, fieldElement(constantMod5(uint32(z1))))
				j++
				if j >= n {
					break
				}
			}
		} else if eta == 4 {
			if subtle.ConstantTimeLessOrEq(int(z0), 8) == 1 {
				a[j] = fieldSub(4, fieldElement(z0))
				j++
				if j >= n {
					break
				}
			}
			if subtle.ConstantTimeLessOrEq(int(z1), 8) == 1 {
				a[j] = fieldSub(4, fieldElement(z1))
				j++
				if j >= n {
					break
				}
			}
		}
		if offset >= blockSize {
			H.Read(buf[:])
			offset = 0
		}
	}
	return a
}

// See FIPS 204, Algorithm 34, ExpandMask()
func expandMask(derivedSeed []byte, gamma1 int) (f ringElement) {
	var nu [32 * 20]byte
	l := len(nu)
	if gamma1 == gamma1TwoPower17 {
		l = 32 * 18
	}
	v := nu[:l]
	H := sha3.NewSHAKE256()
	H.Write(derivedSeed)
	H.Read(v)

	switch gamma1 {
	case gamma1TwoPower17:
		bitUnpackSignedTwoPower17(v, &f)
	case gamma1TwoPower19:
		bitUnpackSignedTwoPower19(v, &f)
	default:
		panic("mldsa: invalid gamma1 value")
	}
	return
}

// samples a polynomial with coefficients in the range {-1..1}.
// The number of non zero values (hamming weight) is given by tau
//
// See FIPS 204, Algorithm 29, SampleInBall()
// This function is assumed to not be constant time.
// The algorithm is based on Durstenfeld's version of the Fisher-Yates shuffle.
//
// Note that the coefficients returned by this implementation are positive
// i.e one of q-1, 0, or 1.
func sampleInBall(seed []byte, tao int) (f ringElement) {
	H := sha3.NewSHAKE256()
	H.Write(seed)

	var buf [64]byte
	var index byte
	var signs uint64

	H.Read(buf[:])
	offset := 8
	signs = uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24
	signs |= uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56

	for end := 256 - tao; end < 256; end++ {
		for {
			if offset == 64 {
				H.Read(buf[:])
				offset = 0
			}

			index = buf[offset]
			offset++
			if index <= byte(end) {
				break
			}
		}
		f[end] = f[index]
		f[index] = fieldSub(1, fieldElement(2*(signs&1)))
		signs >>= 1
	}
	return
}
