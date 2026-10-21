// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sm3vectors builds the SM3 hash and KDF vector suite.
//
// Every expected value is produced by the reference implementation below,
// which is written from GB/T 32905-2016 rather than from the package under
// test. The reference is validated against the published "abc" and
// sixteen-"abcd" digests before a single case is emitted, so the suite pins
// the library to the standard instead of to itself.
//
// The hash cases straddle the padding boundary: a message of 55 bytes still
// fits the length field into the same block, 56 bytes forces an extra block,
// and 63/64/65 and 119/120 straddle the same boundary one and two blocks
// later. The KDF cases cover the output lengths around the 32-byte digest
// size, where an off-by-one in the counter loop shows up as an extra or a
// missing block.
package sm3vectors

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

const fileName = "sm3_semantics.json"

var (
	refIV = [8]uint32{
		0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
		0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
	}
	// Published digests used to validate the reference before it is used.
	abcDigest = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	// GB/T 32905-2016 A.2: "abcd" repeated sixteen times.
	abcd16Digest = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
)

func rotl(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }

func p0(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }

func p1(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

// compress applies the message expansion and the 64-round compression
// function of GB/T 32905-2016 5.3.3 to one 64-byte block.
func compress(v *[8]uint32, block []byte) {
	var w [68]uint32
	var w1 [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[i*4:])
	}
	for j := 16; j < 68; j++ {
		w[j] = p1(w[j-16]^w[j-9]^rotl(w[j-3], 15)) ^ rotl(w[j-13], 7) ^ w[j-6]
	}
	for j := 0; j < 64; j++ {
		w1[j] = w[j] ^ w[j+4]
	}

	a, b, c, d, e, f, g, h := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
	for j := 0; j < 64; j++ {
		var ff, gg, tj uint32
		if j < 16 {
			ff = a ^ b ^ c
			gg = e ^ f ^ g
			tj = 0x79cc4519
		} else {
			ff = (a & b) | (a & c) | (b & c)
			gg = (e & f) | (^e & g)
			tj = 0x7a879d8a
		}
		ss1 := rotl(rotl(a, 12)+e+rotl(tj, uint(j%32)), 7)
		ss2 := ss1 ^ rotl(a, 12)
		tt1 := ff + d + ss2 + w1[j]
		tt2 := gg + h + ss1 + w[j]
		d, c, b, a = c, rotl(b, 9), a, tt1
		h, g, f, e = g, rotl(f, 19), e, p0(tt2)
	}
	v[0] ^= a
	v[1] ^= b
	v[2] ^= c
	v[3] ^= d
	v[4] ^= e
	v[5] ^= f
	v[6] ^= g
	v[7] ^= h
}

// sm3Ref is the reference digest. It is independent of the package under
// test: the padding, the message expansion and the compression function are
// transcribed from the standard.
func sm3Ref(msg []byte) [32]byte {
	padded := make([]byte, 0, len(msg)+72)
	padded = append(padded, msg...)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0)
	}
	padded = binary.BigEndian.AppendUint64(padded, uint64(len(msg))*8)

	v := refIV
	for i := 0; i < len(padded); i += 64 {
		compress(&v, padded[i:i+64])
	}
	var out [32]byte
	for i := range 8 {
		binary.BigEndian.PutUint32(out[i*4:], v[i])
	}
	return out
}

// kdfRef derives outLen bytes the way GB/T 32918.4-2016 5.4.3 defines the
// SM3-based KDF: the concatenation of SM3(z || counter), counter a 32-bit
// big-endian integer starting at one, truncated to outLen.
func kdfRef(z []byte, outLen int) []byte {
	var out []byte
	for counter := uint32(1); len(out) < outLen; counter++ {
		block := make([]byte, 0, len(z)+4)
		block = append(block, z...)
		block = binary.BigEndian.AppendUint32(block, counter)
		digest := sm3Ref(block)
		out = append(out, digest[:]...)
	}
	return out[:outLen]
}

func seq(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// buildHash pins the digest of messages that sit on the padding boundary.
func buildHash() []vectors.Case {
	messages := []struct {
		tcID    int
		comment string
		msg     []byte
	}{
		{1, "GB/T 32905-2016 A.1: abc", []byte("abc")},
		{2, "empty message", nil},
		{3, "one byte", seq(1)},
		{4, "three bytes", seq(3)},
		{5, "55 bytes: the length field still fits the first block", seq(55)},
		{6, "56 bytes: the length field forces an extra block", seq(56)},
		{7, "63 bytes", seq(63)},
		{8, "64 bytes: one full block", seq(64)},
		{9, "65 bytes", seq(65)},
		{10, "119 bytes", seq(119)},
		{11, "120 bytes", seq(120)},
		{12, "127 bytes", seq(127)},
		{13, "128 bytes: two full blocks", seq(128)},
	}
	cases := make([]vectors.Case, 0, len(messages))
	for _, m := range messages {
		digest := sm3Ref(m.msg)
		cases = append(cases, vectors.Case{
			TCID:     m.tcID,
			Comment:  m.comment,
			Msg:      hexStr(m.msg),
			Expected: hexStr(digest[:]),
		})
	}
	return cases
}

// buildKDF pins the KDF output lengths around the digest size. A zero length
// must return an empty key, not one block; a length of 33 must return two
// blocks truncated to one byte past the first block.
func buildKDF() []vectors.Case {
	z := seq(80)
	lengths := []struct {
		tcID    int
		comment string
		z       []byte
		keyLen  int
	}{
		{1, "zero-length output", z, 0},
		{2, "one byte", z, 1},
		{3, "one byte short of a block", z, 31},
		{4, "exactly one block", z, 32},
		{5, "one byte into the second block", z, 33},
		{6, "one byte short of two blocks", z, 63},
		{7, "exactly two blocks", z, 64},
		{8, "one byte into the third block", z, 65},
		{9, "exactly three blocks", z, 96},
		{10, "four blocks plus one byte", z, 129},
		{11, "empty shared secret", nil, 32},
	}
	cases := make([]vectors.Case, 0, len(lengths))
	for _, c := range lengths {
		cases = append(cases, vectors.Case{
			TCID:     c.tcID,
			Comment:  c.comment,
			Input:    hexStr(c.z),
			KeyLen:   c.keyLen,
			Expected: hexStr(kdfRef(c.z, c.keyLen)),
		})
	}
	return cases
}

// BuildSuite builds the SM3 suite.
func BuildSuite() (*vectors.Suite, error) {
	if got := sm3Ref([]byte("abc")); hexStr(got[:]) != abcDigest {
		return nil, fmt.Errorf("reference SM3 disagrees with GB/T 32905-2016 A.1: got %x, want %s", got, abcDigest)
	}
	abcd16 := make([]byte, 0, 64)
	for range 16 {
		abcd16 = append(abcd16, "abcd"...)
	}
	if got := sm3Ref(abcd16); hexStr(got[:]) != abcd16Digest {
		return nil, fmt.Errorf("reference SM3 disagrees with GB/T 32905-2016 A.2: got %x, want %s", got, abcd16Digest)
	}

	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "sm3",
		Generator: "go test ./internal/cryptotest/sm3vectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			{
				Type:    "SM3Hash",
				Comment: "SM3 digests at and around the 64-byte block and 56-byte length-field boundaries. The expected values come from an independent implementation written from GB/T 32905-2016.",
				Tests:   buildHash(),
			},
			{
				Type:    "SM3KDF",
				Comment: "SM3-based KDF output lengths around the 32-byte digest size, plus the zero-length output and an empty shared secret. The expected values come from the same independent SM3.",
				Tests:   buildKDF(),
			},
		},
	}
	if err := suite.Validate(); err != nil {
		return nil, err
	}
	return suite, nil
}

// MarshalSuite renders a suite the way the committed files are stored.
func MarshalSuite(s *vectors.Suite) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
