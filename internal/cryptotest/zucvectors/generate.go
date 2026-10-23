// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package zucvectors builds the ZUC EEA and EIA vector suite.
//
// The keystream and MAC cases are the official GB/T 33133 vectors already
// committed in zuc/eea_test.go and zuc/eia_test.go. The frame IV that the
// EEA and EIA entry points derive from (count, bearer, direction) is computed
// here from the published bit layout, so the suite checks the library against
// the standard twice: once through the frame API, which derives the IV
// itself, and once through the raw key/IV API fed with the IV derived here.
//
// The constructed EIA cases at 1, 7, 8, 31, 32, 33, 63, 64, 65, 127 and 128
// bits are regression pins: the official 577- and 5670-bit vectors anchor
// the bit-oriented path, and these cases pin the block and word boundaries
// between them. Their expected values were recorded from the implementation
// before it was frozen here.
package zucvectors

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

const fileName = "zuc_semantics.json"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("zucvectors: invalid hex constant: " + err.Error())
	}
	return b
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func seq(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// eeaFrameIV derives the 16-byte ZUC-128 EEA frame IV from the 32-bit frame
// counter, the 5-bit bearer identity and the 1-bit direction flag. The bearer
// and direction bits share the octet that follows the counter, and the counter
// followed by that octet is repeated to fill the 128-bit IV.
func eeaFrameIV(count, bearer, direction uint32) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv, count)
	copy(iv[8:], iv[:4])
	iv[4] = byte(((bearer << 1) | (direction & 1)) << 2)
	iv[12] = iv[4]
	return iv
}

// eiaFrameIV derives the 16-byte ZUC-128 EIA frame IV. The layout differs from
// the EEA one: the direction bit stays out of the bearer octet and appears at
// the top of the second counter copy and in the fourteenth octet. Both layouts
// are anchored by the official test sets, which cover direction = 1 for EEA
// (test set 2) and EIA (test set 2).
func eiaFrameIV(count, bearer, direction uint32) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv, count)
	copy(iv[9:12], iv[1:4])
	iv[4] = byte(bearer << 3)
	iv[12] = iv[4]
	iv[8] = iv[0] ^ byte(direction<<7)
	iv[14] = byte(direction << 7)
	return iv
}

// buildEEA pins the EEA keystream. Each case carries the frame parameters and
// the IV derived from them, so the consumer can run both entry points.
func buildEEA() []vectors.Case {
	out := make([]vectors.Case, 0, len(officialEEA))
	for i, v := range officialEEA {
		out = append(out, vectors.Case{
			TCID:      i + 1,
			Comment:   fmt.Sprintf("GB/T 33133 EEA test set %d", i+1),
			Result:    "valid",
			Key:       v.key,
			Nonce:     hexStr(eeaFrameIV(v.count, v.bearer, v.direction)),
			Count:     v.count,
			Bearer:    v.bearer,
			Direction: v.direction,
			Input:     v.in,
			Expected:  v.out,
		})
	}
	return out
}

// buildEEAInit pins the key and IV length checks of the stream cipher
// constructor. The 32/23 combination selects ZUC-256.
func buildEEAInit() []vectors.Case {
	key16 := hexStr(repeat(0x11, 16))
	key31 := hexStr(repeat(0x33, 31))
	key32 := hexStr(repeat(0x33, 32))
	iv16 := hexStr(repeat(0x22, 16))
	iv23 := hexStr(repeat(0x44, 23))

	cases := []struct {
		tcID    int
		comment string
		key     string
		nonce   string
		result  string
	}{
		{1, "15-byte key", hexStr(repeat(0x11, 15)), iv16, "invalid"},
		{2, "17-byte key", hexStr(repeat(0x11, 17)), iv16, "invalid"},
		{3, "15-byte iv", key16, hexStr(repeat(0x22, 15)), "invalid"},
		{4, "17-byte iv", key16, hexStr(repeat(0x22, 17)), "invalid"},
		{5, "32-byte key with a 16-byte iv", key32, iv16, "invalid"},
		{6, "16-byte key with a 23-byte iv", key16, iv23, "invalid"},
		{7, "31-byte key with a 23-byte iv", key31, iv23, "invalid"},
		{8, "32-byte key with a 23-byte iv selects ZUC-256", key32, iv23, "valid"},
	}
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		out = append(out, vectors.Case{
			TCID:    c.tcID,
			Comment: c.comment,
			Result:  c.result,
			Key:     c.key,
			Nonce:   c.nonce,
		})
	}
	return out
}

// constructedEIA holds the pinned MACs for the 32-byte message and the
// all-zero IV under the 0x5a key.
var constructedEIA = []struct {
	nbits int
	mac   string
}{
	{1, "bebdc477"},
	{7, "a725890b"},
	{8, "a9b714f9"},
	{31, "100f8983"},
	{32, "b350646f"},
	{33, "e597c564"},
	{63, "b7577847"},
	{64, "ea037a1d"},
	{65, "af290d0b"},
	{127, "e8410d0e"},
	{128, "a4e4e992"},
}

// buildEIA pins the ZUC-128 MAC. The official cases use the published frame
// parameters; the constructed cases use a zero count, bearer and direction,
// whose frame IV is all zero, and a fixed 32-byte message.
func buildEIA() []vectors.Case {
	var out []vectors.Case
	for i, v := range officialEIA {
		out = append(out, vectors.Case{
			TCID:      i + 1,
			Comment:   fmt.Sprintf("GB/T 33133 EIA test set %d, %d-bit message", i+1, v.nbits),
			Result:    "valid",
			Key:       v.key,
			Nonce:     hexStr(eiaFrameIV(v.count, v.bearer, v.direction)),
			Count:     v.count,
			Bearer:    v.bearer,
			Direction: v.direction,
			Input:     v.in,
			BitLen:    v.nbits,
			Expected:  v.mac,
		})
	}
	key := hexStr(repeat(0x5a, 16))
	msg := hexStr(seq(32))
	for i, c := range constructedEIA {
		out = append(out, vectors.Case{
			TCID:     len(officialEIA) + i + 1,
			Comment:  fmt.Sprintf("constructed: %d bits of a 32-byte message", c.nbits),
			Result:   "valid",
			Key:      key,
			Nonce:    hexStr(eiaFrameIV(0, 0, 0)),
			Input:    msg,
			BitLen:   c.nbits,
			Expected: c.mac,
		})
	}
	return out
}

// buildEIA256 pins the ZUC-256 MAC for the three supported tag sizes. Each
// official case is emitted once per tag size.
func buildEIA256() []vectors.Case {
	cases := []struct {
		keyHex  string
		ivHex   string
		msgHex  string
		nMsgs   int
		macs    [3]string
		comment string
	}{
		{hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), hexStr(repeat(0x00, 50)), 1,
			[3]string{"9b972a74", "673e54990034d38c", "d85e54bbcb9600967084c952a1654b26"},
			"GB/T 33133 ZUC-256 test set 1: zero key and iv"},
		{hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), hexStr(repeat(0x11, 50)), 10,
			[3]string{"8754f5cf", "130dc225e72240cc", "df1e8307b31cc62beca1ac6f8190c22f"},
			"GB/T 33133 ZUC-256 test set 2: zero key and iv, ten 0x11 messages"},
		{hexStr(repeat(0xff, 32)), hexStr(repeat(0xff, 23)), hexStr(repeat(0x00, 50)), 1,
			[3]string{"1f3079b4", "8c71394d39957725", "a35bb274b567c48b28319f111af34fbd"},
			"GB/T 33133 ZUC-256 test set 3: all-ones key and iv"},
		{hexStr(repeat(0xff, 32)), hexStr(repeat(0xff, 23)), hexStr(repeat(0x11, 50)), 10,
			[3]string{"5c7c8b88", "ea1dee544bb6223b", "3a83b554be408ca5494124ed9d473205"},
			"GB/T 33133 ZUC-256 test set 4: all-ones key and iv, ten 0x11 messages"},
	}
	tagSizes := [3]int{4, 8, 16}
	var out []vectors.Case
	for _, c := range cases {
		msg := mustHex(c.msgHex)
		input := make([]byte, 0, len(msg)*c.nMsgs)
		for range c.nMsgs {
			input = append(input, msg...)
		}
		for i, tagSize := range tagSizes {
			out = append(out, vectors.Case{
				TCID:     len(out) + 1,
				Comment:  fmt.Sprintf("%s, %d-byte tag", c.comment, tagSize),
				Result:   "valid",
				Key:      c.keyHex,
				Nonce:    c.ivHex,
				Input:    hexStr(input),
				TagSize:  tagSize,
				Expected: c.macs[i],
			})
		}
	}

	invalid := []struct {
		tcID    int
		comment string
		key     string
		nonce   string
		tagSize int
	}{
		{len(out) + 1, "1-byte tag", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), 1},
		{len(out) + 2, "15-byte tag", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), 15},
		{len(out) + 3, "17-byte tag", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), 17},
		{len(out) + 4, "32-byte tag", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 23)), 32},
		{len(out) + 5, "31-byte key", hexStr(repeat(0x00, 31)), hexStr(repeat(0x00, 23)), 4},
		{len(out) + 6, "22-byte iv", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 22)), 4},
		{len(out) + 7, "24-byte iv", hexStr(repeat(0x00, 32)), hexStr(repeat(0x00, 24)), 4},
	}
	for _, c := range invalid {
		out = append(out, vectors.Case{
			TCID:    c.tcID,
			Comment: c.comment,
			Result:  "invalid",
			Key:     c.key,
			Nonce:   c.nonce,
			TagSize: c.tagSize,
			Input:   hexStr(repeat(0x00, 16)),
		})
	}
	return out
}

// BuildSuite builds the ZUC suite.
func BuildSuite() (*vectors.Suite, error) {
	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "zuc",
		Generator: "go test ./internal/cryptotest/zucvectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			{
				Type:    "ZUCEEA",
				Comment: "ZUC-128 EEA keystream from the GB/T 33133 test sets. Each case carries the frame parameters and the frame IV derived from them, so the frame API and the raw key/IV API must agree with the published keystream.",
				Tests:   buildEEA(),
			},
			{
				Type:    "ZUCEEAInit",
				Comment: "Stream cipher key and IV length checks. A 32-byte key with a 23-byte IV selects ZUC-256; every mismatched combination must be rejected.",
				Tests:   buildEEAInit(),
			},
			{
				Type:    "ZUCEIA",
				Comment: "ZUC-128 EIA MAC. The official 1-, 577- and 5670-bit vectors anchor the bit-oriented path; the constructed cases pin the word and block boundaries between them.",
				Tests:   buildEIA(),
			},
			{
				Type:    "ZUC256EIA",
				Comment: "ZUC-256 EIA MAC from the GB/T 33133 test sets, once per supported tag size (4, 8 and 16 bytes), plus the rejected tag, key and IV sizes.",
				Tests:   buildEIA256(),
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
