// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sm4vectors builds the SM4 AEAD and padding vector suites.
//
// Valid ciphertexts come from one of three sources, never from the code under
// test:
//
//   - GCM is produced by Go's generic crypto/cipher implementation over the
//     SM4 block. The wrapper hides any NewGCM method, so the accelerated path
//     under test is never used, and every standard case is checked against
//     GB/T 36624-2018 or GB/T 15852.3-2019 before it is emitted.
//   - CCM is implemented here from CBC-MAC and CTR and checked against
//     RFC 8998 Appendix A.2, which validates the implementation before any
//     other (nonce size, tag size) combination is derived from it.
//   - GCM-SIV and XTS reuse the standard vectors already committed in
//     cipher/*_test.go (RFC 8452 construction, IEEE 1619 and GB/T 17964-2021
//     B.7); their mode arithmetic is covered there and by the differential
//     suites.
//
// Padding vectors are constructed by hand: the padded bytes and the expected
// verdict follow directly from each scheme's definition.
package sm4vectors

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/sm4"
)

const (
	aeadFileName    = "sm4_aead.json"
	paddingFileName = "padding.json"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("sm4vectors: invalid hex constant: " + err.Error())
	}
	return b
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

// plainBlock hides any accelerated NewGCM method from crypto/cipher, so the
// oracle below runs Go's generic GCM instead of the SM4 kernel.
type plainBlock struct{ cipher.Block }

func gcmSeal(key, nonce, plaintext, aad []byte, tagSize int) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wrapped := plainBlock{block}
	var aead cipher.AEAD
	switch {
	case len(nonce) != 12 && tagSize != 16:
		return nil, fmt.Errorf("generic GCM oracle cannot combine a %d-byte nonce with a %d-byte tag", len(nonce), tagSize)
	case len(nonce) != 12:
		aead, err = cipher.NewGCMWithNonceSize(wrapped, len(nonce))
	case tagSize != 16:
		aead, err = cipher.NewGCMWithTagSize(wrapped, tagSize)
	default:
		aead, err = cipher.NewGCM(wrapped)
	}
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// ccmMAC absorbs data into the CBC-MAC state x, zero-padding the final
// partial block.
func ccmMAC(block cipher.Block, x, data []byte) {
	for len(data) >= 16 {
		for i := range 16 {
			x[i] ^= data[i]
		}
		block.Encrypt(x, x)
		data = data[16:]
	}
	if len(data) > 0 {
		var b [16]byte
		copy(b[:], data)
		for i := range 16 {
			x[i] ^= b[i]
		}
		block.Encrypt(x, x)
	}
}

// ccmSeal derives the GB/T 32918.4-style CCM ciphertext from RFC 3610: the
// tag is the CBC-MAC over B0, the associated data and the plaintext, masked
// with E(A0); the plaintext is encrypted with counters starting at one.
func ccmSeal(key, nonce, plaintext, aad []byte, tagSize int) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	lenSize := 15 - len(nonce)

	b0 := make([]byte, 16)
	b0[0] = byte((tagSize-2)/2<<3) | byte(lenSize-1)
	if len(aad) > 0 {
		b0[0] |= 0x40
	}
	copy(b0[1:], nonce)
	for i, v := range plaintextLenBytes(len(plaintext), lenSize) {
		b0[16-lenSize+i] = v
	}

	x := make([]byte, 16)
	block.Encrypt(x, b0)

	if len(aad) > 0 {
		var header []byte
		switch {
		case len(aad) < 0xFF00:
			header = []byte{byte(len(aad) >> 8), byte(len(aad))}
		case uint64(len(aad)) <= 0xFFFFFFFF:
			header = []byte{0xFF, 0xFE, byte(len(aad) >> 24), byte(len(aad) >> 16), byte(len(aad) >> 8), byte(len(aad))}
		default:
			return nil, fmt.Errorf("ccm oracle: aad too long")
		}
		ccmMAC(block, x, append(header, aad...))
	}
	ccmMAC(block, x, plaintext)
	tag := append([]byte(nil), x[:tagSize]...)

	a0 := make([]byte, 16)
	a0[0] = byte(lenSize - 1)
	copy(a0[1:], nonce)
	s0 := make([]byte, 16)
	block.Encrypt(s0, a0)
	for i := range tag {
		tag[i] ^= s0[i]
	}

	out := make([]byte, len(plaintext))
	ctr := append([]byte(nil), a0...)
	for off := 0; off < len(plaintext); off += 16 {
		for i := 15; i >= 16-lenSize; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
		var ks [16]byte
		block.Encrypt(ks[:], ctr)
		for i := 0; i < 16 && off+i < len(plaintext); i++ {
			out[off+i] = plaintext[off+i] ^ ks[i]
		}
	}
	return append(out, tag...), nil
}

func plaintextLenBytes(n, size int) []byte {
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(n)
		n >>= 8
	}
	return out
}

type aeadCase struct {
	tcID       int
	comment    string
	key        string
	nonce      string
	aad        string
	plaintext  string
	ciphertext string
	tagSize    int
	nonceSize  int
}

func (c aeadCase) vector(result string) vectors.Case {
	return vectors.Case{
		TCID:       c.tcID,
		Comment:    c.comment,
		Result:     result,
		Key:        c.key,
		Nonce:      c.nonce,
		AAD:        c.aad,
		Plaintext:  c.plaintext,
		Ciphertext: c.ciphertext,
		TagSize:    c.tagSize,
		NonceSize:  c.nonceSize,
	}
}

// buildGCM pins SM4-GCM. The four standard cases come from GB/T 36624-2018
// C.5 and GB/T 15852.3-2019 A.4; the remaining valid cases exercise a
// non-96-bit nonce and a truncated tag, which only the generic implementation
// can produce.
func buildGCM() ([]vectors.Case, error) {
	const (
		keyZero   = "00000000000000000000000000000000"
		keyFF     = "feffe9928665731c6d6a8f9467308308"
		nonceZero = "000000000000000000000000"
		nonceFF   = "cafebabefacedbaddecaf888"
	)
	standard := []struct {
		tcID       int
		comment    string
		key        string
		nonce      string
		aad        string
		plaintext  string
		ciphertext string
	}{
		{1, "GB/T 36624-2018 C.5: empty plaintext, empty AAD", keyZero, nonceZero, "", "",
			"232f0cfe308b49ea6fc88229b5dc858d"},
		{2, "GB/T 36624-2018 C.5: one zero block", keyZero, nonceZero, "",
			"00000000000000000000000000000000",
			"7de2aa7f1110188218063be1bfeb6d89b851b5f39493752be508f1bb4482c557"},
		{3, "GB/T 15852.3-2019 A.4 GMAC: 16-byte AAD", keyFF, nonceFF,
			"feedfacedeadbeeffeedfacedeadbeef", "", "9d632570f93064264a20918e3081b4cd"},
		{4, "GB/T 15852.3-2019 A.4 GMAC: 40-byte AAD", keyFF, nonceFF,
			"feedfacedeadbeeffeedfacedeadbeefabaddad242831ec2217774244b7221b7", "",
			"1eeaeb669e96bd059bd9929123030e78"},
	}

	var cases []vectors.Case
	for _, s := range standard {
		ct, err := gcmSeal(mustHex(s.key), mustHex(s.nonce), mustHex(s.plaintext), mustHex(s.aad), 16)
		if err != nil {
			return nil, fmt.Errorf("tc%d: %w", s.tcID, err)
		}
		if got := hexStr(ct); got != s.ciphertext {
			return nil, fmt.Errorf("tc%d: generic GCM disagrees with the published vector: got %s, want %s", s.tcID, got, s.ciphertext)
		}
		cases = append(cases, aeadCase{s.tcID, s.comment, s.key, s.nonce, s.aad, s.plaintext, s.ciphertext, 0, 0}.vector("valid"))
	}

	derived := []aeadCase{
		{5, "64-bit nonce", keyZero, "0102030405060708", "a0a1a2",
			"00112233445566778899aabbccddeeff", "", 0, 8},
		{6, "96-bit tag", keyFF, nonceFF, "feedfacedeadbeeffeedfacedeadbeef",
			"00112233445566778899aabbccddeeff", "", 12, 0},
	}
	for i := range derived {
		c := &derived[i]
		ct, err := gcmSeal(mustHex(c.key), mustHex(c.nonce), mustHex(c.plaintext), mustHex(c.aad), tagSizeOr(c.tagSize, 16))
		if err != nil {
			return nil, fmt.Errorf("tc%d: %w", c.tcID, err)
		}
		c.ciphertext = hexStr(ct)
		cases = append(cases, c.vector("valid"))
	}

	// The first two standard cases are the shortest, so they carry the tag
	// truncation tests. The mutation callback returns the new ciphertext so
	// that a truncation actually shortens the emitted value.
	tc := func(i int) aeadCase {
		s := standard[i]
		return aeadCase{s.tcID, s.comment, s.key, s.nonce, s.aad, s.plaintext, s.ciphertext, 0, 0}
	}
	tc1, tc2, tc3 := tc(0), tc(1), tc(2)
	mutate := func(id int, base aeadCase, comment string, f func([]byte) []byte) aeadCase {
		base.tcID = id
		base.comment = comment
		base.ciphertext = hexStr(f(mustHex(base.ciphertext)))
		return base
	}

	invalid := []aeadCase{
		mutate(7, tc1, "tag bit flipped", func(ct []byte) []byte {
			ct[len(ct)-1] ^= 1
			return ct
		}),
		mutate(8, tc2, "tag bit flipped on a one-block message", func(ct []byte) []byte {
			ct[len(ct)-1] ^= 1
			return ct
		}),
		mutate(9, tc1, "shorter than the tag", func(ct []byte) []byte { return ct[:12] }),
		mutate(10, tc2, "truncated by one byte", func(ct []byte) []byte { return ct[:len(ct)-1] }),
		{11, "wrong AAD", tc3.key, tc3.nonce, "feedfacedeadbeeffeedfacedeadbeee", tc3.plaintext, tc3.ciphertext, 0, 0},
		{12, "wrong nonce", tc1.key, "000000000000000000000001", tc1.aad, tc1.plaintext, tc1.ciphertext, 0, 0},
		{13, "tag size below the minimum", keyZero, nonceZero, "", "", "", 8, 0},
		{14, "tag size above the maximum", keyZero, nonceZero, "", "", "", 17, 0},
	}
	for _, c := range invalid {
		cases = append(cases, c.vector("invalid"))
	}
	return cases, nil
}

func tagSizeOr(tagSize, def int) int {
	if tagSize == 0 {
		return def
	}
	return tagSize
}

// buildCCM pins SM4-CCM. The RFC 8998 case validates the CBC-MAC/CTR oracle
// before it produces the non-standard (nonce size, tag size) combinations.
func buildCCM() ([]vectors.Case, error) {
	const (
		rfcKey   = "0123456789abcdeffedcba9876543210"
		rfcNonce = "00001234567800000000abcd"
		rfcAAD   = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
		rfcPlain = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
		rfcCT    = "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b16842d4fa186f56ab33256971fa110f4"
	)

	ct, err := ccmSeal(mustHex(rfcKey), mustHex(rfcNonce), mustHex(rfcPlain), mustHex(rfcAAD), 16)
	if err != nil {
		return nil, err
	}
	if got := hexStr(ct); got != rfcCT {
		return nil, fmt.Errorf("ccm oracle disagrees with RFC 8998 A.2: got %s, want %s", got, rfcCT)
	}

	derived := []aeadCase{
		{2, "empty plaintext with AAD", rfcKey, rfcNonce, "feedfacedeadbeeffeedfacedeadbeef", "", "", 0, 0},
		{3, "7-byte nonce", rfcKey, "00010203040506", "", "0011223344556677", "", 0, 7},
		{4, "13-byte nonce, 64-bit tag", rfcKey, "000102030405060708090a0b0c", "a0a1a2a3", "0011223344556677", "", 8, 13},
		{5, "32-bit tag", rfcKey, rfcNonce, "", "0011223344556677", "", 4, 0},
	}
	cases := []vectors.Case{
		{TCID: 1, Comment: "RFC 8998 A.2", Result: "valid", Key: rfcKey, Nonce: rfcNonce,
			AAD: rfcAAD, Plaintext: rfcPlain, Ciphertext: rfcCT},
	}
	for i := range derived {
		c := &derived[i]
		ct, err := ccmSeal(mustHex(c.key), mustHex(c.nonce), mustHex(c.plaintext), mustHex(c.aad), tagSizeOr(c.tagSize, 16))
		if err != nil {
			return nil, fmt.Errorf("tc%d: %w", c.tcID, err)
		}
		c.ciphertext = hexStr(ct)
		cases = append(cases, c.vector("valid"))
	}

	base := cases[0]
	tagFlip := mustHex(base.Ciphertext)
	tagFlip[len(tagFlip)-1] ^= 1
	truncated := mustHex(base.Ciphertext)[:len(mustHex(base.Ciphertext))-1]
	shortTag := mustHex(base.Ciphertext)[:15]

	invalid := []aeadCase{
		{6, "tag bit flipped", base.Key, base.Nonce, base.AAD, base.Plaintext, hexStr(tagFlip), 0, 0},
		{7, "truncated by one byte", base.Key, base.Nonce, base.AAD, base.Plaintext, hexStr(truncated), 0, 0},
		{8, "shorter than the tag", base.Key, base.Nonce, base.AAD, base.Plaintext, hexStr(shortTag), 0, 0},
		{9, "wrong AAD", base.Key, base.Nonce, "feedfacedeadbeeffeedfacedeadbeea", base.Plaintext, base.Ciphertext, 0, 0},
		{10, "wrong nonce", base.Key, "00001234567800000000abce", base.AAD, base.Plaintext, base.Ciphertext, 0, 0},
		{11, "odd tag size", rfcKey, rfcNonce, "", "", "", 5, 0},
		{12, "nonce too short", rfcKey, "000102030405", "", "", "", 0, 6},
		{13, "nonce too long", rfcKey, "000102030405060708090a0b0c0d", "", "", "", 0, 14},
		{14, "tag too large", rfcKey, rfcNonce, "", "", "", 17, 0},
	}
	for _, c := range invalid {
		cases = append(cases, c.vector("invalid"))
	}
	return cases, nil
}

// buildGCMSIV pins GCM-SIV. The valid ciphertexts are the committed SM4-SIV
// KATs from RFC 8452's construction; the invalid cases are their mutations.
func buildGCMSIV() ([]vectors.Case, error) {
	const (
		sivKey   = "01000000000000000000000000000000"
		sivNonce = "030000000000000000000000"
	)
	valid := []aeadCase{
		{1, "empty plaintext", sivKey, sivNonce, "", "", "1a8a0d12690856bd81e73d4b49a484a6", 0, 0},
		{2, "AAD and 8-byte plaintext", sivKey, sivNonce, "01", "0200000000000000",
			"25a3d08f8c1ab23e168ae39d5edc751b5939a21554bbe86f", 0, 0},
	}
	var cases []vectors.Case
	for _, c := range valid {
		cases = append(cases, c.vector("valid"))
	}

	tagFlip := mustHex(valid[0].ciphertext)
	tagFlip[len(tagFlip)-1] ^= 1
	truncated := mustHex(valid[1].ciphertext)
	truncated = truncated[:len(truncated)-1]

	invalid := []aeadCase{
		{3, "tag bit flipped", sivKey, sivNonce, "", "", hexStr(tagFlip), 0, 0},
		{4, "truncated by one byte", sivKey, sivNonce, "01", "0200000000000000", hexStr(truncated), 0, 0},
		{5, "wrong AAD", sivKey, sivNonce, "02", "0200000000000000", valid[1].ciphertext, 0, 0},
		{6, "wrong nonce", sivKey, "020000000000000000000000", "", "", valid[0].ciphertext, 0, 0},
		{7, "24-byte key", "010000000000000000000000000000000000000000000000", sivNonce, "", "", "", 0, 0},
		{8, "15-byte key", "010000000000000000000000000000", sivNonce, "", "", "", 0, 0},
	}
	for _, c := range invalid {
		cases = append(cases, c.vector("invalid"))
	}
	return cases, nil
}

type xtsCase struct {
	tcID       int
	comment    string
	key        string
	key2       string
	sector     uint64
	tweak      string
	plaintext  string
	ciphertext string
}

func (c xtsCase) vector(result string) vectors.Case {
	return vectors.Case{
		TCID:       c.tcID,
		Comment:    c.comment,
		Result:     result,
		Key:        c.key,
		Key2:       c.key2,
		Sector:     c.sector,
		Tweak:      c.tweak,
		Plaintext:  c.plaintext,
		Ciphertext: c.ciphertext,
	}
}

func splitKey(key string) (string, string) {
	b := mustHex(key)
	return hexStr(b[:len(b)/2]), hexStr(b[len(b)/2:])
}

// buildXTS pins XTS sector encryption, including ciphertext stealing on a
// 25-byte data unit.
func buildXTS() ([]vectors.Case, error) {
	full := []struct {
		tcID       int
		comment    string
		key        string
		sector     uint64
		plaintext  string
		ciphertext string
	}{
		{1, "one 16-byte block, sector 0",
			"0000000000000000000000000000000000000000000000000000000000000000",
			0, "0000000000000000000000000000000000000000000000000000000000000000",
			"d9b421f731c894fdc35b77291fe4e3b02a1fb76698d59f0e51376c4ada5bc75d"},
		{2, "two blocks, sector 0x3333333333",
			"1111111111111111111111111111111122222222222222222222222222222222",
			0x3333333333, "4444444444444444444444444444444444444444444444444444444444444444",
			"a74d726c11196a32be04e001ff29d0c7932f9f3ec29bfcb64dd17f63cbd3ea31"},
		{3, "25-byte data unit, ciphertext stealing",
			"c46acc2e7e013cb71cdbf750cf76b000249fbf4fb6cd17607773c23ffa2c4330",
			94, "7e9c2289cba460e470222953439cdaa892a5433d4dab2a3f67",
			"c3cf5445c64aa518f4abce2848faddfb4605d9fb66f1f12c0c"},
	}
	var cases []vectors.Case
	for _, c := range full {
		key, key2 := splitKey(c.key)
		cases = append(cases, xtsCase{c.tcID, c.comment, key, key2, c.sector, "", c.plaintext, c.ciphertext}.vector("valid"))
	}
	invalid := []xtsCase{
		{4, "15-byte data key", hexStr(repeat(0, 15)), hexStr(repeat(0, 16)), 0, "", "", ""},
		{5, "15-byte tweak key", hexStr(repeat(0, 16)), hexStr(repeat(0, 15)), 0, "", "", ""},
	}
	for _, c := range invalid {
		cases = append(cases, c.vector("invalid"))
	}
	return cases, nil
}

// buildGBXTS pins the GB/T 17964-2021 tweak schedule (B.7), including the
// 61-byte ciphertext-stealing case.
func buildGBXTS() ([]vectors.Case, error) {
	full := []struct {
		tcID       int
		comment    string
		key        string
		tweak      string
		plaintext  string
		ciphertext string
	}{
		{1, "GB/T 17964-2021 B.7: one block",
			"44d5ed13a49771e27533cc8ece9489d757a55435b1871352ec0a08ac1933ae17",
			"d2aa700ffb6a92b265b6177810bd5980",
			"c36f981fc08308ff509d99149481edc2",
			"5da5ce300ef7719ca2d833f7d0662a13"},
		{2, "GB/T 17964-2021 B.7: three blocks",
			"2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f",
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17",
			"e9538251c71d7b80bbe4483fef497bd12c5c581bd6242fc51e08964fb4f60fdb0ba42f63499279213d318d2c11f6886e903be7f93a1b3479"},
		{3, "GB/T 17964-2021 B.7: 61-byte data unit",
			"dacb6342586202826d4078a20579951f21396c4ed74efda349e557b0bce0c15f",
			"5e1d5f6eed82c04da8abeee6f416cf88",
			"6e857aeac5f36165222eed4077df4c74327360cd5050112de5445cf4299e692608754c94a1c8c6cd985513d3df26e5780a6a286baa0679f8af0487297d89e83cdc61571635238145880542e0a0b0cb9d",
			"9b2adabe119edf424b25ff31c952307408c145d7cd7ae83a8fc7a79c387118fb0be89e9658e1d9a83d7919dd9d195a3621237d3baaef3525a58b56519ac64d1f62144450238c7e3a0edc9e1fcb54bfee"},
	}
	var cases []vectors.Case
	for _, c := range full {
		key, key2 := splitKey(c.key)
		cases = append(cases, xtsCase{c.tcID, c.comment, key, key2, 0, c.tweak, c.plaintext, c.ciphertext}.vector("valid"))
	}
	invalid := []xtsCase{
		{4, "15-byte tweak", hexStr(repeat(0, 16)), hexStr(repeat(0, 16)), 0, hexStr(repeat(0, 15)), "", ""},
		{5, "15-byte tweak key", hexStr(repeat(0, 16)), hexStr(repeat(0, 15)), 0, hexStr(repeat(0, 16)), "", ""},
	}
	for _, c := range invalid {
		cases = append(cases, c.vector("invalid"))
	}
	return cases, nil
}

// BuildAEADSuite builds the AEAD and XTS suite.
func BuildAEADSuite() (*vectors.Suite, error) {
	gcm, err := buildGCM()
	if err != nil {
		return nil, err
	}
	ccm, err := buildCCM()
	if err != nil {
		return nil, err
	}
	siv, err := buildGCMSIV()
	if err != nil {
		return nil, err
	}
	xts, err := buildXTS()
	if err != nil {
		return nil, err
	}
	gbxts, err := buildGBXTS()
	if err != nil {
		return nil, err
	}
	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "sm4",
		Generator: "go test ./internal/cryptotest/sm4vectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			{
				Type:    "GCM",
				Comment: "SM4-GCM. Ciphertext is C||T unless a truncated tag is configured. The standard cases are checked against GB/T 36624-2018 and GB/T 15852.3-2019; the generic Go implementation, not the SM4 kernel, produces the derived nonce and tag sizes.",
				Tests:   gcm,
			},
			{
				Type:    "CCM",
				Comment: "SM4-CCM as specified by RFC 3610. The RFC 8998 A.2 case validates the independent CBC-MAC/CTR implementation used to derive the 7- and 13-byte nonce and 32-bit tag cases.",
				Tests:   ccm,
			},
			{
				Type:    "GCMSIV",
				Comment: "SM4-GCM-SIV. The valid ciphertexts are the committed SM4-SIV KATs; every invalid case is a single-point mutation of one of them, and the tag check must fail.",
				Tests:   siv,
			},
			{
				Type:    "XTS",
				Comment: "SM4-XTS with the IEEE 1619 tweak schedule, addressed by sector number. The 25-byte data unit exercises ciphertext stealing.",
				Tests:   xts,
			},
			{
				Type:    "GBXTS",
				Comment: "SM4-XTS with the GB/T 17964-2021 tweak schedule, addressed by a raw 16-byte tweak. The 61-byte data unit exercises ciphertext stealing.",
				Tests:   gbxts,
			},
		},
	}
	if err := suite.Validate(); err != nil {
		return nil, err
	}
	return suite, nil
}

type paddingCase struct {
	tcID    int
	comment string
	input   []byte
	want    []byte
}

func (c paddingCase) vector(blockSize int, valid bool) vectors.Case {
	tc := vectors.Case{
		TCID:    c.tcID,
		Comment: c.comment,
		Input:   hexStr(c.input),
		Flags:   []string{fmt.Sprintf("BlockSize%d", blockSize)},
	}
	if valid {
		tc.Result = "valid"
		tc.Expected = hexStr(c.want)
	} else {
		tc.Result = "invalid"
	}
	return tc
}

// buildPadding pins the unpadding side of each scheme: it is the direction
// that consumes attacker-controlled bytes. Pad is covered by the package
// tests, so the vectors only carry the padded input and the expected verdict.
func buildPadding() (map[string][]vectors.Case, error) {
	const bs = 16
	seq := func(n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(i)
		}
		return out
	}

	pkcs7 := []paddingCase{
		{1, "whole block of padding", repeat(0x10, bs), []byte{}},
		{2, "one byte and fifteen pad bytes", append([]byte{0x01}, repeat(0x0f, 15)...), []byte{0x01}},
		{3, "fifteen bytes and one pad byte", append(seq(15), 0x01), seq(15)},
		{4, "aligned plaintext gets a full block", append(seq(16), repeat(0x10, 16)...), seq(16)},
		{5, "empty input", nil, nil},
		{6, "length not a multiple of the block size", append(seq(16), 0x00), nil},
		{7, "zero pad byte", repeat(0x00, bs), nil},
		{8, "pad byte above the block size", append(repeat(0x00, 15), 0x11), nil},
		{9, "inconsistent pad bytes", append(repeat(0x10, 15), 0x0f), nil},
		{10, "all ones", repeat(0xff, bs), nil},
	}

	ansi := []paddingCase{
		{1, "whole block of padding", append(repeat(0x00, 15), 0x10), []byte{}},
		{2, "one byte and fifteen pad bytes", append([]byte{0x01}, append(repeat(0x00, 14), 0x0f)...), []byte{0x01}},
		{3, "fifteen bytes and one pad byte", append(seq(15), 0x01), seq(15)},
		{4, "non-zero filler byte", append(append([]byte{0x01}, repeat(0x00, 14)...), 0x10), nil},
		{5, "zero pad byte", repeat(0x00, bs), nil},
		{6, "pad byte above the block size", append(repeat(0x00, 15), 0x11), nil},
		{7, "empty input", nil, nil},
		{8, "length not a multiple of the block size", append(seq(16), 0x00), nil},
	}

	iso2 := []paddingCase{
		{1, "whole block of padding", append([]byte{0x80}, repeat(0x00, 15)...), []byte{}},
		{2, "one byte and fifteen pad bytes", append([]byte{0x01, 0x80}, repeat(0x00, 14)...), []byte{0x01}},
		{3, "fifteen bytes and the 0x80 marker", append(seq(15), 0x80), seq(15)},
		{4, "aligned plaintext gets a full block", append(append(seq(16), 0x80), repeat(0x00, 15)...), seq(16)},
		{5, "no 0x80 marker", repeat(0x00, bs), nil},
		{6, "last byte is not the marker", append(repeat(0x00, 15), 0x01), nil},
		{7, "empty input", nil, nil},
		{8, "length not a multiple of the block size", append(seq(16), 0x00), nil},
	}

	header := func(bits uint64) []byte {
		h := make([]byte, bs)
		for i := 0; i < 8; i++ {
			h[15-i] = byte(bits)
			bits >>= 8
		}
		return h
	}
	badHeader := append(header(32), []byte("abcd")...)
	badHeader = append(badHeader, repeat(0x00, 12)...)
	badHeader[0] = 0x01

	iso3 := []paddingCase{
		{1, "empty plaintext", repeat(0x00, 2*bs), []byte{}},
		{2, "four-byte plaintext", append(append(header(32), []byte("abcd")...), repeat(0x00, 12)...), []byte("abcd")},
		{3, "aligned plaintext", append(header(128), seq(16)...), seq(16)},
		{4, "empty input", nil, nil},
		{5, "shorter than two blocks", repeat(0x00, bs), nil},
		{6, "non-zero header", badHeader, nil},
		{7, "length field too large", append(header(1<<40), repeat(0x00, 16)...), nil},
		{8, "non-zero byte after the plaintext", append(append(header(32), []byte("abcd")...), append(repeat(0x00, 11), 0x01)...), nil},
		{9, "extra zero block after an aligned plaintext", append(append(header(128), seq(16)...), repeat(0x00, 16)...), seq(16)},
	}

	zero := []paddingCase{
		{1, "all bytes are padding", repeat(0x00, bs), []byte{}},
		{2, "trailing zeros are stripped", append([]byte{0x01, 0x02}, repeat(0x00, 14)...), []byte{0x01, 0x02}},
		{3, "no padding to remove", append(seq(15), 0x10), append(seq(15), 0x10)},
		{4, "empty input", nil, nil},
		{5, "length not a multiple of the block size", append(repeat(0x00, 16), 0x01), nil},
	}

	groups := map[string][]vectors.Case{}
	for name, cases := range map[string][]paddingCase{
		"PKCS7": pkcs7, "ANSIX923": ansi, "ISO9797M2": iso2, "ISO9797M3": iso3, "ZeroPadding": zero,
	} {
		out := make([]vectors.Case, 0, len(cases))
		for _, c := range cases {
			out = append(out, c.vector(bs, c.want != nil))
		}
		groups[name] = out
	}
	return groups, nil
}

// BuildPaddingSuite builds the padding suite. Every scheme runs at the SM4
// block size.
func BuildPaddingSuite() (*vectors.Suite, error) {
	groups, err := buildPadding()
	if err != nil {
		return nil, err
	}
	order := []struct{ name, comment string }{
		{"PKCS7", "PKCS#7: every padding byte equals the padding length, and a full block is always added."},
		{"ANSIX923", "ANSI X.923: zero fillers followed by the padding length."},
		{"ISO9797M2", "ISO/IEC 9797-1 method 2: a 0x80 marker followed by zeros."},
		{"ISO9797M3", "ISO/IEC 9797-1 method 3: a length header prepended to the data, then zero fill."},
		{"ZeroPadding", "Zero padding: trailing zeros are stripped; the all-zero block is valid and unpads to empty."},
	}
	var list []vectors.Group
	for _, g := range order {
		list = append(list, vectors.Group{Type: g.name, Comment: g.comment, Tests: groups[g.name]})
	}
	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "padding",
		Generator: "go test ./internal/cryptotest/sm4vectors -run TestVectorsUpToDate -update",
		Groups:    list,
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
