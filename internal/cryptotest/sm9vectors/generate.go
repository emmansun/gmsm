// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sm9vectors builds the SM9 signature, encryption and key parsing
// vector suite.
//
// The baseline cases are the published GB/T 32918.5 examples: the signature
// of "Chinese IBS standard" by Alice under hid 1, and the ciphertext of
// "Chinese IBE standard" for Bob under hid 3. Everything the standard does
// not publish is derived from it by a single, documented mutation: one byte
// flipped, one field truncated, one value pushed out of range. The expected
// verdict of each mutation follows from the algorithm, not from the library,
// so the suite records which malformed inputs must be rejected.
//
// Key material is written out rather than derived at generation time. The
// user keys below are the GB/T 32918.5 user keys obtained from the published
// master keys; writing them down keeps the generator from depending on the
// package under test.
package sm9vectors

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

const fileName = "sm9_semantics.json"

// GB/T 32918.5 signature example.
const (
	signMasterPubHex = "049f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d"
	signUserKeyHex   = "04a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa6982078559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3"
	signMasterKeyHex = "000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"
	signUID          = "Alice"
	signHID          = 1
	signMessage      = "Chinese IBS standard"
	signHashHex      = "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb"
	signSHex         = "0473bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
)

// GB/T 32918.5 encryption example.
const (
	encMasterPubHex  = "04787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"
	encUserKeyHex    = "0494736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
	encMasterKeyHex  = "0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22"
	encUID           = "Bob"
	encHID           = 3
	encPlaintext     = "Chinese IBE standard"
	encCiphertextHex = "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f3671b5f5b0e951489682f3e64e1378cdd5da9513b1c"
)

// sm9OrderHex is the order of the SM9 groups G1, G2 and GT. It is not the
// SM2 group order, and the two are easy to confuse when building an
// out-of-range scalar case.
const sm9OrderHex = "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("sm9vectors: invalid hex constant: " + err.Error())
	}
	return b
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// orderMinus1 returns N-1, the largest scalar below the group order.
func orderMinus1() []byte {
	n, ok := new(big.Int).SetString(sm9OrderHex, 16)
	if !ok {
		panic("sm9vectors: invalid group order")
	}
	return n.Sub(n, big.NewInt(1)).FillBytes(make([]byte, 32))
}

// marshalInt renders a scalar as the DER INTEGER the master private key
// parsers expect.
func marshalInt(scalar []byte) []byte {
	der, err := asn1.Marshal(new(big.Int).SetBytes(scalar))
	if err != nil {
		panic("sm9vectors: marshalling scalar: " + err.Error())
	}
	return der
}

type sm9Signature struct {
	H []byte
	S asn1.BitString
}

// marshalSignature renders h and s as SEQUENCE { OCTET STRING, BIT STRING }.
func marshalSignature(h, s []byte) []byte {
	der, err := asn1.Marshal(sm9Signature{H: h, S: asn1.BitString{Bytes: s, BitLength: len(s) * 8}})
	if err != nil {
		panic("sm9vectors: marshalling signature: " + err.Error())
	}
	return der
}

// flipLast returns a copy of b with the low bit of the last byte inverted,
// which moves a point off its curve.
func flipLast(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 1
	return out
}

// buildSignatureVerify pins signature verification. Every invalid case is
// the standard signature with exactly one field out of range, malformed or
// replaced.
func buildSignatureVerify() []vectors.Case {
	h := mustHex(signHashHex)
	s := mustHex(signSHex)
	valid := marshalSignature(h, s)
	zero := make([]byte, 32)
	identity := make([]byte, 65)
	identity[0] = 4

	cases := []struct {
		tcID    int
		comment string
		uid     string
		hid     int
		hash    []byte
		sig     []byte
		result  string
	}{
		{1, "GB/T 32918.5 signature over the published message", signUID, signHID, []byte(signMessage), valid, "valid"},
		{2, "h is zero", signUID, signHID, []byte(signMessage), marshalSignature(zero, s), "invalid"},
		{3, "h equals the group order", signUID, signHID, []byte(signMessage), marshalSignature(mustHex(sm9OrderHex), s), "invalid"},
		{4, "h is N-1, in range but not the signed value", signUID, signHID, []byte(signMessage), marshalSignature(orderMinus1(), s), "invalid"},
		{5, "h carries a leading zero byte", signUID, signHID, []byte(signMessage),
			marshalSignature(append([]byte{0}, h...), s), "invalid"},
		{6, "h truncated by one byte", signUID, signHID, []byte(signMessage), marshalSignature(h[1:], s), "invalid"},
		{7, "s is not on the curve", signUID, signHID, []byte(signMessage), marshalSignature(h, flipLast(s)), "invalid"},
		{8, "s is the identity", signUID, signHID, []byte(signMessage), marshalSignature(h, identity), "invalid"},
		{9, "s omits the 0x04 prefix", signUID, signHID, []byte(signMessage), marshalSignature(h, s[1:]), "invalid"},
		{10, "wrong user id", "Bob", signHID, []byte(signMessage), valid, "invalid"},
		{11, "wrong hid", signUID, 2, []byte(signMessage), valid, "invalid"},
		{12, "wrong message", signUID, signHID, []byte("chinese ibs standard"), valid, "invalid"},
		{13, "trailing byte after the signature", signUID, signHID, []byte(signMessage), append(append([]byte(nil), valid...), 0), "invalid"},
		{14, "empty user id", "", signHID, []byte(signMessage), valid, "invalid"},
		{15, "signature truncated by one byte", signUID, signHID, []byte(signMessage), valid[:len(valid)-1], "invalid"},
		{16, "empty signature", signUID, signHID, []byte(signMessage), nil, "invalid"},
	}
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		out = append(out, vectors.Case{
			TCID:    c.tcID,
			Comment: c.comment,
			Result:  c.result,
			Pub:     signMasterPubHex,
			UID:     hexStr([]byte(c.uid)),
			HID:     c.hid,
			Msg:     hexStr(c.hash),
			Sig:     hexStr(c.sig),
		})
	}
	return out
}

// buildDecrypt pins decryption of the standard ciphertext. The MAC covers
// C2 and the KDF output, so flipping a C2 byte and flipping a C3 byte must
// both be rejected; the C1 point must be on the curve and not the identity.
func buildDecrypt() []vectors.Case {
	ciphertext := mustHex(encCiphertextHex)
	plaintext := []byte(encPlaintext)
	if got, want := len(ciphertext), 64+32+len(plaintext); got != want {
		panic(fmt.Sprintf("sm9vectors: the published ciphertext has %d bytes, want %d", got, want))
	}
	c3 := append([]byte(nil), ciphertext...)
	c3[64] ^= 1
	c2 := append([]byte(nil), ciphertext...)
	c2[len(c2)-1] ^= 1
	c1 := append([]byte(nil), ciphertext...)
	c1[63] ^= 1
	identity := append(make([]byte, 64), ciphertext[64:]...)

	cases := []struct {
		tcID    int
		comment string
		uid     string
		ct      []byte
		result  string
	}{
		{1, "GB/T 32918.5 ciphertext for the published plaintext", encUID, ciphertext, "valid"},
		{2, "C3 byte flipped", encUID, c3, "invalid"},
		{3, "C2 byte flipped", encUID, c2, "invalid"},
		{4, "C1 coordinate flipped", encUID, c1, "invalid"},
		{5, "C1 is the identity", encUID, identity, "invalid"},
		{6, "truncated by one byte", encUID, ciphertext[:len(ciphertext)-1], "invalid"},
		{7, "C1 and C3 only, no C2", encUID, ciphertext[:96], "invalid"},
		{8, "trailing byte", encUID, append(append([]byte(nil), ciphertext...), 0), "invalid"},
		{9, "wrong user id", "Alice", ciphertext, "invalid"},
		{10, "empty user id", "", ciphertext, "invalid"},
		{11, "empty ciphertext", encUID, nil, "invalid"},
	}
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		tc := vectors.Case{
			TCID:       c.tcID,
			Comment:    c.comment,
			Result:     c.result,
			Priv:       encUserKeyHex,
			UID:        hexStr([]byte(c.uid)),
			Ciphertext: hexStr(c.ct),
			Ordering:   "C1C3C2",
		}
		if c.result == "valid" {
			tc.Expected = hexStr(plaintext)
		}
		out = append(out, tc)
	}
	return out
}

type keyCase struct {
	tcID     int
	comment  string
	material []byte
	result   string
}

// buildKeyGroup turns a list of raw key encodings into vectors. The caller
// supplies the field name: Pub for the public key parsers, Priv for the
// private key parsers.
func buildKeyGroup(cases []keyCase, pub bool) []vectors.Case {
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		tc := vectors.Case{TCID: c.tcID, Comment: c.comment, Result: c.result}
		if pub {
			tc.Pub = hexStr(c.material)
		} else {
			tc.Priv = hexStr(c.material)
		}
		out = append(out, tc)
	}
	return out
}

// pointCases builds the shared point-encoding cases for one uncompressed
// point of prefix length n: identity, off-curve, missing prefix, unknown
// wire type, and the two compressed forms of the same x.
func pointCases(first int, point []byte) []keyCase {
	x := point[1 : 1+len(point)/2]
	identity := make([]byte, len(point))
	identity[0] = 4
	cases := []keyCase{
		{first, "uncompressed point", point, "valid"},
		{first + 1, "identity", identity, "invalid"},
		{first + 2, "off the curve", flipLast(point), "invalid"},
		{first + 3, "compressed point, odd y", append([]byte{3}, x...), "valid"},
		{first + 4, "compressed point, even y", append([]byte{2}, x...), "valid"},
		{first + 5, "missing the 0x04 prefix", point[1:], "invalid"},
		{first + 6, "unknown wire type", append([]byte{5}, point[1:]...), "invalid"},
		{first + 7, "empty input", nil, "invalid"},
	}
	return cases
}

func buildSignMasterPublicKey() []vectors.Case {
	return buildKeyGroup(pointCases(1, mustHex(signMasterPubHex)), true)
}

func buildEncryptMasterPublicKey() []vectors.Case {
	return buildKeyGroup(pointCases(1, mustHex(encMasterPubHex)), true)
}

func buildSignPrivateKey() []vectors.Case {
	cases := pointCases(1, mustHex(signUserKeyHex))
	cases = append(cases, keyCase{9, "truncated by one byte", mustHex(signUserKeyHex)[:64], "invalid"})
	return buildKeyGroup(cases, false)
}

func buildEncryptPrivateKey() []vectors.Case {
	cases := pointCases(1, mustHex(encUserKeyHex))
	cases = append(cases, keyCase{9, "truncated by one byte", mustHex(encUserKeyHex)[:128], "invalid"})
	return buildKeyGroup(cases, false)
}

// buildMasterPrivateKey pins the scalar range check: zero and any value at
// or above the group order must be rejected, N-1 is in range.
func buildMasterPrivateKey(keyHex string) []vectors.Case {
	key := mustHex(keyHex)
	cases := []keyCase{
		{1, "published master private key", key, "valid"},
		{2, "zero scalar", make([]byte, 32), "invalid"},
		{3, "scalar equal to the group order", mustHex(sm9OrderHex), "invalid"},
		{4, "scalar N-1", orderMinus1(), "invalid"},
	}
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		out = append(out, vectors.Case{
			TCID:    c.tcID,
			Comment: c.comment,
			Result:  c.result,
			Priv:    hexStr(marshalInt(c.material)),
		})
	}
	out = append(out, vectors.Case{
		TCID:    5,
		Comment: "trailing byte after the DER integer",
		Result:  "invalid",
		Priv:    hexStr(append(marshalInt(key), 0)),
	})
	return out
}

// buildASN1Parse collects malformed inputs that every ASN.1 key parser must
// reject with an error. A panic here is a denial of service on attacker
// supplied key material, so the consumer treats it as a failure.
func buildASN1Parse() []vectors.Case {
	bitString := func(payload []byte) []byte {
		der, err := asn1.Marshal(asn1.BitString{Bytes: payload, BitLength: len(payload) * 8})
		if err != nil {
			panic("sm9vectors: marshalling bit string: " + err.Error())
		}
		return der
	}
	cases := []struct {
		tcID    int
		comment string
		input   []byte
	}{
		{1, "empty input", nil},
		{2, "single SEQUENCE tag", []byte{0x30}},
		{3, "SEQUENCE with no content", []byte{0x30, 0x00}},
		{4, "BIT STRING with no content", []byte{0x03, 0x00}},
		{5, "BIT STRING that promises more bytes than it carries", []byte{0x03, 0x42, 0x00, 0x04}},
		{6, "BIT STRING wrapping an empty payload", bitString(nil)},
		{7, "BIT STRING wrapping two bytes", bitString([]byte{0x04, 0x00})},
	}
	out := make([]vectors.Case, 0, len(cases))
	for _, c := range cases {
		out = append(out, vectors.Case{
			TCID:    c.tcID,
			Comment: c.comment,
			Result:  "invalid",
			Input:   hexStr(c.input),
		})
	}
	return out
}

// BuildSuite builds the SM9 suite.
func BuildSuite() (*vectors.Suite, error) {
	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "sm9",
		Generator: "go test ./internal/cryptotest/sm9vectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			{
				Type:    "SM9SignatureVerify",
				Comment: "Signature verification of the GB/T 32918.5 example and its single-field mutations. The hash field carries the byte string the standard feeds to H2; for larger messages the API expects a precomputed digest. h must lie in [1, N-1], s must be an uncompressed point on G1 that is not the identity.",
				Tests:   buildSignatureVerify(),
			},
			{
				Type:    "SM9Decrypt",
				Comment: "Decryption of the GB/T 32918.5 ciphertext (C1||C3||C2, C1 without its 0x04 prefix) and single-byte mutations. Every invalid case must return an error, never plaintext.",
				Tests:   buildDecrypt(),
			},
			{
				Type:    "SM9SignMasterPublicKey",
				Comment: "Raw signature master public key: a G2 point (129 bytes). Compressed encodings are accepted, the identity and off-curve points are not.",
				Tests:   buildSignMasterPublicKey(),
			},
			{
				Type:    "SM9EncryptMasterPublicKey",
				Comment: "Raw encryption master public key: a G1 point (65 bytes). Compressed encodings are accepted, the identity and off-curve points are not.",
				Tests:   buildEncryptMasterPublicKey(),
			},
			{
				Type:    "SM9SignPrivateKey",
				Comment: "Raw signature user private key: a G1 point (65 bytes).",
				Tests:   buildSignPrivateKey(),
			},
			{
				Type:    "SM9EncryptPrivateKey",
				Comment: "Raw encryption user private key: a G2 point (129 bytes).",
				Tests:   buildEncryptPrivateKey(),
			},
			{
				Type:    "SM9SignMasterPrivateKey",
				Comment: "Signature master private key as a DER INTEGER. The scalar must be in [1, N-1]; the group order is the SM9 order, not the SM2 order.",
				Tests:   buildMasterPrivateKey(signMasterKeyHex),
			},
			{
				Type:    "SM9EncryptMasterPrivateKey",
				Comment: "Encryption master private key as a DER INTEGER, with the same range check.",
				Tests:   buildMasterPrivateKey(encMasterKeyHex),
			},
			{
				Type:    "SM9ASN1KeyParse",
				Comment: "Malformed ASN.1 fed to all six ASN.1 key parsers. Each parser must return an error; a panic on empty or truncated input is a denial of service.",
				Tests:   buildASN1Parse(),
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
