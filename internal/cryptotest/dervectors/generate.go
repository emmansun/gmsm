// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package dervectors generates the committed DER/BER parser vectors.
//
// The vectors are hand-built rather than produced by the library: every
// baseline is assembled from the ASN.1 definitions with this package's own
// encoder, so a bug in the code under test cannot become the expected bytes.
// Each case then applies exactly one structural change and pins whether the
// entry point must accept or reject it.
//
// Sources: ITU-T X.690 (DER canonical form), RFC 5280 (certificates),
// RFC 2986 (PKCS #10), RFC 5208 (PKCS #8) and RFC 5652 (CMS).
//
// Three behaviours are deliberately not pinned because the schema only
// expresses valid/invalid, and neither DER nor the upstream crypto/x509
// contract requires the library to reject them:
//
//   - a zero certificate serial number, and PKCS #8 or CSR version fields
//     other than the value RFC 5208 and RFC 2986 prescribe;
//   - trailing bytes after a PKCS #8 PrivateKeyInfo, which
//     encoding/asn1.Unmarshal leaves in its remainder;
//   - a certificate or CSR signature that does not verify: these entry
//     points parse and never check signatures.
package dervectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
)

const (
	certGroup  = "X509Certificate"
	csrGroup   = "X509CSR"
	pkcs8Group = "PKCS8"
	pkcs7Group = "PKCS7"
)

// Flags classify why a case is interesting. They follow the Wycheproof idea
// of explaining the trap rather than just recording the verdict.
const (
	flagNonCanonical   = "DerNonCanonical"     // X.690 10.1 shortest-form rules
	flagIndefinite     = "IndefiniteLength"    // X.690 8.1.3.2: DER forbids it
	flagTrailing       = "TrailingData"        // bytes after the top-level element
	flagTruncated      = "Truncated"           // length claims more than is present
	flagTagMismatch    = "TagMismatch"         // wrong universal/P/C bits
	flagSchema         = "SchemaViolation"     // violates the RFC 5280/2986/5208 schema
	flagOutOfRange     = "OutOfRange"          // value outside the required range
	flagLengthOverflow = "LengthOverflow"      // absurd length, must not allocate
	flagBERLeniency    = "BERLeniency"         // valid BER that is not valid DER
	flagTolerance      = "DocumentedTolerance" // unusual but deliberately accepted
)

type derCase struct {
	comment string
	flags   []string
	input   []byte
	valid   bool
}

func (c derCase) vector(tcID int) vectors.Case {
	v := vectors.Case{
		TCID:    tcID,
		Comment: c.comment,
		Flags:   c.flags,
		Input:   hex.EncodeToString(c.input),
	}
	if c.valid {
		v.Result = "valid"
	} else {
		v.Result = "invalid"
	}
	return v
}

func newGroup(typ, comment string, cases []derCase) vectors.Group {
	g := vectors.Group{Type: typ, Comment: comment}
	for i, c := range cases {
		if c.comment == "" || len(c.flags) == 0 {
			panic(fmt.Sprintf("dervectors: %s case %d lacks a comment or flags", typ, i+1))
		}
		g.Tests = append(g.Tests, c.vector(i+1))
	}
	return g
}

// ---- minimal DER/BER encoder, independent of the code under test ----

func lenBytes(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var out []byte
	for v := n; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return append([]byte{0x80 | byte(len(out))}, out...)
}

func tlv(tag byte, parts ...[]byte) []byte {
	content := bytes.Join(parts, nil)
	out := []byte{tag}
	out = append(out, lenBytes(len(content))...)
	return append(out, content...)
}

func seq(parts ...[]byte) []byte   { return tlv(0x30, parts...) }
func setOf(parts ...[]byte) []byte { return tlv(0x31, parts...) }

func expl(tag byte, in []byte) []byte { return tlv(0xa0|tag, in) }

func oid(arcs ...int) []byte {
	body := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		var enc []byte
		enc = append(enc, byte(a&0x7f))
		for a >>= 7; a > 0; a >>= 7 {
			enc = append([]byte{byte(a&0x7f) | 0x80}, enc...)
		}
		body = append(body, enc...)
	}
	return tlv(0x06, body)
}

func derInt(v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if v == 0 || v == -1 {
			break
		}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(0x02, b)
}

func octet(b []byte) []byte  { return tlv(0x04, b) }
func bitStr(b []byte) []byte { return tlv(0x03, append([]byte{0}, b...)) }
func utc(s string) []byte    { return tlv(0x17, []byte(s)) }

func boolean(v bool) []byte {
	if v {
		return tlv(0x01, []byte{0xff})
	}
	return tlv(0x01, []byte{0})
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	// The sm2p256v1 base point, GB/T 32918.5.
	gx = mustHex("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
	gy = mustHex("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
	// The sm2p256v1 group order n.
	sm2Order = mustHex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123")
	// point2G is 2G, used as a public key that does not match d = 1.
	point2G = mustHex("04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" +
		"1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")

	oidSM2    = oid(1, 2, 156, 10197, 1, 301) // id-sm2-with-sm3 key algorithm and curve
	oidSM3SM2 = oid(1, 2, 156, 10197, 1, 501) // sm3WithSM2 signature algorithm
	oidP256   = oid(1, 2, 840, 10045, 3, 1, 7)
)

func point() []byte { return append([]byte{4}, append(append([]byte{}, gx...), gy...)...) }

func sigAlg() []byte { return seq(oidSM3SM2) }

func d32(v byte) []byte {
	d := make([]byte, 32)
	d[31] = v
	return d
}

// ---- builders ----

type certOpts struct {
	serial     []byte
	version    int // -1 omits the version field
	exts       [][]byte
	spkiParams []byte
	outerSig   []byte
}

func buildCert(o certOpts) []byte {
	if o.serial == nil {
		o.serial = []byte{0x01}
	}
	if o.version == 0 {
		o.version = 2
	}
	if len(o.exts) > 0 && o.version != 2 {
		panic("dervectors: extensions require a v3 certificate")
	}
	if o.spkiParams == nil {
		o.spkiParams = oidSM2
	}
	name := seq()
	validity := seq(utc("250101000000Z"), utc("350101000000Z"))
	spki := seq(seq(oidSM2, o.spkiParams), bitStr(point()))

	var parts [][]byte
	if o.version >= 0 {
		parts = append(parts, expl(0, derInt(int64(o.version))))
	}
	parts = append(parts, tlv(0x02, o.serial), sigAlg(), name, validity, name, spki)
	if len(o.exts) > 0 {
		parts = append(parts, expl(3, seq(o.exts...)))
	}

	outer := sigAlg()
	if o.outerSig != nil {
		outer = o.outerSig
	}
	return seq(seq(parts...), outer, bitStr([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}))
}

func basicConstraints() []byte {
	return seq(oid(2, 5, 29, 19), octet(seq(boolean(true))))
}

type csrOpts struct {
	attrs []byte
}

func buildCSR(o csrOpts) []byte {
	if o.attrs == nil {
		o.attrs = tlv(0xa0)
	}
	cri := seq(derInt(0), seq(), seq(seq(oidSM2, oidSM2), bitStr(point())), o.attrs)
	return seq(cri, sigAlg(), bitStr([]byte{1, 2, 3, 4}))
}

type pkcs8Opts struct {
	d         []byte
	curveOID  []byte // nil omits the [0] parameters
	ecVersion int
	pub       []byte // nil omits the [1] public key
}

func buildPKCS8(o pkcs8Opts) []byte {
	if o.ecVersion == 0 {
		o.ecVersion = 1
	}
	ecParts := [][]byte{derInt(int64(o.ecVersion)), octet(o.d)}
	if o.curveOID != nil {
		ecParts = append(ecParts, expl(0, o.curveOID))
	}
	if o.pub != nil {
		ecParts = append(ecParts, expl(1, bitStr(o.pub)))
	}
	alg := seq(oidSM2)
	if o.curveOID != nil {
		alg = seq(oidSM2, o.curveOID)
	}
	return seq(derInt(0), alg, octet(seq(ecParts...)))
}

type pkcs7Opts struct {
	indefiniteSigners bool
	sdTag             byte
}

func buildPKCS7(o pkcs7Opts) []byte {
	eContent := seq(oid(1, 2, 840, 113549, 1, 7, 1), expl(0, octet([]byte("gmsm der vectors"))))
	signers := setOf()
	if o.indefiniteSigners {
		signers = []byte{0x31, 0x80, 0x00, 0x00}
	}
	tag := o.sdTag
	if tag == 0 {
		tag = 0x30
	}
	sd := tlv(tag, derInt(1), setOf(), eContent, signers)
	return seq(oid(1, 2, 840, 113549, 1, 7, 2), expl(0, sd))
}

// ---- structural mutators ----

func header(b []byte) int {
	if b[1] < 0x80 {
		return 2
	}
	return 2 + int(b[1]&0x7f)
}

func contentLen(b []byte) int {
	if b[1] < 0x80 {
		return int(b[1])
	}
	n := 0
	for _, v := range b[2:header(b)] {
		n = n<<8 | int(v)
	}
	return n
}

func tlvLen(b []byte) int { return header(b) + contentLen(b) }

func children(b []byte) [][2]int {
	var out [][2]int
	base := header(b)
	for content := b[base:]; len(content) > 0; {
		n := tlvLen(content)
		out = append(out, [2]int{base, n})
		base += n
		content = content[n:]
	}
	return out
}

func withOuterLength(b, enc []byte) []byte {
	out := []byte{b[0]}
	out = append(out, enc...)
	return append(out, b[header(b):]...)
}

// nonMinimalLength rewrites the outer length with a superfluous leading zero.
func nonMinimalLength(b []byte) []byte {
	n := len(b) - header(b)
	var e []byte
	for v := n; v > 0; v >>= 8 {
		e = append([]byte{byte(v)}, e...)
	}
	e = append([]byte{0x80 | byte(len(e)+1), 0x00}, e...)
	return withOuterLength(b, e)
}

// indefiniteLength rewrites the outer element in indefinite form.
func indefiniteLength(b []byte) []byte {
	return append(withOuterLength(b, []byte{0x80}), 0, 0)
}

// indefiniteAll re-encodes every constructed element in indefinite form, which
// is valid BER but not DER.
func indefiniteAll(b []byte) []byte {
	if b[0]&0x20 == 0 {
		return b
	}
	content := b[header(b):]
	out := []byte{b[0], 0x80}
	for len(content) > 0 {
		n := tlvLen(content)
		out = append(out, indefiniteAll(content[:n])...)
		content = content[n:]
	}
	return append(out, 0, 0)
}

// ---- suite ----

// BuildSuite assembles the DER/BER suite.
func BuildSuite() *vectors.Suite {
	v3Cert := buildCert(certOpts{version: 2, exts: [][]byte{basicConstraints()}})
	csr := buildCSR(csrOpts{})
	pk8 := buildPKCS8(pkcs8Opts{d: d32(1), curveOID: oidSM2, pub: point()})
	p7 := buildPKCS7(pkcs7Opts{})

	suite := &vectors.Suite{
		Schema:    vectors.SemanticsSchema,
		Algorithm: "DER",
		Generator: "internal/cryptotest/dervectors/generate.go; regenerate with " +
			"go test ./internal/cryptotest/dervectors -run TestVectorsUpToDate -update",
		Groups: []vectors.Group{
			newGroup(certGroup, "smx509.ParseCertificate. DER only: X.690 length and tag canon", []derCase{
				{"v3 certificate with a basicConstraints extension", []string{"Baseline"}, v3Cert, true},
				{"v1 certificate: the version field and extensions are absent", []string{"Baseline"}, buildCert(certOpts{version: -1}), true},
				{"trailing zero byte after the top-level SEQUENCE", []string{flagTrailing}, append(append([]byte{}, v3Cert...), 0), false},
				{"trailing complete TLV after the top-level SEQUENCE", []string{flagTrailing}, append(append([]byte{}, v3Cert...), 0x05, 0x00), false},
				{"outer length in long form with a leading zero", []string{flagNonCanonical}, nonMinimalLength(v3Cert), false},
				{"outer element in indefinite form", []string{flagIndefinite}, indefiniteLength(v3Cert), false},
				{"outer length claims 2 GiB", []string{flagLengthOverflow}, withOuterLength(v3Cert, []byte{0x84, 0x7f, 0xff, 0xff, 0xff}), false},
				{"last byte removed", []string{flagTruncated}, v3Cert[:len(v3Cert)-1], false},
				{"outer SEQUENCE tag changed to SET", []string{flagTagMismatch}, withTag(v3Cert, 0x31), false},
				{"signature BIT STRING encoded as constructed", []string{flagTagMismatch}, func() []byte {
					c := append([]byte{}, v3Cert...)
					k := children(c)
					c[k[len(k)-1][0]] |= 0x20
					return c
				}(), false},
				{"negative serial number", []string{flagOutOfRange}, buildCert(certOpts{serial: []byte{0x80}}), false},
				{"certificate version 4", []string{flagSchema}, buildCert(certOpts{version: 3}), false},
				{"serial INTEGER with a leading zero", []string{flagNonCanonical}, buildCert(certOpts{serial: []byte{0x00, 0x01}}), false},
				{"duplicate basicConstraints extension", []string{flagSchema}, buildCert(certOpts{
					exts: [][]byte{basicConstraints(), basicConstraints()},
				}), false},
				{"inner and outer signature algorithm identifiers differ", []string{flagSchema}, buildCert(certOpts{
					outerSig: seq(oid(1, 2, 840, 10045, 4, 3, 2)),
				}), false},
				{"SM2 subjectPublicKeyInfo with explicit curve parameters", []string{flagSchema}, buildCert(certOpts{
					spkiParams: seq(
						derInt(1),
						seq(oid(1, 2, 840, 10045, 1, 1), derInt(23)),
						seq(derInt(1), octet(gx), octet(gy), octet([]byte{1}), octet([]byte{2}), derInt(1), derInt(1)),
					),
				}), false},
				{"empty input", []string{flagTruncated}, nil, false},
			}),
			newGroup(csrGroup, "smx509.ParseCertificateRequest. PKCS #10 (RFC 2986) over encoding/asn1, which enforces DER", []derCase{
				{"request with an empty attribute set", []string{"Baseline"}, csr, true},
				{"trailing byte after the top-level SEQUENCE", []string{flagTrailing}, append(append([]byte{}, csr...), 0), false},
				{"outer length in long form with a leading zero", []string{flagNonCanonical}, nonMinimalLength(csr), false},
				{"outer element in indefinite form", []string{flagIndefinite}, indefiniteLength(csr), false},
				{"last byte removed", []string{flagTruncated}, csr[:len(csr)-1], false},
				{"outer SEQUENCE tag changed to SET", []string{flagTagMismatch}, withTag(csr, 0x31), false},
				{"SAN extension with a three byte IP address", []string{flagSchema}, buildCSR(csrOpts{attrs: func() []byte {
					badSAN := seq(seq(oid(2, 5, 29, 17), octet(seq(tlv(0x87, []byte{1, 2, 3})))))
					return tlv(0xa0, seq(oid(1, 2, 840, 113549, 1, 9, 14), setOf(badSAN)))
				}()}), false},
			}),
			newGroup(pkcs8Group, "pkcs8.ParsePKCS8PrivateKeySM2. RFC 5208 PrivateKeyInfo wrapping a SEC 1 ECPrivateKey", []derCase{
				{"unencrypted key with d = 1", []string{"Baseline"}, pk8, true},
				{"outer length in long form with a leading zero", []string{flagNonCanonical}, nonMinimalLength(pk8), false},
				{"outer element in indefinite form", []string{flagIndefinite}, indefiniteLength(pk8), false},
				{"last byte removed", []string{flagTruncated}, pk8[:len(pk8)-1], false},
				{"empty input", []string{flagTruncated}, nil, false},
				{"embedded ECPrivateKey version 2", []string{flagSchema}, buildPKCS8(pkcs8Opts{
					d: d32(1), curveOID: oidSM2, ecVersion: 2,
				}), false},
				{"d = 0", []string{flagOutOfRange}, buildPKCS8(pkcs8Opts{
					d: make([]byte, 32), curveOID: oidSM2,
				}), false},
				{"d = n, the group order", []string{flagOutOfRange}, buildPKCS8(pkcs8Opts{
					d: sm2Order, curveOID: oidSM2,
				}), false},
				{"d padded to 33 bytes with a leading zero", []string{flagTolerance}, buildPKCS8(pkcs8Opts{
					d: append([]byte{0}, d32(1)...), curveOID: oidSM2,
				}), true},
				{"curve parameters absent", []string{flagSchema}, buildPKCS8(pkcs8Opts{d: d32(1)}), false},
				{"curve parameters name P-256", []string{flagSchema}, buildPKCS8(pkcs8Opts{
					d: d32(1), curveOID: oidP256,
				}), false},
				{"embedded public key is 2G while d = 1", []string{flagTolerance}, buildPKCS8(pkcs8Opts{
					d: d32(1), curveOID: oidSM2, pub: point2G,
				}), true},
			}),
			newGroup(pkcs7Group, "pkcs7.Parse. RFC 5652 CMS; BER is accepted, so indefinite lengths are legal input", []derCase{
				{"DER SignedData with an empty signerInfos set", []string{"Baseline"}, p7, true},
				{"same content with every constructed element in indefinite form", []string{flagBERLeniency}, indefiniteAll(p7), true},
				{"empty signerInfos SET encoded in indefinite form", []string{flagBERLeniency}, buildPKCS7(pkcs7Opts{
					indefiniteSigners: true,
				}), true},
				{"trailing zero byte after the ContentInfo", []string{flagTrailing}, append(append([]byte{}, p7...), 0), false},
				{"trailing TLV after the ContentInfo", []string{flagTrailing}, append(append([]byte{}, p7...), 0xde, 0xad), false},
				{"SignedData SEQUENCE tag changed to SET", []string{flagTagMismatch}, buildPKCS7(pkcs7Opts{sdTag: 0x31}), false},
				{"last byte removed", []string{flagTruncated}, p7[:len(p7)-1], false},
				{"empty input", []string{flagTruncated}, nil, false},
				{"top-level tag has the constructed bit cleared", []string{flagTagMismatch}, withTag(p7, 0x10), false},
				{"outer length claims 2 GiB", []string{flagLengthOverflow}, withOuterLength(p7, []byte{0x84, 0x7f, 0xff, 0xff, 0xff}), false},
				{"indefinite form without the final end-of-contents octets", []string{flagTruncated}, func() []byte {
					b := indefiniteAll(p7)
					return b[:len(b)-2]
				}(), false},
			}),
		},
	}
	if err := suite.Validate(); err != nil {
		panic(fmt.Sprintf("dervectors: %v", err))
	}
	return suite
}

func withTag(b []byte, tag byte) []byte {
	out := append([]byte{}, b...)
	out[0] = tag
	return out
}

// MarshalSuite renders a suite as the indented JSON stored in testdata.
func MarshalSuite(s *vectors.Suite) ([]byte, error) {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
