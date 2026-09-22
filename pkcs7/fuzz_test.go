// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package pkcs7

import (
	"testing"
)

// FuzzBER2DER directly fuzzes the internal DER conversion function,
// covering every branch of readObject (including recursion) and providing
// the fastest feedback loop for boundary-related regressions.
func FuzzBER2DER(f *testing.F) {
	// Seed corpus: known panic inputs plus a set of valid/boundary DER structures.
	seeds := [][]byte{
		// Known panic inputs (regression seeds)
		{0x30, 0x81},                         // truncated long-form length
		{0x30, 0x82},                         // truncated two-byte length
		{0x1f, 0x05},                         // high tag number without length byte
		{0x1f, 0x81},                         // truncated multi-byte high tag form
		{0x1f, 0x81, 0x81, 0x81, 0x81, 0x81}, // consecutive high-tag bytes (tag<<7 overflow path)
		// Minimal valid structures
		{0x30, 0x00},                               // empty SEQUENCE
		{0x30, 0x02, 0x05, 0x00},                   // SEQUENCE { NULL }
		{0x04, 0x03, 0x01, 0x02, 0x03},             // OCTET STRING
		{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}, // indefinite-length SEQUENCE
		// Nested structures (recursive parse path)
		{0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x05, 0x00},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := ber2der(data)
		if err != nil {
			return
		}
		// Round-trip check on success: re-parsing the output must also
		// succeed, guarding against "converts fine but result is invalid".
		if _, err := ber2der(out); err != nil {
			t.Errorf("ber2der output re-parse failed: input=% x err=%v", data, err)
		}
	})
}

// FuzzParse exercises the full public entry point, covering the ASN.1
// parsing path after ber2der (asn1.Unmarshal, OID dispatch, etc.).
// This is the surface actually exposed to attackers.
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		// Known panic inputs (regression seeds)
		{0x30, 0x81},
		{0x30, 0x82},
		{0x1f, 0x05},
		{0x1f, 0x81},
		// A minimal valid structure to guide the fuzzer past ber2der
		// and into the asn1 layer.
		{0x30, 0x0a, 0x06, 0x01, 0x2a, 0x04, 0x05, 0x00, 0x04, 0x03, 0x01, 0x02},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := Parse(data)
		if err != nil {
			return
		}
		// Touch a few exported fields so that any panics in lazily
		// evaluated accessors or slice arithmetic on the parsed result
		// are also caught.
		_ = p7.Content
		_ = p7.Certificates
	})
}
