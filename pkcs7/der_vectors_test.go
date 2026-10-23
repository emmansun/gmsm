// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package pkcs7_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/pkcs7"
)

// TestDERParseVectors pins the CMS container parser: BER input is accepted
// (indefinite lengths included), but trailing data, malformed BER and
// structures that do not match the RFC 5652 schema are rejected.
func TestDERParseVectors(t *testing.T) {
	suite, err := vectors.Load("der_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	group, err := suite.Group("PKCS7")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		tc := tc
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			v := checkDERVector(t, tc, func(b []byte) (any, error) {
				return pkcs7.Parse(b)
			})
			if v == nil {
				return
			}
			if content := string(v.(*pkcs7.PKCS7).Content); content != "gmsm der vectors" {
				t.Fatalf("tc%d (%s): got content %q", tc.TCID, tc.Comment, content)
			}
		})
	}
}

func checkDERVector(t *testing.T, tc vectors.Case, parse func([]byte) (any, error)) any {
	t.Helper()
	in, err := hex.DecodeString(tc.Input)
	if err != nil {
		t.Fatalf("tc%d (%s): input is not hex: %v", tc.TCID, tc.Comment, err)
	}

	var (
		parsed   any
		parseErr error
		panicVal any
	)
	func() {
		defer func() { panicVal = recover() }()
		parsed, parseErr = parse(in)
	}()
	if panicVal != nil {
		t.Fatalf("tc%d (%s): parser panicked: %v", tc.TCID, tc.Comment, panicVal)
	}

	wantValid := tc.Result == "valid"
	if !wantValid {
		if parseErr == nil {
			t.Fatalf("tc%d (%s): accepted an invalid encoding", tc.TCID, tc.Comment)
		}
		return nil
	}
	if parseErr != nil {
		t.Fatalf("tc%d (%s): rejected a valid encoding: %v", tc.TCID, tc.Comment, parseErr)
	}
	if parsed == nil {
		t.Fatalf("tc%d (%s): parser returned no value and no error", tc.TCID, tc.Comment)
	}
	return parsed
}
