// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package pkcs8_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/pkcs8"
)

// TestDERParseVectors pins the DER strictness of PKCS #8 private key parsing:
// canonical lengths, definite lengths, the RFC 5208 wrapper and the SEC 1
// ECPrivateKey range checks.
func TestDERParseVectors(t *testing.T) {
	suite, err := vectors.Load("der_semantics.json")
	if err != nil {
		t.Fatal(err)
	}
	group, err := suite.Group("PKCS8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range group.Tests {
		tc := tc
		t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
			checkDERVector(t, tc, func(b []byte) (any, error) {
				return pkcs8.ParsePKCS8PrivateKeySM2(b)
			})
		})
	}
}

func checkDERVector(t *testing.T, tc vectors.Case, parse func([]byte) (any, error)) {
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
		return
	}
	if parseErr != nil {
		t.Fatalf("tc%d (%s): rejected a valid encoding: %v", tc.TCID, tc.Comment, parseErr)
	}
	if parsed == nil {
		t.Fatalf("tc%d (%s): parser returned no value and no error", tc.TCID, tc.Comment)
	}
}
