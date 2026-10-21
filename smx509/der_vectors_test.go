// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package smx509_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/smx509"
)

// TestDERParseVectors pins the DER strictness of the certificate and CSR
// parsers: canonical lengths, definite lengths, trailing data and the schema
// rules of RFC 5280 and RFC 2986.
func TestDERParseVectors(t *testing.T) {
	suite, err := vectors.Load("der_semantics.json")
	if err != nil {
		t.Fatal(err)
	}

	groups := []struct {
		name  string
		parse func([]byte) (any, error)
	}{
		{"X509Certificate", func(b []byte) (any, error) { return smx509.ParseCertificate(b) }},
		{"X509CSR", func(b []byte) (any, error) { return smx509.ParseCertificateRequest(b) }},
	}
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			g, err := suite.Group(group.name)
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range g.Tests {
				tc := tc
				t.Run(fmt.Sprintf("tc%d", tc.TCID), func(t *testing.T) {
					checkDERVector(t, tc, group.parse)
				})
			}
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
