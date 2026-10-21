// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package vectors

import "testing"

func TestLoadKernelSuite(t *testing.T) {
	suite, err := Load("sm2ec_p256_mul_bmi2.json")
	if err != nil {
		t.Fatal(err)
	}
	if suite.Schema != "gmsm-kernel-vectors/v1" {
		t.Errorf("schema = %q", suite.Schema)
	}
	for _, typ := range []string{"FieldMul", "FieldSqr"} {
		group, err := suite.Group(typ)
		if err != nil {
			t.Fatal(err)
		}
		if len(group.Tests) == 0 {
			t.Fatalf("%s: no test cases", typ)
		}
		for _, tc := range group.Tests {
			if _, err := DecodeHex32(tc.A); err != nil {
				t.Errorf("%s tc%d: %v", typ, tc.TCID, err)
			}
			if _, err := DecodeHex32(tc.Expected); err != nil {
				t.Errorf("%s tc%d: %v", typ, tc.TCID, err)
			}
		}
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.json"); err == nil {
		t.Fatal("Load() succeeded for a missing file")
	}
}

func TestGroupRequires(t *testing.T) {
	group := &Group{
		Type:     "FieldMul",
		Arch:     []string{"amd64"},
		Features: []string{"adx", "bmi2"},
	}

	ok, missing, err := group.Requires("amd64", map[string]bool{"adx": true, "bmi2": true})
	if err != nil || !ok || len(missing) != 0 {
		t.Fatalf("Requires() = %v, %v, %v; want true, nil, nil", ok, missing, err)
	}

	ok, missing, err = group.Requires("arm64", map[string]bool{"adx": false, "bmi2": true})
	if err != nil {
		t.Fatal(err)
	}
	if ok || len(missing) != 2 {
		t.Fatalf("Requires() = %v, %v; want false and two constraints", ok, missing)
	}

	// A typo in a vector file must be an error, not a silent skip.
	if _, _, err := group.Requires("amd64", map[string]bool{"adx": true}); err == nil {
		t.Fatal("Requires() accepted an unknown feature")
	}
}

func TestDecodeHex32(t *testing.T) {
	in := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	out, err := DecodeHex32(in)
	if err != nil {
		t.Fatal(err)
	}
	if out[0] != 0 || out[31] != 0x1f {
		t.Fatalf("DecodeHex32() = %x", out)
	}
	for _, bad := range []string{"00", in + "00", "zz" + in[2:]} {
		if _, err := DecodeHex32(bad); err == nil {
			t.Errorf("DecodeHex32(%q) succeeded", bad)
		}
	}
}
