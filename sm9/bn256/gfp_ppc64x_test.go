// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (ppc64 || ppc64le) && !purego

package bn256

import "testing"

func TestGfpNegAsm(t *testing.T) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	got := &gfP{}
	gfpSubAsm(got, zero, x)
	expected := &gfP{}
	gfpNegAsm(expected, x)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
	gfpSubAsm(got, zero, zero)
	gfpNegAsm(expected, zero)
	if *expected != *got {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func TestGfpAsmBasicOperations(t *testing.T) {
	x := fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"))
	y := fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"))
	expectedAdd := fromBigInt(bigFromHex("0691692307d370af56226e57920199fbbe10f216c67fbc9468c7f225a4b1f21f"))
	expectedDouble := fromBigInt(bigFromHex("551de7a0ee24723edcf314ff72f478fac1c7c4e7044238acc3913cfbcdaf7d05"))
	expectedSub := fromBigInt(bigFromHex("67b381821c52a5624f3304a8149be8461e3bc07adcb872c38aa65051ba53ba97"))
	expectedNeg := fromBigInt(bigFromHex("7f1d8aad70909be90358f1d02240062433cc3a0248ded72febb879ec33ce6f22"))
	expectedMul := fromBigInt(bigFromHex("3d08bbad376584e4f74bd31f78f716372b96ba8c3f939c12b8d54e79b6489e76"))
	expectedMul2 := fromBigInt(bigFromHex("1df94a9e05a559ff38e0ab50cece734dc058d33738ceacaa15986a67cbff1ef6"))

	t.Parallel()
	t.Run("add", func(t *testing.T) {
		ret := &gfP{}
		gfpAddAsm(ret, x, y)
		if *expectedAdd != *ret {
			t.Errorf("add not same")
		}
		x1 := &gfP{}
		x1.Set(x)
		gfpAddAsm(x1, x1, y)
		if *expectedAdd != *x1 {
			t.Errorf("add not same when add self")
		}
	})

	t.Run("double", func(t *testing.T) {
		ret := &gfP{}
		gfpDoubleAsm(ret, x)
		if ret.Equal(expectedDouble) != 1 {
			t.Errorf("double not same, got %v, expected %v", ret, expectedDouble)
		}
		ret.Set(x)
		gfpDoubleAsm(ret, ret)
		if ret.Equal(expectedDouble) != 1 {
			t.Errorf("double not same, got %v, expected %v", ret, expectedDouble)
		}
	})

	t.Run("triple", func(t *testing.T) {
		expected := &gfP{}
		gfpAddAsm(expected, x, expectedDouble)
		ret := &gfP{}
		ret.Set(x)
		gfpTripleAsm(ret, ret)
		if ret.Equal(expected) != 1 {
			t.Errorf("expected %v, got %v", expected, ret)
		}
	})

	t.Run("sub", func(t *testing.T) {
		ret := &gfP{}
		gfpSubAsm(ret, y, x)
		if *expectedSub != *ret {
			t.Errorf("sub not same")
		}
		x1 := &gfP{}
		x1.Set(x)
		gfpSubAsm(x1, y, x1)
		if *expectedSub != *x1 {
			t.Errorf("sub not same when sub self")
		}
		gfpSubAsm(ret, x, x)
		if *ret != *zero {
			t.Errorf("expected zero")
		}
	})

	t.Run("neg", func(t *testing.T) {
		ret := &gfP{}
		gfpNegAsm(ret, y)
		if *expectedNeg != *ret {
			t.Errorf("neg not same")
		}
		ret.Set(y)
		gfpNegAsm(ret, ret)
		if *expectedNeg != *ret {
			t.Errorf("neg not same when neg self")
		}
	})

	t.Run("mul", func(t *testing.T) {
		ret := &gfP{}
		gfpMulAsm(ret, x, y)
		if *expectedMul != *ret {
			t.Errorf("mul not same")
		}
		ret.Set(x)
		gfpMulAsm(ret, ret, y)
		if *expectedMul != *ret {
			t.Errorf("mul not same when mul self")
		}
	})

	t.Run("square", func(t *testing.T) {
		ret, ret1, ret2 := &gfP{}, &gfP{}, &gfP{}
		gfpMulAsm(ret, x, y)
		gfpMulAsm(ret1, ret, ret)
		if *ret1 != *expectedMul2 {
			t.Errorf("mul not same")
		}
		gfpMulAsm(ret1, ret1, ret1)
		gfpSqrAsm(ret2, ret, 2)
		if *ret1 != *ret2 {
			t.Errorf("mul/sqr not same")
		}
		ret2.Set(ret)
		gfpSqrAsm(ret2, ret2, 2)
		if *ret1 != *ret2 {
			t.Errorf("mul/sqr not same when square self")
		}
	})
}
