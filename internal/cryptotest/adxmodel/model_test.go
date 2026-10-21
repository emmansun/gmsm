// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package adxmodel

import (
	"math/bits"
	"math/rand/v2"
	"testing"
)

func TestModelMatchesReference(t *testing.T) {
	// q-1 and q-2 in limb order, where q = 2^256 - 2^224 - 2^96 + 2^64 - 1 is
	// the SM2 field prime (not the group order).
	qMinus1 := [4]uint64{0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff}
	qMinus2 := [4]uint64{0xfffffffffffffffd, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff}

	cases := []struct {
		name string
		a, b [4]uint64
	}{
		{"zero", [4]uint64{}, [4]uint64{1}},
		{"one", [4]uint64{1}, [4]uint64{1}},
		{"one-q-minus-1", [4]uint64{1}, qMinus1},
		{"q-minus-1-squared", qMinus1, qMinus1},
		{"q-minus-1-times-q-minus-2", qMinus1, qMinus2},
		{"max-low-limb", [4]uint64{^uint64(0)}, [4]uint64{1}},
		{"max-high-limb", [4]uint64{1}, [4]uint64{0, 0, 0, 0xfffffffeffffffff}},
	}
	rng := rand.New(rand.NewPCG(0xa1, 0xb2))
	for i := 0; i < 200; i++ {
		var a, b [4]uint64
		for j := 0; j < 4; j++ {
			a[j], b[j] = rng.Uint64(), rng.Uint64()
		}
		// Keep operands canonical (< q): the kernels are specified for
		// reduced inputs and callers never pass larger values.
		a = primReduce(a[0], a[1], a[2], a[3], 0)
		b = primReduce(b[0], b[1], b[2], b[3], 0)
		cases = append(cases, struct {
			name string
			a, b [4]uint64
		}{"random", a, b})
	}

	for _, tc := range cases {
		want := ReferenceMul(tc.a, tc.b)
		for _, ch := range []Channel{ADCX, ADOX} {
			if got := MontgomeryMul(tc.a, tc.b, ch).R; got != want {
				t.Errorf("%s: model(%d) = %x, want %x", tc.name, ch, got, want)
			}
		}
	}
}

// TestADOXChainCorruptionReproduced verifies that every generated vector
// actually distinguishes the pre-fix ADOX chain from the fixed ADCX chain,
// and that the corrupting carry arrives at the reduction step the case claims.
func TestADOXChainCorruptionReproduced(t *testing.T) {
	suite, err := GenerateSuite()
	if err != nil {
		t.Fatal(err)
	}
	group := suite.Groups[0]
	for _, c := range group.Tests {
		aBE, err := decodeHex32(c.A)
		if err != nil {
			t.Fatalf("tc%d: %v", c.TCID, err)
		}
		bBE, err := decodeHex32(c.B)
		if err != nil {
			t.Fatalf("tc%d: %v", c.TCID, err)
		}
		a, b := LimbsFromBigEndian(&aBE), LimbsFromBigEndian(&bBE)

		fixed := MontgomeryMul(a, b, ADCX)
		old := MontgomeryMul(a, b, ADOX)
		if fixed.R == old.R {
			t.Errorf("tc%d: ADOX chain produces the correct result for this vector", c.TCID)
		}
		if got, want := hex32(fixed.R), c.Expected; got != want {
			t.Errorf("tc%d: model expected %s, vector pins %s", c.TCID, got, want)
		}

		hit := false
		for _, s := range old.Steps {
			if s.InOF == 1 {
				hit = true
			}
		}
		if !hit {
			t.Errorf("tc%d: no reduction step consumed a stale OF=1", c.TCID)
		}
	}
}

func TestConstructedFamilies(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xc3, 0xd4))
	for i := 0; i < 100; i++ {
		a, b := BuildRed0Hit(rng)
		if got, want := MontgomeryMul(a, b, ADCX).R, ReferenceMul(a, b); got != want {
			t.Fatalf("red0 family: model diverges from reference")
		}
		if MontgomeryMul(a, b, ADOX).Steps[0].InOF != 1 {
			t.Fatalf("red0 family: constructed vector did not hit the window")
		}
		if MontgomeryMul(a, b, ADOX).R == MontgomeryMul(a, b, ADCX).R {
			t.Fatalf("red0 family: old chain not corrupted")
		}

		a, b = BuildRed1Hit(rng)
		if got, want := MontgomeryMul(a, b, ADCX).R, ReferenceMul(a, b); got != want {
			t.Fatalf("red1 family: model diverges from reference")
		}
		if MontgomeryMul(a, b, ADOX).Steps[1].InOF != 1 {
			t.Fatalf("red1 family: constructed vector did not hit the window")
		}
		if MontgomeryMul(a, b, ADOX).R == MontgomeryMul(a, b, ADCX).R {
			t.Fatalf("red1 family: old chain not corrupted")
		}
	}
}

// TestBN256CarryTailUnreachable documents the audit of the three carry folds
// added to gfpMul in internal/sm9/bn256/gfp_cmn_amd64.s by the issue #560 fix
// (commit d85cf96). At each merge point the value in BX is hi(x[3]*y[k]), the
// ADCX chain's pending carry is 0 or 1, and for all x, y < 2^64
//
//	hi(x*y) <= hi((2^64-1)^2) = 2^64-2,
//
// so BX + carry never overflows and the pre-fix code never actually dropped a
// carry there. Unlike the SM2EC reduction chain, these folds are defensive:
// no input can violate them, so no boundary vector exists for BN256.
func TestBN256CarryTailUnreachable(t *testing.T) {
	max := ^uint64(0)
	pairs := [][2]uint64{
		{max, max}, {max, max - 1}, {max - 1, max}, {1 << 63, 2}, {1, max},
	}
	rng := rand.New(rand.NewPCG(0xe5, 0xf6))
	for i := 0; i < 10000; i++ {
		pairs = append(pairs, [2]uint64{rng.Uint64(), rng.Uint64()})
	}
	for _, p := range pairs {
		hi, _ := bits.Mul64(p[0], p[1])
		if hi > max-1 {
			t.Fatalf("hi(%#x * %#x) = %#x exceeds 2^64-2: the BN256 carry fold is reachable", p[0], p[1], hi)
		}
	}
}

func decodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, errNot64(s)
	}
	for i := 0; i < 32; i++ {
		hi, lo := hexNibble(s[2*i]), hexNibble(s[2*i+1])
		if hi < 0 || lo < 0 {
			return out, errNotHex(s)
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hex32(in [4]uint64) string {
	be := BigEndianFromLimbs(in)
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, v := range be {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&0xf]
	}
	return string(out)
}

func hexNibble(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

type hexError string

func (e hexError) Error() string { return string(e) }

func errNot64(s string) error  { return hexError("not 64 hex characters: " + s) }
func errNotHex(s string) error { return hexError("invalid hex: " + s) }
