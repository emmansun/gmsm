package sm2ec

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

var _ = elliptic.P256() // force NIST P curves init, avoid panic when we invoke generic implementation's method

// genericParamsForCurve returns the dereferenced CurveParams for
// the specified curve. This is used to avoid the logic for
// upgrading a curve to its specific implementation, forcing
// usage of the generic implementation.
func genericParamsForCurve(c elliptic.Curve) *elliptic.CurveParams {
	d := *(c.Params())
	return &d
}

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"SM2P256", P256()},
		{"SM2P256/Params", genericParamsForCurve(P256())},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve elliptic.Curve) {
		if !curve.IsOnCurve(curve.Params().Gx, curve.Params().Gy) {
			t.Error("basepoint is not on the curve")
		}
	})
}

func TestOffCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve elliptic.Curve) {
		x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
		if curve.IsOnCurve(x, y) {
			t.Errorf("point off curve is claimed to be on the curve")
		}

		byteLen := (curve.Params().BitSize + 7) / 8
		b := make([]byte, 1+2*byteLen)
		b[0] = 4 // uncompressed point
		x.FillBytes(b[1 : 1+byteLen])
		y.FillBytes(b[1+byteLen : 1+2*byteLen])

		x1, y1 := Unmarshal(curve, b)
		if x1 != nil || y1 != nil {
			t.Errorf("unmarshaling a point not on the curve succeeded")
		}
	})
}

func TestInfinity(t *testing.T) {
	testAllCurves(t, testInfinity)
}

func isInfinity(x, y *big.Int) bool {
	return x.Sign() == 0 && y.Sign() == 0
}

func testInfinity(t *testing.T, curve elliptic.Curve) {
	x0, y0 := new(big.Int), new(big.Int)
	xG, yG := curve.Params().Gx, curve.Params().Gy

	if !isInfinity(curve.ScalarMult(xG, yG, curve.Params().N.Bytes())) {
		t.Errorf("x^q != ∞")
	}
	if !isInfinity(curve.ScalarMult(xG, yG, []byte{0})) {
		t.Errorf("x^0 != ∞")
	}

	if !isInfinity(curve.ScalarMult(x0, y0, []byte{1, 2, 3})) {
		t.Errorf("∞^k != ∞")
	}
	if !isInfinity(curve.ScalarMult(x0, y0, []byte{0})) {
		t.Errorf("∞^0 != ∞")
	}

	if !isInfinity(curve.ScalarBaseMult(curve.Params().N.Bytes())) {
		t.Errorf("b^q != ∞")
	}
	if !isInfinity(curve.ScalarBaseMult([]byte{0})) {
		t.Errorf("b^0 != ∞")
	}

	if !isInfinity(curve.Double(x0, y0)) {
		t.Errorf("2∞ != ∞")
	}
	// There is no other point of order two on the NIST curves (as they have
	// cofactor one), so Double can't otherwise return the point at infinity.

	nMinusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	x, y := curve.ScalarMult(xG, yG, nMinusOne.Bytes())
	x, y = curve.Add(x, y, xG, yG)
	if !isInfinity(x, y) {
		t.Errorf("x^(q-1) + x != ∞")
	}
	x, y = curve.Add(xG, yG, x0, y0)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("x+∞ != x")
	}
	x, y = curve.Add(x0, y0, xG, yG)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("∞+x != x")
	}

	if curve.IsOnCurve(x0, y0) {
		t.Errorf("IsOnCurve(∞) == true")
	}

	if xx, yy := Unmarshal(curve, elliptic.Marshal(curve, x0, y0)); xx != nil || yy != nil {
		t.Errorf("Unmarshal(Marshal(∞)) did not return an error")
	}
	// We don't test UnmarshalCompressed(MarshalCompressed(∞)) because there are
	// two valid points with x = 0.
	if xx, yy := Unmarshal(curve, []byte{0x00}); xx != nil || yy != nil {
		t.Errorf("Unmarshal(∞) did not return an error")
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	buf := make([]byte, byteLen*2+1)
	buf[0] = 4 // Uncompressed format.
	if xx, yy := Unmarshal(curve, buf); xx != nil || yy != nil {
		t.Errorf("Unmarshal((0,0)) did not return an error")
	}
}

func TestMarshal(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve elliptic.Curve) {
		_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serialized := elliptic.Marshal(curve, x, y)
		xx, yy := Unmarshal(curve, serialized)
		if xx == nil {
			t.Fatal("failed to unmarshal")
		}
		if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
			t.Fatal("unmarshal returned different values")
		}
	})
}

// TestInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestInvalidCoordinates(t *testing.T) {
	testAllCurves(t, testInvalidCoordinates)
}

func testInvalidCoordinates(t *testing.T, curve elliptic.Curve) {
	checkIsOnCurveFalse := func(name string, x, y *big.Int) {
		if curve.IsOnCurve(x, y) {
			t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
		}
	}

	p := curve.Params().P
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	xx, yy := new(big.Int), new(big.Int)

	// Check if the sign is getting dropped.
	xx.Neg(x)
	checkIsOnCurveFalse("-x, y", xx, y)
	yy.Neg(y)
	checkIsOnCurveFalse("x, -y", x, yy)

	// Check if negative values are reduced modulo P.
	xx.Sub(x, p)
	checkIsOnCurveFalse("x-P, y", xx, y)
	yy.Sub(y, p)
	checkIsOnCurveFalse("x, y-P", x, yy)

	// Check if positive values are reduced modulo P.
	xx.Add(x, p)
	checkIsOnCurveFalse("x+P, y", xx, y)
	yy.Add(y, p)
	checkIsOnCurveFalse("x, y+P", x, yy)

	// Check if the overflow is dropped.
	xx.Add(x, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x+2⁵³⁵, y", xx, y)
	yy.Add(y, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x, y+2⁵³⁵", x, yy)

	// Check if P is treated like zero (if possible).
	// y^2 = x^3 - 3x + B
	// y = mod_sqrt(x^3 - 3x + B)
	// y = mod_sqrt(B) if x = 0
	// If there is no modsqrt, there is no point with x = 0, can't test x = P.
	if yy := new(big.Int).ModSqrt(curve.Params().B, p); yy != nil {
		if !curve.IsOnCurve(big.NewInt(0), yy) {
			t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
		}
		checkIsOnCurveFalse("P, y", p, yy)
	}
}

func TestMarshalCompressed(t *testing.T) {
	t.Run("P-256/03", func(t *testing.T) {
		data, _ := hex.DecodeString("031b5709a068f5c1d05d0a61c0c70a13310df2d3a6c2ca9c9bba53337ea3e10de3")
		x, _ := new(big.Int).SetString("1b5709a068f5c1d05d0a61c0c70a13310df2d3a6c2ca9c9bba53337ea3e10de3", 16)
		y, _ := new(big.Int).SetString("a7ac81d1fdd4fcd224bbd95183136f948861812594ef24bd867c23d955fee3bb", 16)
		testMarshalCompressed(t, P256(), x, y, data)
	})
	t.Run("P-256/02", func(t *testing.T) {
		data, _ := hex.DecodeString("0258f9a2efca4139f2b07662b937439a719ea3bf59d7de346c365db7c85d4bc32a")
		x, _ := new(big.Int).SetString("58f9a2efca4139f2b07662b937439a719ea3bf59d7de346c365db7c85d4bc32a", 16)
		y, _ := new(big.Int).SetString("02680fbe48b1d8cf023d0b7c1d9ab9b56535384729db5fcb8db29ec72c7fc9ca", 16)
		testMarshalCompressed(t, P256(), x, y, data)
	})

	t.Run("Invalid", func(t *testing.T) {
		data, _ := hex.DecodeString("02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535")
		X, Y := UnmarshalCompressed(P256(), data)
		if X != nil || Y != nil {
			t.Error("expected an error for invalid encoding")
		}
	})

	if testing.Short() {
		t.Skip("skipping other curves on short test")
	}

	testAllCurves(t, func(t *testing.T, curve elliptic.Curve) {
		_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testMarshalCompressed(t, curve, x, y, nil)
	})
}

func testMarshalCompressed(t *testing.T, curve elliptic.Curve, x, y *big.Int, want []byte) {
	if !curve.IsOnCurve(x, y) {
		t.Fatal("invalid test point")
	}
	got := elliptic.MarshalCompressed(curve, x, y)
	if want != nil && !bytes.Equal(got, want) {
		t.Errorf("got unexpected MarshalCompressed result: got %x, want %x", got, want)
	}

	X, Y := UnmarshalCompressed(curve, got)
	if X == nil || Y == nil {
		t.Fatalf("UnmarshalCompressed failed unexpectedly")
	}

	if !curve.IsOnCurve(X, Y) {
		t.Error("UnmarshalCompressed returned a point not on the curve")
	}
	if X.Cmp(x) != 0 || Y.Cmp(y) != 0 {
		t.Errorf("point did not round-trip correctly: got (%v, %v), want (%v, %v)", X, Y, x, y)
	}
}

func TestLargeIsOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve elliptic.Curve) {
		large := big.NewInt(1)
		large.Lsh(large, 1000)
		if curve.IsOnCurve(large, large) {
			t.Errorf("(2^1000, 2^1000) is reported on the curve")
		}
	})
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"SM2P256", P256()},
	}
	for _, test := range tests {
		curve := test.curve
		b.Run(test.name, func(b *testing.B) {
			f(b, curve)
		})
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		priv, _, _, _ := elliptic.GenerateKey(curve, rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, _ := curve.ScalarBaseMult(priv)
			// Prevent the compiler from optimizing out the operation.
			priv[0] ^= byte(x.Bits()[0])
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
		priv, _, _, _ := elliptic.GenerateKey(curve, rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
		b.Run("Uncompressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := elliptic.Marshal(curve, x, y)
				xx, yy := Unmarshal(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
		b.Run("Compressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := elliptic.MarshalCompressed(curve, x, y)
				xx, yy := UnmarshalCompressed(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
	})
}
