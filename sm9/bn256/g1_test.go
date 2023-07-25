package bn256

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestG1AddNeg(t *testing.T) {
	g1, g2 := &G1{}, &G1{}

	g1.Neg(Gen1)
	g2.Add(g1, Gen1)
	if !g2.p.IsInfinity() {
		t.Fail()
	}
	g3 := &G1{}
	g3.Set(Gen1)
	if !g3.Equal(Gen1) {
		t.Fail()
	}
}

func TestG1AddSame(t *testing.T) {
	g1, g2 := &G1{}, &G1{}
	g1.Add(Gen1, Gen1)
	g2.Double(Gen1)

	if !g1.Equal(g2) {
		t.Fail()
	}
}

func TestCurvePointDouble(t *testing.T) {
	p := &curvePoint{}
	p.Double(p)
	if !p.IsInfinity() {
		t.Fail()
	}
}

func TestCurvePointDobuleComplete(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		p2 := &curvePoint{}
		p2.DoubleComplete(curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointDouble(p3, curveGen)
		p3.AffineFromJacobian()

		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})

	t.Run("exception case: IsInfinity", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.SetInfinity()
		p2 := &curvePoint{}
		p2.DoubleComplete(p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
}

func TestCurvePointAddComplete(t *testing.T) {
	t.Run("normal case", func(t *testing.T) {
		p1 := &curvePoint{}
		curvePointDouble(p1, curveGen)
		p1.AffineFromJacobian()

		p2 := &curvePoint{}
		p2.AddComplete(p1, curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointAdd(p3, curveGen, p1)
		p3.AffineFromJacobian()

		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})
	t.Run("exception case: double", func(t *testing.T) {
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, curveGen)
		p2.AffineFromProjective()

		p3 := &curvePoint{}
		curvePointDouble(p3, curveGen)
		p3.AffineFromJacobian()
		if !p2.Equal(p3) {
			t.Errorf("Got %v, expected %v", p2, p3)
		}
	})
	t.Run("exception case: neg", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.Neg(curveGen)
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
	t.Run("exception case: IsInfinity", func(t *testing.T) {
		p1 := &curvePoint{}
		p1.SetInfinity()
		p2 := &curvePoint{}
		p2.AddComplete(curveGen, p1)
		p2.AffineFromProjective()
		if !p2.Equal(curveGen) {
			t.Fatal("should be curveGen")
		}
		p2.AddComplete(p1, curveGen)
		p2.AffineFromProjective()
		if !p2.Equal(curveGen) {
			t.Fatal("should be curveGen")
		}
		p2.AddComplete(p1, p1)
		p2.AffineFromProjective()
		if !p2.IsInfinity() {
			t.Fatal("should be infinity")
		}
	})
}

type g1BaseMultTest struct {
	k string
}

var baseMultTests = []g1BaseMultTest{
	{
		"112233445566778899",
	},
	{
		"112233445566778899112233445566778899",
	},
	{
		"6950511619965839450988900688150712778015737983940691968051900319680",
	},
	{
		"13479972933410060327035789020509431695094902435494295338570602119423",
	},
	{
		"13479971751745682581351455311314208093898607229429740618390390702079",
	},
	{
		"13479972931865328106486971546324465392952975980343228160962702868479",
	},
	{
		"11795773708834916026404142434151065506931607341523388140225443265536",
	},
	{
		"784254593043826236572847595991346435467177662189391577090",
	},
	{
		"13479767645505654746623887797783387853576174193480695826442858012671",
	},
	{
		"205688069665150753842126177372015544874550518966168735589597183",
	},
	{
		"13479966930919337728895168462090683249159702977113823384618282123295",
	},
	{
		"50210731791415612487756441341851895584393717453129007497216",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368041",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368042",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368043",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368044",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368045",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368046",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368047",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368048",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368049",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368050",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368051",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368052",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368053",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368054",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368055",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368056",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368057",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368058",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368059",
	},
	{
		"26959946667150639794667015087019625940457807714424391721682722368060",
	},
}

func TestG1BaseMult(t *testing.T) {
	g1 := g1Curve
	g1Generic := g1.Params()

	scalars := make([]*big.Int, 0, len(baseMultTests)+1)
	for i := 1; i <= 20; i++ {
		k := new(big.Int).SetInt64(int64(i))
		scalars = append(scalars, k)
	}
	for _, e := range baseMultTests {
		k, _ := new(big.Int).SetString(e.k, 10)
		scalars = append(scalars, k)
	}
	k := new(big.Int).SetInt64(1)
	k.Lsh(k, 500)
	scalars = append(scalars, k)

	for i, k := range scalars {
		x, y := g1.ScalarBaseMult(k.Bytes())
		x2, y2 := g1Generic.ScalarBaseMult(k.Bytes())
		if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
			t.Errorf("#%d: got (%x, %x), want (%x, %x)", i, x, y, x2, y2)
		}

		if testing.Short() && i > 5 {
			break
		}
	}
}

func TestG1ScalarMult(t *testing.T) {
	checkScalar := func(t *testing.T, scalar []byte) {
		p1, err := (&G1{}).ScalarBaseMult(scalar)
		fatalIfErr(t, err)
		p2, err := (&G1{}).ScalarMult(Gen1, scalar)
		fatalIfErr(t, err)
		p1.p.MakeAffine()
		p2.p.MakeAffine()
		if !p1.Equal(p2) {
			t.Error("[k]G != ScalarBaseMult(k)")
		}

		d := new(big.Int).SetBytes(scalar)
		d.Sub(Order, d)
		d.Mod(d, Order)
		g1, err := (&G1{}).ScalarBaseMult(d.FillBytes(make([]byte, len(scalar))))
		fatalIfErr(t, err)
		g1.Add(g1, p1)
		g1.p.MakeAffine()
		if !g1.p.IsInfinity() {
			t.Error("[N - k]G + [k]G != ∞")
		}
	}

	byteLen := len(Order.Bytes())
	bitLen := Order.BitLen()
	t.Run("0", func(t *testing.T) { checkScalar(t, make([]byte, byteLen)) })
	t.Run("1", func(t *testing.T) {
		checkScalar(t, big.NewInt(1).FillBytes(make([]byte, byteLen)))
	})
	t.Run("N-6", func(t *testing.T) {
		checkScalar(t, new(big.Int).Sub(Order, big.NewInt(6)).Bytes())
	})
	t.Run("N-1", func(t *testing.T) {
		checkScalar(t, new(big.Int).Sub(Order, big.NewInt(1)).Bytes())
	})
	t.Run("N", func(t *testing.T) { checkScalar(t, Order.Bytes()) })
	t.Run("N+1", func(t *testing.T) {
		checkScalar(t, new(big.Int).Add(Order, big.NewInt(1)).Bytes())
	})
	t.Run("N+22", func(t *testing.T) {
		checkScalar(t, new(big.Int).Add(Order, big.NewInt(22)).Bytes())
	})
	t.Run("all1s", func(t *testing.T) {
		s := new(big.Int).Lsh(big.NewInt(1), uint(bitLen))
		s.Sub(s, big.NewInt(1))
		checkScalar(t, s.Bytes())
	})
	if testing.Short() {
		return
	}
	for i := 0; i < bitLen; i++ {
		t.Run(fmt.Sprintf("1<<%d", i), func(t *testing.T) {
			s := new(big.Int).Lsh(big.NewInt(1), uint(i))
			checkScalar(t, s.FillBytes(make([]byte, byteLen)))
		})
	}
	for i := 0; i <= 64; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			checkScalar(t, big.NewInt(int64(i)).FillBytes(make([]byte, byteLen)))
		})
	}

	// Test N-64...N+64 since they risk overlapping with precomputed table values
	// in the final additions.
	for i := int64(-64); i <= 64; i++ {
		t.Run(fmt.Sprintf("N%+d", i), func(t *testing.T) {
			checkScalar(t, new(big.Int).Add(Order, big.NewInt(i)).Bytes())
		})
	}

}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFuzz(t *testing.T) {
	g1 := g1Curve
	g1Generic := g1.Params()

	var scalar1 [32]byte
	var scalar2 [32]byte
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}

	for {
		select {
		case <-timeout.C:
			return
		default:
		}

		io.ReadFull(rand.Reader, scalar1[:])
		io.ReadFull(rand.Reader, scalar2[:])

		x, y := g1.ScalarBaseMult(scalar1[:])
		x2, y2 := g1Generic.ScalarBaseMult(scalar1[:])

		xx, yy := g1.ScalarMult(x, y, scalar2[:])
		xx2, yy2 := g1Generic.ScalarMult(x2, y2, scalar2[:])

		if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
			t.Fatalf("ScalarBaseMult does not match reference result with scalar: %x, please report this error to https://github.com/emmansun/gmsm/issues", scalar1)
		}

		if xx.Cmp(xx2) != 0 || yy.Cmp(yy2) != 0 {
			t.Fatalf("ScalarMult does not match reference result with scalars: %x and %x, please report this error to https://github.com/emmansun/gmsm/issues", scalar1, scalar2)
		}
	}
}

func TestG1OnCurve(t *testing.T) {
	if !g1Curve.IsOnCurve(g1Curve.Params().Gx, g1Curve.Params().Gy) {
		t.Error("basepoint is not on the curve")
	}
}

func TestOffCurve(t *testing.T) {
	x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
	if g1Curve.IsOnCurve(x, y) {
		t.Errorf("point off curve is claimed to be on the curve")
	}

	byteLen := (g1Curve.Params().BitSize + 7) / 8
	b := make([]byte, 1+2*byteLen)
	b[0] = 4 // uncompressed point
	x.FillBytes(b[1 : 1+byteLen])
	y.FillBytes(b[1+byteLen : 1+2*byteLen])

	x1, y1 := Unmarshal(g1Curve, b)
	if x1 != nil || y1 != nil {
		t.Errorf("unmarshaling a point not on the curve succeeded")
	}
}

func isInfinity(x, y *big.Int) bool {
	return x.Sign() == 0 && y.Sign() == 0
}

func TestInfinity(t *testing.T) {
	x0, y0 := new(big.Int), new(big.Int)
	xG, yG := g1Curve.Params().Gx, g1Curve.Params().Gy

	if !isInfinity(g1Curve.ScalarMult(xG, yG, g1Curve.Params().N.Bytes())) {
		t.Errorf("x^q != ∞")
	}
	if !isInfinity(g1Curve.ScalarMult(xG, yG, []byte{0})) {
		t.Errorf("x^0 != ∞")
	}

	if !isInfinity(g1Curve.ScalarMult(x0, y0, []byte{1, 2, 3})) {
		t.Errorf("∞^k != ∞")
	}
	if !isInfinity(g1Curve.ScalarMult(x0, y0, []byte{0})) {
		t.Errorf("∞^0 != ∞")
	}

	if !isInfinity(g1Curve.ScalarBaseMult(g1Curve.Params().N.Bytes())) {
		t.Errorf("b^q != ∞")
	}
	if !isInfinity(g1Curve.ScalarBaseMult([]byte{0})) {
		t.Errorf("b^0 != ∞")
	}

	if !isInfinity(g1Curve.Double(x0, y0)) {
		t.Errorf("2∞ != ∞")
	}
	// There is no other point of order two on the NIST curves (as they have
	// cofactor one), so Double can't otherwise return the point at infinity.

	nMinusOne := new(big.Int).Sub(g1Curve.Params().N, big.NewInt(1))
	x, y := g1Curve.ScalarMult(xG, yG, nMinusOne.Bytes())
	x, y = g1Curve.Add(x, y, xG, yG)
	if !isInfinity(x, y) {
		t.Errorf("x^(q-1) + x != ∞")
	}
	x, y = g1Curve.Add(xG, yG, x0, y0)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("x+∞ != x")
	}
	x, y = g1Curve.Add(x0, y0, xG, yG)
	if x.Cmp(xG) != 0 || y.Cmp(yG) != 0 {
		t.Errorf("∞+x != x")
	}

	if !g1Curve.IsOnCurve(x0, y0) {
		t.Errorf("IsOnCurve(∞) != true")
	}
	/*
			if xx, yy := Unmarshal(g1Curve, Marshal(g1Curve, x0, y0)); xx == nil || yy == nil {
				t.Errorf("Unmarshal(Marshal(∞)) did return an error")
			}
			// We don't test UnmarshalCompressed(MarshalCompressed(∞)) because there are
			// two valid points with x = 0.
			if xx, yy := Unmarshal(g1Curve, []byte{0x00}); xx != nil || yy != nil {
				t.Errorf("Unmarshal(∞) did not return an error")
			}

		byteLen := (g1Curve.Params().BitSize + 7) / 8
		buf := make([]byte, byteLen*2+1)
		buf[0] = 4 // Uncompressed format.
		if xx, yy := Unmarshal(g1Curve, buf); xx == nil || yy == nil {
			t.Errorf("Unmarshal((0,0)) did return an error")
		}
	*/
}

func testAllCurves(t *testing.T, f func(*testing.T, Curve)) {
	tests := []struct {
		name  string
		curve Curve
	}{
		{"g1", g1Curve},
		{"g1/Params", g1Curve.params},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestMarshal(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve Curve) {
		_, x, y, err := GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serialized := Marshal(curve, x, y)
		xx, yy := Unmarshal(curve, serialized)
		if xx == nil {
			t.Fatal("failed to unmarshal")
		}
		if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
			t.Fatal("unmarshal returned different values")
		}
	})
}

func TestMarshalCompressed(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve Curve) {
		_, x, y, err := GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testMarshalCompressed(t, curve, x, y, nil)
	})
}

func testMarshalCompressed(t *testing.T, curve Curve, x, y *big.Int, want []byte) {
	if !curve.IsOnCurve(x, y) {
		t.Fatal("invalid test point")
	}
	got := MarshalCompressed(curve, x, y)
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
func TestInvalidCoordinates(t *testing.T) {
	checkIsOnCurveFalse := func(name string, x, y *big.Int) {
		if g1Curve.IsOnCurve(x, y) {
			t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
		}
	}

	p := g1Curve.Params().P
	_, x, y, _ := GenerateKey(g1Curve, rand.Reader)
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

	/*
		// Check if positive values are reduced modulo P.
		xx.Add(x, p)
		checkIsOnCurveFalse("x+P, y", xx, y)
		yy.Add(y, p)
		checkIsOnCurveFalse("x, y+P", x, yy)
	*/
	// Check if the overflow is dropped.
	xx.Add(x, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x+2⁵³⁵, y", xx, y)
	yy.Add(y, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x, y+2⁵³⁵", x, yy)

	// Check if P is treated like zero (if possible).
	// y^2 = x^3 + B
	// y = mod_sqrt(x^3 + B)
	// y = mod_sqrt(B) if x = 0
	// If there is no modsqrt, there is no point with x = 0, can't test x = P.
	if yy := new(big.Int).ModSqrt(g1Curve.Params().B, p); yy != nil {
		if !g1Curve.IsOnCurve(big.NewInt(0), yy) {
			t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
		}
		checkIsOnCurveFalse("P, y", p, yy)
	}
}

func TestLargeIsOnCurve(t *testing.T) {
	large := big.NewInt(1)
	large.Lsh(large, 1000)
	if g1Curve.IsOnCurve(large, large) {
		t.Errorf("(2^1000, 2^1000) is reported on the curve")
	}
}

func Test_G1MarshalCompressed(t *testing.T) {
	e, e2 := &G1{}, &G1{}
	ret := e.MarshalCompressed()
	_, err := e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if !e2.p.IsInfinity() {
		t.Errorf("not same")
	}
	e.p.Set(curveGen)
	ret = e.MarshalCompressed()
	_, err = e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if e2.p.x != e.p.x || e2.p.y != e.p.y || e2.p.z != e.p.z {
		t.Errorf("not same")
	}
	e.p.Neg(e.p)
	ret = e.MarshalCompressed()
	_, err = e2.UnmarshalCompressed(ret)
	if err != nil {
		t.Fatal(err)
	}
	if e2.p.x != e.p.x || e2.p.y != e.p.y || e2.p.z != e.p.z {
		t.Errorf("not same")
	}
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, Curve)) {
	tests := []struct {
		name  string
		curve Curve
	}{
		{"sm9", g1Curve},
		{"sm9Parmas", g1Curve.Params()},
	}
	for _, test := range tests {
		curve := test.curve
		b.Run(test.name, func(b *testing.B) {
			f(b, curve)
		})
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		priv, _, _, _ := GenerateKey(curve, rand.Reader)
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
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		_, x, y, _ := GenerateKey(curve, rand.Reader)
		priv, _, _, _ := GenerateKey(curve, rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve Curve) {
		_, x, y, _ := GenerateKey(curve, rand.Reader)
		b.Run("Uncompressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := Marshal(curve, x, y)
				xx, yy := Unmarshal(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
		b.Run("Compressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := MarshalCompressed(curve, x, y)
				xx, yy := UnmarshalCompressed(curve, buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
	})
}

func BenchmarkAddPoint(b *testing.B) {
	p1 := &curvePoint{}
	curvePointDouble(p1, curveGen)
	p1.AffineFromJacobian()
	p2 := &curvePoint{}

	b.Run("Add complete", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p2.AddComplete(curveGen, p1)
		}
	})

	b.Run("Add traditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			curvePointAdd(p2, curveGen, p1)
		}
	})
}

func BenchmarkDoublePoint(b *testing.B) {
	p2 := &curvePoint{}

	b.Run("Double complete", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p2.DoubleComplete(curveGen)
		}
	})

	b.Run("Double traditional", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			curvePointDouble(p2, curveGen)
		}
	})
}
