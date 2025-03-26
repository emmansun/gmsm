package bn256

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"sync"
)

func randomK(r io.Reader) (k *big.Int, err error) {
	for {
		k, err = rand.Int(r, Order)
		if err != nil || k.Sign() > 0 {
			return
		}
	}
}

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 struct {
	p *curvePoint
}

// Gen1 is the generator of G1.
var Gen1 = &G1{curveGen}

var g1GeneratorTable *[32 * 2]curvePointTable
var g1GeneratorTableOnce sync.Once

func (g *G1) generatorTable() *[32 * 2]curvePointTable {
	g1GeneratorTableOnce.Do(func() {
		g1GeneratorTable = new([32 * 2]curvePointTable)
		base := NewCurveGenerator()
		for i := 0; i < 32*2; i++ {
			g1GeneratorTable[i][0] = &curvePoint{}
			g1GeneratorTable[i][0].Set(base)

			g1GeneratorTable[i][1] = &curvePoint{}
			g1GeneratorTable[i][1].Double(g1GeneratorTable[i][0])
			g1GeneratorTable[i][2] = &curvePoint{}
			g1GeneratorTable[i][2].Add(g1GeneratorTable[i][1], base)

			g1GeneratorTable[i][3] = &curvePoint{}
			g1GeneratorTable[i][3].Double(g1GeneratorTable[i][1])
			g1GeneratorTable[i][4] = &curvePoint{}
			g1GeneratorTable[i][4].Add(g1GeneratorTable[i][3], base)

			g1GeneratorTable[i][5] = &curvePoint{}
			g1GeneratorTable[i][5].Double(g1GeneratorTable[i][2])
			g1GeneratorTable[i][6] = &curvePoint{}
			g1GeneratorTable[i][6].Add(g1GeneratorTable[i][5], base)

			g1GeneratorTable[i][7] = &curvePoint{}
			g1GeneratorTable[i][7].Double(g1GeneratorTable[i][3])
			g1GeneratorTable[i][8] = &curvePoint{}
			g1GeneratorTable[i][8].Add(g1GeneratorTable[i][7], base)

			g1GeneratorTable[i][9] = &curvePoint{}
			g1GeneratorTable[i][9].Double(g1GeneratorTable[i][4])
			g1GeneratorTable[i][10] = &curvePoint{}
			g1GeneratorTable[i][10].Add(g1GeneratorTable[i][9], base)

			g1GeneratorTable[i][11] = &curvePoint{}
			g1GeneratorTable[i][11].Double(g1GeneratorTable[i][5])
			g1GeneratorTable[i][12] = &curvePoint{}
			g1GeneratorTable[i][12].Add(g1GeneratorTable[i][11], base)

			g1GeneratorTable[i][13] = &curvePoint{}
			g1GeneratorTable[i][13].Double(g1GeneratorTable[i][6])
			g1GeneratorTable[i][14] = &curvePoint{}
			g1GeneratorTable[i][14].Add(g1GeneratorTable[i][13], base)

			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return g1GeneratorTable
}

// RandomG1 returns x and g₁ˣ where x is a random, non-zero number read from r.
func RandomG1(r io.Reader) (*big.Int, *G1, error) {
	k, err := randomK(r)
	if err != nil {
		return nil, nil, err
	}

	g1, err := new(G1).ScalarBaseMult(NormalizeScalar(k.Bytes()))
	return k, g1, err
}

func (g *G1) String() string {
	return "sm9.G1" + g.p.String()
}

func NormalizeScalar(scalar []byte) []byte {
	if len(scalar) == 32 {
		return scalar
	}
	s := new(big.Int).SetBytes(scalar)
	if len(scalar) > 32 {
		s.Mod(s, Order)
	}
	out := make([]byte, 32)
	return s.FillBytes(out)
}

// ScalarBaseMult sets e to scaler*g where g is the generator of the group and then
// returns e.
func (e *G1) ScalarBaseMult(scalar []byte) (*G1, error) {
	if len(scalar) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	if e.p == nil {
		e.p = &curvePoint{}
	}

	//e.p.Mul(curveGen, k)

	tables := e.generatorTable()
	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := NewCurvePoint()
	e.p.SetInfinity()
	tableIndex := len(tables) - 1
	for _, byte := range scalar {
		windowValue := byte >> 4
		tables[tableIndex].Select(t, windowValue)
		e.p.Add(e.p, t)
		tableIndex--
		windowValue = byte & 0b1111
		tables[tableIndex].Select(t, windowValue)
		e.p.Add(e.p, t)
		tableIndex--
	}
	return e, nil
}

// ScalarMult sets e to a*k and then returns e.
func (e *G1) ScalarMult(a *G1, scalar []byte) (*G1, error) {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	//e.p.Mul(a.p, k)
	// Compute a curvePointTable for the base point a.
	var table = curvePointTable{NewCurvePoint(), NewCurvePoint(), NewCurvePoint(),
		NewCurvePoint(), NewCurvePoint(), NewCurvePoint(), NewCurvePoint(),
		NewCurvePoint(), NewCurvePoint(), NewCurvePoint(), NewCurvePoint(),
		NewCurvePoint(), NewCurvePoint(), NewCurvePoint(), NewCurvePoint()}
	table[0].Set(a.p)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], a.p)
	}
	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := &G1{NewCurvePoint()}
	e.p.SetInfinity()
	for i, byte := range scalar {
		// No need to double on the first iteration, as p is the identity at
		// this point, and [N]∞ = ∞.
		if i != 0 {
			e.Double(e)
			e.Double(e)
			e.Double(e)
			e.Double(e)
		}
		windowValue := byte >> 4
		table.Select(t.p, windowValue)
		e.Add(e, t)
		e.Double(e)
		e.Double(e)
		e.Double(e)
		e.Double(e)
		windowValue = byte & 0b1111
		table.Select(t.p, windowValue)
		e.Add(e, t)
	}
	return e, nil
}

// Add sets e to a+b and then returns e.
func (e *G1) Add(a, b *G1) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Add(a.p, b.p)
	return e
}

// Double sets e to [2]a and then returns e.
func (e *G1) Double(a *G1) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Double(a.p)
	return e
}

// Neg sets e to -a and then returns e.
func (e *G1) Neg(a *G1) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Neg(a.p)
	return e
}

// Set sets e to a and then returns e.
func (e *G1) Set(a *G1) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Set(a.p)
	return e
}

// Marshal converts e to a byte slice.
func (e *G1) Marshal() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	ret := make([]byte, numBytes*2)

	e.fillBytes(ret)
	return ret
}

// MarshalUncompressed converts e to a byte slice with prefix
func (e *G1) MarshalUncompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	ret := make([]byte, numBytes*2+1)
	ret[0] = 4

	e.fillBytes(ret[1:])
	return ret
}

// MarshalCompressed converts e to a byte slice with compress prefix.
// If the point is not on the curve (or is the conventional point at infinity), the behavior is undefined.
func (e *G1) MarshalCompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	ret := make([]byte, numBytes+1)
	if e.p == nil {
		e.p = &curvePoint{}
	}

	e.p.MakeAffine()
	temp := &gfP{}
	montDecode(temp, &e.p.y)

	temp.Marshal(ret[1:])
	ret[0] = (ret[numBytes] & 1) | 2
	montDecode(temp, &e.p.x)
	temp.Marshal(ret[1:])

	return ret
}

// UnmarshalCompressed sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G1) UnmarshalCompressed(data []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	if len(data) < 1+numBytes {
		return nil, errors.New("sm9.G1: not enough data")
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, errors.New("sm9.G1: invalid point compress byte")
	}
	if e.p == nil {
		e.p = &curvePoint{}
	} else {
		e.p.x.Set(zero)
		e.p.y.Set(zero)
	}
	e.p.x.Unmarshal(data[1:])
	montEncode(&e.p.x, &e.p.x)
	x3 := e.p.polynomial(&e.p.x)
	e.p.y.Sqrt(x3)
	montDecode(x3, &e.p.y)
	if byte(x3[0]&1) != data[0]&1 {
		gfpNeg(&e.p.y, &e.p.y)
	}
	if e.p.x.Equal(zero) == 1 && e.p.y.Equal(zero) == 1 {
		// This is the point at infinity.
		e.p.SetInfinity()
	} else {
		e.p.z.Set(one)
		e.p.t.Set(one)

		if !e.p.IsOnCurve() {
			return nil, errors.New("sm9.G1: malformed point")
		}
	}

	return data[numBytes+1:], nil
}

func (e *G1) fillBytes(buffer []byte) {
	const numBytes = 256 / 8

	if e.p == nil {
		e.p = &curvePoint{}
	}

	e.p.MakeAffine()
	if e.p.IsInfinity() {
		return
	}
	temp := &gfP{}

	montDecode(temp, &e.p.x)
	temp.Marshal(buffer)
	montDecode(temp, &e.p.y)
	temp.Marshal(buffer[numBytes:])
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G1) Unmarshal(m []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	if len(m) < 2*numBytes {
		return nil, errors.New("sm9.G1: not enough data")
	}

	if e.p == nil {
		e.p = &curvePoint{}
	} else {
		e.p.x.Set(zero)
		e.p.y.Set(zero)
	}

	e.p.x.Unmarshal(m)
	e.p.y.Unmarshal(m[numBytes:])
	montEncode(&e.p.x, &e.p.x)
	montEncode(&e.p.y, &e.p.y)

	if e.p.x.Equal(zero) == 1 && e.p.y.Equal(zero) == 1 {
		// This is the point at infinity.
		e.p.SetInfinity()
	} else {
		e.p.z.Set(one)
		e.p.t.Set(one)

		if !e.p.IsOnCurve() {
			return nil, errors.New("sm9.G1: malformed point")
		}
	}

	return m[2*numBytes:], nil
}

// Equal compare e and other
func (e *G1) Equal(other *G1) bool {
	if e.p == nil && other.p == nil {
		return true
	}
	return e.p.Equal(other.p)
}

// IsOnCurve returns true if e is on the curve.
func (e *G1) IsOnCurve() bool {
	return e.p.IsOnCurve()
}
