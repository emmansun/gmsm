package sm9

import (
	"errors"
	"io"
	"math/big"
	"sync"
)

// G2 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G2 struct {
	p *twistPoint
}

//Gen2 is the generator of G2.
var Gen2 = &G2{twistGen}

var g2GeneratorTable *[32 * 2]twistPointTable
var g2GeneratorTableOnce sync.Once

func (g *G2) generatorTable() *[32 * 2]twistPointTable {
	g2GeneratorTableOnce.Do(func() {
		g2GeneratorTable = new([32 * 2]twistPointTable)
		base := NewTwistGenerator()
		for i := 0; i < 32*2; i++ {
			g2GeneratorTable[i][0] = &twistPoint{}
			g2GeneratorTable[i][0].Set(base)
			for j := 1; j < 15; j += 2 {
				g2GeneratorTable[i][j] = &twistPoint{}
				g2GeneratorTable[i][j].Double(g2GeneratorTable[i][j/2])
				g2GeneratorTable[i][j+1] = &twistPoint{}
				g2GeneratorTable[i][j+1].Add(g2GeneratorTable[i][j], base)
			}
			base.Double(base)
			base.Double(base)
			base.Double(base)
			base.Double(base)
		}
	})
	return g2GeneratorTable
}

// RandomG2 returns x and g₂ˣ where x is a random, non-zero number read from r.
func RandomG2(r io.Reader) (*big.Int, *G2, error) {
	k, err := randomK(r)
	if err != nil {
		return nil, nil, err
	}

	return k, new(G2).ScalarBaseMult(k), nil
}

func (e *G2) String() string {
	return "sm9.G2" + e.p.String()
}

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns out.
func (e *G2) ScalarBaseMult(k *big.Int) *G2 {
	if e.p == nil {
		e.p = &twistPoint{}
	}
	//e.p.Mul(twistGen, k)

	scalar := normalizeScalar(k.Bytes())
	tables := e.generatorTable()
	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	t := NewTwistPoint()
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

	return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *G2) ScalarMult(a *G2, k *big.Int) *G2 {
	if e.p == nil {
		e.p = &twistPoint{}
	}
	//e.p.Mul(a.p, k)
	// Compute a twistPointTable for the base point a.
	var table = twistPointTable{NewTwistPoint(), NewTwistPoint(), NewTwistPoint(),
		NewTwistPoint(), NewTwistPoint(), NewTwistPoint(), NewTwistPoint(),
		NewTwistPoint(), NewTwistPoint(), NewTwistPoint(), NewTwistPoint(),
		NewTwistPoint(), NewTwistPoint(), NewTwistPoint(), NewTwistPoint()}
	table[0].Set(a.p)
	for i := 1; i < 15; i += 2 {
		table[i].Double(table[i/2])
		table[i+1].Add(table[i], a.p)
	}
	// Instead of doing the classic double-and-add chain, we do it with a
	// four-bit window: we double four times, and then add [0-15]P.
	t := &G2{NewTwistPoint()}
	e.p.SetInfinity()
	scalarBytes := normalizeScalar(k.Bytes())
	for i, byte := range scalarBytes {
		// No need to double on the first iteration, as p is the identity at
		// this point, and [N]∞ = ∞.
		if i != 0 {
			e.p.Double(e.p)
			e.p.Double(e.p)
			e.p.Double(e.p)
			e.p.Double(e.p)
		}
		windowValue := byte >> 4
		table.Select(t.p, windowValue)
		e.Add(e, t)
		e.p.Double(e.p)
		e.p.Double(e.p)
		e.p.Double(e.p)
		e.p.Double(e.p)
		windowValue = byte & 0b1111
		table.Select(t.p, windowValue)
		e.Add(e, t)
	}
	return e
}

// Add sets e to a+b and then returns e.
func (e *G2) Add(a, b *G2) *G2 {
	if e.p == nil {
		e.p = &twistPoint{}
	}
	e.p.Add(a.p, b.p)
	return e
}

// Neg sets e to -a and then returns e.
func (e *G2) Neg(a *G2) *G2 {
	if e.p == nil {
		e.p = &twistPoint{}
	}
	e.p.Neg(a.p)
	return e
}

// Set sets e to a and then returns e.
func (e *G2) Set(a *G2) *G2 {
	if e.p == nil {
		e.p = &twistPoint{}
	}
	e.p.Set(a.p)
	return e
}

// Marshal converts e into a byte slice.
func (e *G2) Marshal() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	ret := make([]byte, numBytes*4)
	e.fillBytes(ret)
	return ret
}

// MarshalUncompressed converts e into a byte slice with uncompressed point prefix
func (e *G2) MarshalUncompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	ret := make([]byte, numBytes*4+1)
	ret[0] = 4
	e.fillBytes(ret[1:])
	return ret
}

// MarshalCompressed converts e into a byte slice with uncompressed point prefix
func (e *G2) MarshalCompressed() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	ret := make([]byte, numBytes*2+1)
	if e.p == nil {
		e.p = &twistPoint{}
	}
	e.p.MakeAffine()
	temp := &gfP{}
	montDecode(temp, &e.p.y.y)
	temp.Marshal(ret[1:])
	ret[0] = (ret[numBytes] & 1) | 2

	montDecode(temp, &e.p.x.x)
	temp.Marshal(ret[1:])
	montDecode(temp, &e.p.x.y)
	temp.Marshal(ret[numBytes+1:])

	return ret
}

// UnmarshalCompressed sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G2) UnmarshalCompressed(data []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	if len(data) < 1+2*numBytes {
		return nil, errors.New("sm9.G2: not enough data")
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, errors.New("sm9.G2: invalid point compress byte")
	}
	var err error
	// Unmarshal the points and check their caps
	if e.p == nil {
		e.p = &twistPoint{}
	}
	if err = e.p.x.x.Unmarshal(data[1:]); err != nil {
		return nil, err
	}
	if err = e.p.x.y.Unmarshal(data[1+numBytes:]); err != nil {
		return nil, err
	}
	montEncode(&e.p.x.x, &e.p.x.x)
	montEncode(&e.p.x.y, &e.p.x.y)
	x3 := e.p.polynomial(&e.p.x)
	e.p.y.Sqrt(x3)
	x3y := &gfP{}
	montDecode(x3y, &e.p.y.y)
	if byte(x3y[0]&1) != data[0]&1 {
		e.p.y.Neg(&e.p.y)
	}
	if e.p.x.IsZero() && e.p.y.IsZero() {
		// This is the point at infinity.
		e.p.y.SetOne()
		e.p.z.SetZero()
		e.p.t.SetZero()
	} else {
		e.p.z.SetOne()
		e.p.t.SetOne()

		if !e.p.IsOnCurve() {
			return nil, errors.New("sm9.G2: malformed point")
		}
	}
	return data[1+2*numBytes:], nil
}

func (e *G2) fillBytes(buffer []byte) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	if e.p == nil {
		e.p = &twistPoint{}
	}

	e.p.MakeAffine()
	if e.p.IsInfinity() {
		return
	}
	temp := &gfP{}

	montDecode(temp, &e.p.x.x)
	temp.Marshal(buffer)
	montDecode(temp, &e.p.x.y)
	temp.Marshal(buffer[numBytes:])
	montDecode(temp, &e.p.y.x)
	temp.Marshal(buffer[2*numBytes:])
	montDecode(temp, &e.p.y.y)
	temp.Marshal(buffer[3*numBytes:])
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *G2) Unmarshal(m []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8
	if len(m) < 4*numBytes {
		return nil, errors.New("sm9.G2: not enough data")
	}
	// Unmarshal the points and check their caps
	if e.p == nil {
		e.p = &twistPoint{}
	}
	var err error
	if err = e.p.x.x.Unmarshal(m); err != nil {
		return nil, err
	}
	if err = e.p.x.y.Unmarshal(m[numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.x.Unmarshal(m[2*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.y.Unmarshal(m[3*numBytes:]); err != nil {
		return nil, err
	}
	// Encode into Montgomery form and ensure it's on the curve
	montEncode(&e.p.x.x, &e.p.x.x)
	montEncode(&e.p.x.y, &e.p.x.y)
	montEncode(&e.p.y.x, &e.p.y.x)
	montEncode(&e.p.y.y, &e.p.y.y)

	if e.p.x.IsZero() && e.p.y.IsZero() {
		// This is the point at infinity.
		e.p.y.SetOne()
		e.p.z.SetZero()
		e.p.t.SetZero()
	} else {
		e.p.z.SetOne()
		e.p.t.SetOne()

		if !e.p.IsOnCurve() {
			return nil, errors.New("sm9.G2: malformed point")
		}
	}
	return m[4*numBytes:], nil
}
