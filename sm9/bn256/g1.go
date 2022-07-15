package bn256

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"math/bits"
	"sync"
)

func randomK(r io.Reader) (k *big.Int, err error) {
	for {
		k, err = rand.Int(r, Order)
		if k.Sign() > 0 || err != nil {
			return
		}
	}
}

// G1 is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type G1 struct {
	p *curvePoint
}

//Gen1 is the generator of G1.
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
			for j := 1; j < 15; j += 2 {
				g1GeneratorTable[i][j] = &curvePoint{}
				g1GeneratorTable[i][j].Double(g1GeneratorTable[i][j/2])
				g1GeneratorTable[i][j+1] = &curvePoint{}
				g1GeneratorTable[i][j+1].Add(g1GeneratorTable[i][j], base)
			}
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

	return k, new(G1).ScalarBaseMult(k), nil
}

func (g *G1) String() string {
	return "sm9.G1" + g.p.String()
}

func normalizeScalar(scalar []byte) []byte {
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

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns e.
func (e *G1) ScalarBaseMult(k *big.Int) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}

	//e.p.Mul(curveGen, k)

	scalar := normalizeScalar(k.Bytes())
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
	return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *G1) ScalarMult(a *G1, k *big.Int) *G1 {
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
	scalarBytes := normalizeScalar(k.Bytes())
	for i, byte := range scalarBytes {
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
	return e
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
		e.p.x, e.p.y = gfP{0}, gfP{0}
	}
	e.p.x.Unmarshal(data[1:])
	montEncode(&e.p.x, &e.p.x)
	x3 := e.p.polynomial(&e.p.x)
	e.p.y.Sqrt(x3)
	montDecode(x3, &e.p.y)
	if byte(x3[0]&1) != data[0]&1 {
		gfpNeg(&e.p.y, &e.p.y)
	}
	if e.p.x == *zero && e.p.y == *zero {
		// This is the point at infinity.
		e.p.y = *newGFp(1)
		e.p.z = gfP{0}
		e.p.t = gfP{0}
	} else {
		e.p.z = *newGFp(1)
		e.p.t = *newGFp(1)

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
		e.p.x, e.p.y = gfP{0}, gfP{0}
	}

	e.p.x.Unmarshal(m)
	e.p.y.Unmarshal(m[numBytes:])
	montEncode(&e.p.x, &e.p.x)
	montEncode(&e.p.y, &e.p.y)

	if e.p.x == *zero && e.p.y == *zero {
		// This is the point at infinity.
		e.p.y = *newGFp(1)
		e.p.z = gfP{0}
		e.p.t = gfP{0}
	} else {
		e.p.z = *newGFp(1)
		e.p.t = *newGFp(1)

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
	return e.p.x == other.p.x &&
		e.p.y == other.p.y &&
		e.p.z == other.p.z &&
		e.p.t == other.p.t
}

// IsOnCurve returns true if e is on the curve.
func (e *G1) IsOnCurve() bool {
	return e.p.IsOnCurve()
}

type G1Curve struct {
	params *CurveParams
	g      G1
}

var g1Curve = &G1Curve{
	params: &CurveParams{
		Name:    "sm9",
		BitSize: 256,
		P:       bigFromHex("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D"),
		N:       bigFromHex("B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"),
		B:       bigFromHex("0000000000000000000000000000000000000000000000000000000000000005"),
		Gx:      bigFromHex("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD"),
		Gy:      bigFromHex("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616"),
	},
	g: G1{},
}

func (g1 *G1Curve) pointFromAffine(x, y *big.Int) (a *G1, err error) {
	a = &G1{&curvePoint{}}
	if x.Sign() == 0 {
		a.p.SetInfinity()
		return a, nil
	}
	// Reject values that would not get correctly encoded.
	if x.Sign() < 0 || y.Sign() < 0 {
		return a, errors.New("negative coordinate")
	}
	if x.BitLen() > g1.params.BitSize || y.BitLen() > g1.params.BitSize {
		return a, errors.New("overflowing coordinate")
	}
	a.p.x = *fromBigInt(x)
	a.p.y = *fromBigInt(y)
	a.p.z = *newGFp(1)
	a.p.t = *newGFp(1)

	if !a.p.IsOnCurve() {
		return a, errors.New("point not on G1 curve")
	}

	return a, nil
}

func (g1 *G1Curve) Params() *CurveParams {
	return g1.params
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the nistec scalar multiplication functions.
func (curve *G1Curve) normalizeScalar(scalar []byte) *big.Int {
	byteSize := (curve.params.N.BitLen() + 7) / 8
	s := new(big.Int).SetBytes(scalar)
	if len(scalar) > byteSize {
		s.Mod(s, curve.params.N)
	}
	return s
}

func (g1 *G1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	scalar := g1.normalizeScalar(k)
	res := g1.g.ScalarBaseMult(scalar).Marshal()
	return new(big.Int).SetBytes(res[:32]), new(big.Int).SetBytes(res[32:])
}

func (g1 *G1Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	a, err := g1.pointFromAffine(Bx, By)
	if err != nil {
		panic("sm9: ScalarMult was called on an invalid point")
	}
	res := g1.g.ScalarMult(a, new(big.Int).SetBytes(k)).Marshal()
	return new(big.Int).SetBytes(res[:32]), new(big.Int).SetBytes(res[32:])
}

func (g1 *G1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	a, err := g1.pointFromAffine(x1, y1)
	if err != nil {
		panic("sm9: Add was called on an invalid point")
	}
	b, err := g1.pointFromAffine(x2, y2)
	if err != nil {
		panic("sm9: Add was called on an invalid point")
	}
	res := g1.g.Add(a, b).Marshal()
	return new(big.Int).SetBytes(res[:32]), new(big.Int).SetBytes(res[32:])
}

func (g1 *G1Curve) Double(x, y *big.Int) (*big.Int, *big.Int) {
	a, err := g1.pointFromAffine(x, y)
	if err != nil {
		panic("sm9: Double was called on an invalid point")
	}
	res := g1.g.Double(a).Marshal()
	return new(big.Int).SetBytes(res[:32]), new(big.Int).SetBytes(res[32:])
}

func (g1 *G1Curve) IsOnCurve(x, y *big.Int) bool {
	_, err := g1.pointFromAffine(x, y)
	return err == nil
}

func lessThanP(x *gfP) int {
	var b uint64
	_, b = bits.Sub64(x[0], p2[0], b)
	_, b = bits.Sub64(x[1], p2[1], b)
	_, b = bits.Sub64(x[2], p2[2], b)
	_, b = bits.Sub64(x[3], p2[3], b)
	return int(b)
}

func (curve *G1Curve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	if len(data) != 33 || (data[0] != 2 && data[0] != 3) {
		return nil, nil
	}
	r := &gfP{}
	r.Unmarshal(data[1:33])
	if lessThanP(r) == 0 {
		return nil, nil
	}
	x = new(big.Int).SetBytes(data[1:33])
	p := &curvePoint{}
	montEncode(r, r)
	p.x = *r
	p.z = *newGFp(1)
	p.t = *newGFp(1)
	y2 := &gfP{}
	gfpMul(y2, r, r)
	gfpMul(y2, y2, r)
	gfpAdd(y2, y2, curveB)
	y2.Sqrt(y2)
	p.y = *y2
	if !p.IsOnCurve() {
		return nil, nil
	}
	montDecode(y2, y2)
	ret := make([]byte, 32)
	y2.Marshal(ret)
	y = new(big.Int).SetBytes(ret)
	if byte(y.Bit(0)) != data[0]&1 {
		gfpNeg(y2, y2)
		y2.Marshal(ret)
		y.SetBytes(ret)
	}
	return x, y
}

func (curve *G1Curve) Unmarshal(data []byte) (x, y *big.Int) {
	if len(data) != 65 || (data[0] != 4) {
		return nil, nil
	}
	x1 := &gfP{}
	x1.Unmarshal(data[1:33])
	y1 := &gfP{}
	y1.Unmarshal(data[33:])
	if lessThanP(x1) == 0 || lessThanP(y1) == 0 {
		return nil, nil
	}
	montEncode(x1, x1)
	montEncode(y1, y1)
	p := &curvePoint{
		x: *x1,
		y: *y1,
		z: *newGFp(1),
		t: *newGFp(1),
	}
	if !p.IsOnCurve() {
		return nil, nil
	}
	x = new(big.Int).SetBytes(data[1:33])
	y = new(big.Int).SetBytes(data[33:])
	return x, y
}
