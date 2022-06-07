package sm9

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"math/bits"
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

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns e.
func (e *G1) ScalarBaseMult(k *big.Int) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Mul(curveGen, k)
	return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *G1) ScalarMult(a *G1, k *big.Int) *G1 {
	if e.p == nil {
		e.p = &curvePoint{}
	}
	e.p.Mul(a.p, k)
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

	if e.p == nil {
		e.p = &curvePoint{}
	}

	e.p.MakeAffine()
	ret := make([]byte, numBytes*2)
	if e.p.IsInfinity() {
		return ret
	}
	temp := &gfP{}

	montDecode(temp, &e.p.x)
	temp.Marshal(ret)
	montDecode(temp, &e.p.y)
	temp.Marshal(ret[numBytes:])

	return ret
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

	zero := gfP{0}
	if e.p.x == zero && e.p.y == zero {
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
