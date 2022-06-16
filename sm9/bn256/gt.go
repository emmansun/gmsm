package bn256

import (
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

// GT is an abstract cyclic group. The zero value is suitable for use as the
// output of an operation, but cannot be used as an input.
type GT struct {
	p *gfP12
}

// RandomGT returns x and e(g₁, g₂)ˣ where x is a random, non-zero number read
// from r.
func RandomGT(r io.Reader) (*big.Int, *GT, error) {
	k, err := randomK(r)
	if err != nil {
		return nil, nil, err
	}

	return k, new(GT).ScalarBaseMult(k), nil
}

// Pair calculates an R-Ate pairing.
func Pair(g1 *G1, g2 *G2) *GT {
	return &GT{pairing(g2.p, g1.p)}
}

// Miller applies Miller's algorithm, which is a bilinear function from the
// source groups to F_p^12. Miller(g1, g2).Finalize() is equivalent to Pair(g1,
// g2).
func Miller(g1 *G1, g2 *G2) *GT {
	return &GT{miller(g2.p, g1.p)}
}

func (g *GT) String() string {
	return "sm9.GT" + g.p.String()
}

// ScalarBaseMult sets e to g*k where g is the generator of the group and then
// returns out.
func (e *GT) ScalarBaseMult(k *big.Int) *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.Exp(gfP12Gen, k)
	return e
}

// ScalarMult sets e to a*k and then returns e.
func (e *GT) ScalarMult(a *GT, k *big.Int) *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.Exp(a.p, k)
	return e
}

// Add sets e to a+b and then returns e.
func (e *GT) Add(a, b *GT) *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.Mul(a.p, b.p)
	return e
}

// Neg sets e to -a and then returns e.
func (e *GT) Neg(a *GT) *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.Neg(a.p) // TODO: fix it.
	return e
}

// Set sets e to a and then returns e.
func (e *GT) Set(a *GT) *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.Set(a.p)
	return e
}

// Set sets e to one and then returns e.
func (e *GT) SetOne() *GT {
	if e.p == nil {
		e.p = &gfP12{}
	}
	e.p.SetOne()
	return e
}

// Finalize is a linear function from F_p^12 to GT.
func (e *GT) Finalize() *GT {
	ret := finalExponentiation(e.p)
	e.p.Set(ret)
	return e
}

// Marshal converts e into a byte slice.
func (e *GT) Marshal() []byte {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	ret := make([]byte, numBytes*12)
	temp := &gfP{}

	montDecode(temp, &e.p.x.x.x)
	temp.Marshal(ret)
	montDecode(temp, &e.p.x.x.y)
	temp.Marshal(ret[numBytes:])
	montDecode(temp, &e.p.x.y.x)
	temp.Marshal(ret[2*numBytes:])
	montDecode(temp, &e.p.x.y.y)
	temp.Marshal(ret[3*numBytes:])

	montDecode(temp, &e.p.y.x.x)
	temp.Marshal(ret[4*numBytes:])
	montDecode(temp, &e.p.y.x.y)
	temp.Marshal(ret[5*numBytes:])
	montDecode(temp, &e.p.y.y.x)
	temp.Marshal(ret[6*numBytes:])
	montDecode(temp, &e.p.y.y.y)
	temp.Marshal(ret[7*numBytes:])

	montDecode(temp, &e.p.z.x.x)
	temp.Marshal(ret[8*numBytes:])
	montDecode(temp, &e.p.z.x.y)
	temp.Marshal(ret[9*numBytes:])
	montDecode(temp, &e.p.z.y.x)
	temp.Marshal(ret[10*numBytes:])
	montDecode(temp, &e.p.z.y.y)
	temp.Marshal(ret[11*numBytes:])

	return ret
}

// Unmarshal sets e to the result of converting the output of Marshal back into
// a group element and then returns e.
func (e *GT) Unmarshal(m []byte) ([]byte, error) {
	// Each value is a 256-bit number.
	const numBytes = 256 / 8

	if len(m) < 12*numBytes {
		return nil, errors.New("sm9.GT: not enough data")
	}

	if e.p == nil {
		e.p = &gfP12{}
	}

	var err error
	if err = e.p.x.x.x.Unmarshal(m); err != nil {
		return nil, err
	}
	if err = e.p.x.x.y.Unmarshal(m[numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.x.y.x.Unmarshal(m[2*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.x.y.y.Unmarshal(m[3*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.x.x.Unmarshal(m[4*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.x.y.Unmarshal(m[5*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.y.x.Unmarshal(m[6*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.y.y.y.Unmarshal(m[7*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.z.x.x.Unmarshal(m[8*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.z.x.y.Unmarshal(m[9*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.z.y.x.Unmarshal(m[10*numBytes:]); err != nil {
		return nil, err
	}
	if err = e.p.z.y.y.Unmarshal(m[11*numBytes:]); err != nil {
		return nil, err
	}

	montEncode(&e.p.x.x.x, &e.p.x.x.x)
	montEncode(&e.p.x.x.y, &e.p.x.x.y)
	montEncode(&e.p.x.y.x, &e.p.x.y.x)
	montEncode(&e.p.x.y.y, &e.p.x.y.y)
	montEncode(&e.p.y.x.x, &e.p.y.x.x)
	montEncode(&e.p.y.x.y, &e.p.y.x.y)
	montEncode(&e.p.y.y.x, &e.p.y.y.x)
	montEncode(&e.p.y.y.y, &e.p.y.y.y)
	montEncode(&e.p.z.x.x, &e.p.z.x.x)
	montEncode(&e.p.z.x.y, &e.p.z.x.y)
	montEncode(&e.p.z.y.x, &e.p.z.y.x)
	montEncode(&e.p.z.y.y, &e.p.z.y.y)

	return m[12*numBytes:], nil
}

// A GTFieldTable holds the first 15 Exp of a value at offset -1, so P
// is at table[0], P^15 is at table[14], and P^0 is implicitly the identity
// point.
type GTFieldTable [15]*GT

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *GTFieldTable) Select(p *GT, n uint8) {
	if n >= 16 {
		panic("sm9: internal error: GTFieldTable called with out-of-bounds value")
	}
	p.p.SetOne()
	for i := uint8(1); i < 16; i++ {
		cond := subtle.ConstantTimeByteEq(i, n)
		p.p.Select(table[i-1].p, p.p, cond)
	}
}

func GenerateGTFieldTable(basePoint *GT) *[32 * 2]GTFieldTable {
	table := new([32 * 2]GTFieldTable)
	base := &GT{}
	base.Set(basePoint)
	for i := 0; i < 32*2; i++ {
		table[i][0] = &GT{}
		table[i][0].Set(base)
		for j := 1; j < 15; j += 2 {
			table[i][j] = &GT{}
			table[i][j].p = &gfP12{}
			table[i][j].p.Square(table[i][j/2].p)
			table[i][j+1] = &GT{}
			table[i][j+1].p = &gfP12{}
			table[i][j+1].Add(table[i][j], base)
		}
		base.p.Square(base.p)
		base.p.Square(base.p)
		base.p.Square(base.p)
		base.p.Square(base.p)
	}
	return table
}

// ScalarBaseMultGT compute basepoint^r with precomputed table
func ScalarBaseMultGT(tables *[32 * 2]GTFieldTable, r *big.Int) *GT {
	scalar := normalizeScalar(r.Bytes())
	// This is also a scalar multiplication with a four-bit window like in
	// ScalarMult, but in this case the doublings are precomputed. The value
	// [windowValue]G added at iteration k would normally get doubled
	// (totIterations-k)×4 times, but with a larger precomputation we can
	// instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
	// doublings between iterations.
	e, t := &GT{}, &GT{}
	tableIndex := len(tables) - 1
	e.SetOne()
	t.SetOne()
	for _, byte := range scalar {
		windowValue := byte >> 4
		tables[tableIndex].Select(t, windowValue)
		e.Add(e, t)
		tableIndex--
		windowValue = byte & 0b1111
		tables[tableIndex].Select(t, windowValue)
		e.Add(e, t)
		tableIndex--
	}
	return e
}
