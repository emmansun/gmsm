package bn256

import "math/big"

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.
//

// gfP12 implements the field of size p¹² as a cubic extension of gfP4 where v³=u
type gfP12 struct {
	x, y, z gfP4 // value is xw² + yw + z
}

func gfP12Decode(in *gfP12) *gfP12 {
	out := &gfP12{}
	out.x = *gfP4Decode(&in.x)
	out.y = *gfP4Decode(&in.y)
	out.z = *gfP4Decode(&in.z)
	return out
}

var gfP12Gen *gfP12 = &gfP12{
	x: gfP4{
		x: gfP2{
			x: *newGFpFromBytes([]byte{0x25, 0x69, 0x43, 0xfb, 0xdb, 0x2b, 0xf8, 0x7a, 0xb9, 0x1a, 0xe7, 0xfb, 0xea, 0xff, 0x14, 0xe1, 0x46, 0xcf, 0x7e, 0x22, 0x79, 0xb9, 0xd1, 0x55, 0xd1, 0x34, 0x61, 0xe0, 0x9b, 0x22, 0xf5, 0x23}),
			y: *newGFpFromBytes([]byte{0x01, 0x67, 0xb0, 0x28, 0x00, 0x51, 0x49, 0x5c, 0x6a, 0xf1, 0xec, 0x23, 0xba, 0x2c, 0xd2, 0xff, 0x1c, 0xdc, 0xde, 0xca, 0x46, 0x1a, 0x5a, 0xb0, 0xb5, 0x44, 0x9e, 0x90, 0x91, 0x30, 0x83, 0x10}),
		},
		y: gfP2{
			x: *newGFpFromBytes([]byte{0x5e, 0x7a, 0xdd, 0xad, 0xdf, 0x7f, 0xbf, 0xe1, 0x62, 0x91, 0xb4, 0xe8, 0x9a, 0xf5, 0x0b, 0x82, 0x17, 0xdd, 0xc4, 0x7b, 0xa3, 0xcb, 0xa8, 0x33, 0xc6, 0xe7, 0x7c, 0x3f, 0xb0, 0x27, 0x68, 0x5e}),
			y: *newGFpFromBytes([]byte{0x79, 0xd0, 0xc8, 0x33, 0x70, 0x72, 0xc9, 0x3f, 0xef, 0x48, 0x2b, 0xb0, 0x55, 0xf4, 0x4d, 0x62, 0x47, 0xcc, 0xac, 0x8e, 0x8e, 0x12, 0x52, 0x58, 0x54, 0xb3, 0x56, 0x62, 0x36, 0x33, 0x7e, 0xbe}),
		},
	},
	y: gfP4{
		x: gfP2{
			x: *newGFpFromBytes([]byte{0x08, 0x2c, 0xde, 0x17, 0x30, 0x22, 0xda, 0x8c, 0xd0, 0x9b, 0x28, 0xa2, 0xd8, 0x0a, 0x8c, 0xee, 0x53, 0x89, 0x44, 0x36, 0xa5, 0x20, 0x07, 0xf9, 0x78, 0xdc, 0x37, 0xf3, 0x61, 0x16, 0xd3, 0x9b}),
			y: *newGFpFromBytes([]byte{0x3f, 0xa7, 0xed, 0x74, 0x1e, 0xae, 0xd9, 0x9a, 0x58, 0xf5, 0x3e, 0x3d, 0xf8, 0x2d, 0xf7, 0xcc, 0xd3, 0x40, 0x7b, 0xcc, 0x7b, 0x1d, 0x44, 0xa9, 0x44, 0x19, 0x20, 0xce, 0xd5, 0xfb, 0x82, 0x4f}),
		},
		y: gfP2{
			x: *newGFpFromBytes([]byte{0x7f, 0xc6, 0xeb, 0x2a, 0xa7, 0x71, 0xd9, 0x9c, 0x92, 0x34, 0xfd, 0xdd, 0x31, 0x75, 0x2e, 0xdf, 0xd6, 0x07, 0x23, 0xe0, 0x5a, 0x4e, 0xbf, 0xde, 0xb5, 0xc3, 0x3f, 0xbd, 0x47, 0xe0, 0xcf, 0x06}),
			y: *newGFpFromBytes([]byte{0x6f, 0xa6, 0xb6, 0xfa, 0x6d, 0xd6, 0xb6, 0xd3, 0xb1, 0x9a, 0x95, 0x9a, 0x11, 0x0e, 0x74, 0x81, 0x54, 0xee, 0xf7, 0x96, 0xdc, 0x0f, 0xc2, 0xdd, 0x76, 0x6e, 0xa4, 0x14, 0xde, 0x78, 0x69, 0x68}),
		},
	},
	z: gfP4{
		x: gfP2{
			x: *newGFpFromBytes([]byte{0x8f, 0xfe, 0x1c, 0x0e, 0x9d, 0xe4, 0x5f, 0xd0, 0xfe, 0xd7, 0x90, 0xac, 0x26, 0xbe, 0x91, 0xf6, 0xb3, 0xf0, 0xa4, 0x9c, 0x08, 0x4f, 0xe2, 0x9a, 0x3f, 0xb6, 0xed, 0x28, 0x8a, 0xd7, 0x99, 0x4d}),
			y: *newGFpFromBytes([]byte{0x16, 0x64, 0xa1, 0x36, 0x6b, 0xeb, 0x31, 0x96, 0xf0, 0x44, 0x3e, 0x15, 0xf5, 0xf9, 0x04, 0x2a, 0x94, 0x73, 0x54, 0xa5, 0x67, 0x84, 0x30, 0xd4, 0x5b, 0xa0, 0x31, 0xcf, 0xf0, 0x6d, 0xb9, 0x27}),
		},
		y: gfP2{
			x: *newGFpFromBytes([]byte{0x7f, 0x7c, 0x6d, 0x52, 0xb4, 0x75, 0xe6, 0xaa, 0xa8, 0x27, 0xfd, 0xc5, 0xb4, 0x17, 0x5a, 0xc6, 0x92, 0x93, 0x20, 0xf7, 0x82, 0xd9, 0x98, 0xf8, 0x6b, 0x6b, 0x57, 0xcd, 0xa4, 0x2a, 0x04, 0x26}),
			y: *newGFpFromBytes([]byte{0x36, 0xa6, 0x99, 0xde, 0x7c, 0x13, 0x6f, 0x78, 0xee, 0xe2, 0xdb, 0xac, 0x4c, 0xa9, 0x72, 0x7b, 0xff, 0x0c, 0xee, 0x02, 0xee, 0x92, 0x0f, 0x58, 0x22, 0xe6, 0x5e, 0xa1, 0x70, 0xaa, 0x96, 0x69}),
		},
	},
}

func (e *gfP12) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ", " + e.z.String() + ")"
}

func (e *gfP12) Set(a *gfP12) *gfP12 {
	gfp12Copy(e, a)
	return e
}

func (e *gfP12) SetZero() *gfP12 {
	e.x.SetZero()
	e.y.SetZero()
	e.z.SetZero()
	return e
}

func (e *gfP12) SetOne() *gfP12 {
	e.x.SetZero()
	e.y.SetZero()
	e.z.SetOne()
	return e
}

func (e *gfP12) SetW() *gfP12 {
	e.x.SetZero()
	e.y.SetOne()
	e.z.SetZero()
	return e
}

func (e *gfP12) SetW2() *gfP12 {
	e.x.SetOne()
	e.y.SetZero()
	e.z.SetZero()
	return e
}

func (e *gfP12) IsZero() bool {
	return e.x.IsZero() && e.y.IsZero() && e.z.IsZero()
}

func (e *gfP12) IsOne() bool {
	return e.x.IsZero() && e.y.IsZero() && e.z.IsOne()
}

func (e *gfP12) Add(a, b *gfP12) *gfP12 {
	e.x.Add(&a.x, &b.x)
	e.y.Add(&a.y, &b.y)
	e.z.Add(&a.z, &b.z)
	return e
}

func (e *gfP12) Sub(a, b *gfP12) *gfP12 {
	e.x.Sub(&a.x, &b.x)
	e.y.Sub(&a.y, &b.y)
	e.z.Sub(&a.z, &b.z)
	return e
}

func (e *gfP12) MulScalar(a *gfP12, b *gfP4) *gfP12 {
	e.x.Mul(&a.x, b)
	e.y.Mul(&a.y, b)
	e.z.Mul(&a.z, b)
	return e
}

func (e *gfP12) MulGFP2(a *gfP12, b *gfP2) *gfP12 {
	e.x.MulScalar(&a.x, b)
	e.y.MulScalar(&a.y, b)
	e.z.MulScalar(&a.z, b)
	return e
}

func (e *gfP12) MulGFP(a *gfP12, b *gfP) *gfP12 {
	e.x.MulGFP(&a.x, b)
	e.y.MulGFP(&a.y, b)
	e.z.MulGFP(&a.z, b)
	return e
}

func (e *gfP12) Mul(a, b *gfP12) *gfP12 {
	tmp := &gfP12{}
	tmp.MulNC(a, b)
	gfp12Copy(e, tmp)
	return e
}

// Mul without value copy, will use e directly, so e can't be same as a and b.
func (e *gfP12) MulNC(a, b *gfP12) *gfP12 {
	// (z0 + y0*w + x0*w^2)* (z1 + y1*w + x1*w^2)
	//  z0*z1 + z0*y1*w + z0*x1*w^2
	// +y0*z1*w + y0*y1*w^2 + y0*x1*v
	// +x0*z1*w^2 + x0*y1*v + x0*x1*v*w
	//=(z0*z1+y0*x1*v+x0*y1*v) + (z0*y1+y0*z1+x0*x1*v)w + (z0*x1 + y0*y1 + x0*z1)*w^2
	// Karatsuba method
	tx := &e.x
	ty := &e.y
	tz := &e.z
	t, v0, v1, v2 := &gfP4{}, &gfP4{}, &gfP4{}, &gfP4{}
	v0.MulNC(&a.z, &b.z)
	v1.MulNC(&a.y, &b.y)
	v2.MulNC(&a.x, &b.x)

	t.Add(&a.y, &a.x)
	tz.Add(&b.y, &b.x)
	t.Mul(t, tz)
	t.Sub(t, v1)
	t.Sub(t, v2)
	t.MulV1(t)
	tz.Add(t, v0)

	t.Add(&a.z, &a.y)
	ty.Add(&b.z, &b.y)
	ty.Mul(t, ty)
	ty.Sub(ty, v0)
	ty.Sub(ty, v1)
	t.MulV1(v2)
	ty.Add(ty, t)

	t.Add(&a.z, &a.x)
	tx.Add(&b.z, &b.x)
	tx.Mul(tx, t)
	tx.Sub(tx, v0)
	tx.Add(tx, v1)
	tx.Sub(tx, v2)
	return e
}

func (e *gfP12) Square(a *gfP12) *gfP12 {
	tmp := &gfP12{}
	tmp.SquareNC(a)
	gfp12Copy(e, tmp)
	return e
}

// Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP12) SquareNC(a *gfP12) *gfP12 {
	// (z + y*w + x*w^2)* (z + y*w + x*w^2)
	// z^2 + z*y*w + z*x*w^2 + y*z*w + y^2*w^2 + y*x*v + x*z*w^2 + x*y*v + x^2 *v *w
	// (z^2 + y*x*v + x*y*v) + (z*y + y*z + v * x^2)w + (z*x + y^2 + x*z)*w^2
	// (z^2 + 2*x*y*v) + (v*x^2 + 2*y*z) *w + (y^2 + 2*x*z) * w^2
	// Karatsuba method
	tx := &e.x
	ty := &e.y
	tz := &e.z
	t, v0, v1, v2 := &gfP4{}, &gfP4{}, &gfP4{}, &gfP4{}
	v0.SquareNC(&a.z)
	v1.SquareNC(&a.y)
	v2.SquareNC(&a.x)

	t.Add(&a.y, &a.x)
	tz.SquareNC(t)
	tz.Sub(tz, v1)
	tz.Sub(tz, v2)
	tz.MulV1(tz)
	tz.Add(tz, v0)

	t.Add(&a.z, &a.y)
	ty.SquareNC(t)
	ty.Sub(ty, v0)
	ty.Sub(ty, v1)
	t.MulV1(v2)
	ty.Add(ty, t)

	t.Add(&a.z, &a.x)
	tx.SquareNC(t)
	tx.Sub(tx, v0)
	tx.Add(tx, v1)
	tx.Sub(tx, v2)

	return e
}

// Cyclo6Square is used in final exponentiation after easy part(a ^ ((p^2 + 1)(p^6-1))).
// Note that after the easy part of the final exponentiation,
// the resulting element lies in cyclotomic subgroup.
// "New software speed records for cryptographic pairings"
// Section 3.3, Final exponentiation
// https://cryptojedi.org/papers/dclxvi-20100714.pdf
// The fomula reference:
// Granger/Scott (PKC2010).
// Section 3.2
// https://eprint.iacr.org/2009/565.pdf
func (e *gfP12) Cyclo6Square(a *gfP12) *gfP12 {
	tmp := &gfP12{}
	tmp.Cyclo6SquareNC(a)
	gfp12Copy(e, tmp)
	return e
}

// Special squaring loop for use on elements in T_6(fp2) (after the
// easy part of the final exponentiation. Used in the hard part
// of the final exponentiation. Function uses formulas in
// Granger/Scott (PKC2010).
func (e *gfP12) Cyclo6Squares(a *gfP12, n int) *gfP12 {
	// Square first round
	in := &gfP12{}
	tx, ty, tz := &gfP4{}, &gfP4{}, &gfP4{}

	v0 := &in.x
	v1 := &in.y
	v2 := &in.z

	v0.SquareVNC(&a.x) // (t02, t10)
	v1.SquareNC(&a.y)  // (t12, t01)
	v2.SquareNC(&a.z)  // (t11, t00)

	tx.Triple(v0)
	ty.Triple(v1)
	tz.Triple(v2)

	v0.Double(&a.x) // (f12, f01)
	v0.y.Neg(&v0.y)
	v1.Double(&a.y) // (f02, f10)
	v1.x.Neg(&v1.x)
	v2.Double(&a.z) // (f11, f00)
	v2.y.Neg(&v2.y)

	v0.Add(ty, v0)
	v1.Add(tx, v1)
	v2.Add(tz, v2)

	tmp := &gfP12{}
	var tmp2 *gfP12

	for i := 1; i < n; i++ {
		v0 = &tmp.x
		v1 = &tmp.y
		v2 = &tmp.z

		v0.SquareVNC(&in.x) // (t02, t10)
		v1.SquareNC(&in.y)  // (t12, t01)
		v2.SquareNC(&in.z)  // (t11, t00)

		tx.Triple(v0)
		ty.Triple(v1)
		tz.Triple(v2)

		v0.Double(&in.x) // (f12, f01)
		v0.y.Neg(&v0.y)
		v1.Double(&in.y) // (f02, f10)
		v1.x.Neg(&v1.x)
		v2.Double(&in.z) // (f11, f00)
		v2.y.Neg(&v2.y)

		v0.Add(ty, v0)
		v1.Add(tx, v1)
		v2.Add(tz, v2)

		// Switch references
		tmp2 = in
		in = tmp
		tmp = tmp2
	}
	gfp12Copy(e, in)
	return e
}

// Special Square without value copy, will use e directly, so e can't be same as a.
func (e *gfP12) Cyclo6SquareNC(a *gfP12) *gfP12 {
	tx, ty, tz := &gfP4{}, &gfP4{}, &gfP4{}

	v0 := &e.x
	v1 := &e.y
	v2 := &e.z

	v0.SquareVNC(&a.x) // (t02, t10)
	v1.SquareNC(&a.y)  // (t12, t01)
	v2.SquareNC(&a.z)  // (t11, t00)

	tx.Triple(v0)
	ty.Triple(v1)
	tz.Triple(v2)

	v0.Double(&a.x) // (f12, f01)
	v0.y.Neg(&v0.y)
	v1.Double(&a.y) // (f02, f10)
	v1.x.Neg(&v1.x)
	v2.Double(&a.z) // (f11, f00)
	v2.y.Neg(&v2.y)

	v0.Add(ty, v0)
	v1.Add(tx, v1)
	v2.Add(tz, v2)

	return e
}

func (e *gfP12) Squares(a *gfP12, n int) *gfP12 {
	// Square first round
	in := &gfP12{}
	tx := &in.x
	ty := &in.y
	tz := &in.z
	t, v0, v1, v2 := &gfP4{}, &gfP4{}, &gfP4{}, &gfP4{}

	v0.SquareNC(&a.z)
	v1.SquareNC(&a.y)
	v2.SquareNC(&a.x)

	t.Add(&a.y, &a.x)
	tz.SquareNC(t)
	tz.Sub(tz, v1)
	tz.Sub(tz, v2)
	tz.MulV1(tz)
	tz.Add(tz, v0)

	t.Add(&a.z, &a.y)
	ty.SquareNC(t)
	ty.Sub(ty, v0)
	ty.Sub(ty, v1)
	t.MulV1(v2)
	ty.Add(ty, t)

	t.Add(&a.z, &a.x)
	tx.SquareNC(t)
	tx.Sub(tx, v0)
	tx.Add(tx, v1)
	tx.Sub(tx, v2)

	tmp := &gfP12{}
	var tmp2 *gfP12

	for i := 1; i < n; i++ {
		tx = &tmp.x
		ty = &tmp.y
		tz = &tmp.z

		v0.SquareNC(&in.z)
		v1.SquareNC(&in.y)
		v2.SquareNC(&in.x)

		t.Add(&in.y, &in.x)
		tz.SquareNC(t)
		tz.Sub(tz, v1)
		tz.Sub(tz, v2)
		tz.MulV1(tz)
		tz.Add(tz, v0)

		t.Add(&in.z, &in.y)
		ty.SquareNC(t)
		ty.Sub(ty, v0)
		ty.Sub(ty, v1)
		t.MulV1(v2)
		ty.Add(ty, t)

		t.Add(&in.z, &in.x)
		tx.SquareNC(t)
		tx.Sub(tx, v0)
		tx.Add(tx, v1)
		tx.Sub(tx, v2)

		// Switch references
		tmp2 = in
		in = tmp
		tmp = tmp2
	}
	gfp12Copy(e, in)
	return e
}

func (e *gfP12) Exp(f *gfP12, power *big.Int) *gfP12 {
	sum := (&gfP12{}).SetOne()
	t := &gfP12{}

	for i := power.BitLen() - 1; i >= 0; i-- {
		t.Square(sum)
		if power.Bit(i) != 0 {
			sum.Mul(t, f)
		} else {
			sum.Set(t)
		}
	}
	gfp12Copy(e, sum)
	return e
}

func (e *gfP12) Invert(a *gfP12) *gfP12 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf

	// Here we can give a short explanation of how it works: let j be a cubic root of
	// unity in GF(p^4) so that 1+j+j²=0.
	// Then (xτ² + yτ + z)(xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
	// = (xτ² + yτ + z)(Cτ²+Bτ+A)
	// = (x³ξ²+y³ξ+z³-3ξxyz) = F is an element of the base field (the norm).
	//
	// On the other hand (xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
	// = τ²(y²-ξxz) + τ(ξx²-yz) + (z²-ξxy)
	//
	// So that's why A = (z²-ξxy), B = (ξx²-yz), C = (y²-ξxz)
	t1 := (&gfP4{}).MulVNC(&a.x, &a.y)
	A := (&gfP4{}).SquareNC(&a.z)
	A.Sub(A, t1)

	B := (&gfP4{}).SquareVNC(&a.x)
	t1.Mul(&a.y, &a.z)
	B.Sub(B, t1)

	C := (&gfP4{}).SquareNC(&a.y)
	t1.Mul(&a.x, &a.z)
	C.Sub(C, t1)

	F := (&gfP4{}).MulVNC(C, &a.y)
	t1.Mul(A, &a.z)
	F.Add(F, t1)
	t1.MulV(B, &a.x)
	F.Add(F, t1)

	F.Invert(F)

	e.x.Mul(C, F)
	e.y.Mul(B, F)
	e.z.Mul(A, F)
	return e
}

func (e *gfP12) Neg(a *gfP12) *gfP12 {
	e.x.Neg(&a.x)
	e.y.Neg(&a.y)
	e.z.Neg(&a.z)
	return e
}

// (z + y*w + x*w^2)^p
// = z^p + y^p*w*w^(p-1)+x^p*w^2*(w^2)^(p-1)
// w2ToP2Minus1 = vToPMinus1 * wToPMinus1
func (e *gfP12) Frobenius(a *gfP12) *gfP12 {
	tmp := &gfP4{}
	x := &tmp.x
	y := &tmp.y

	x.Conjugate(&a.z.x)
	y.Conjugate(&a.z.y)
	x.MulScalar(x, vToPMinus1)
	gfp4Copy(&e.z, tmp)

	x.Conjugate(&a.y.x)
	y.Conjugate(&a.y.y)
	x.MulScalar(x, w2ToP2Minus1)
	y.MulScalar(y, wToPMinus1)
	gfp4Copy(&e.y, tmp)

	x.Conjugate(&a.x.x)
	y.Conjugate(&a.x.y)
	x.MulScalar(x, vToPMinus1Mw2ToPMinus1)
	y.MulScalar(y, w2ToPMinus1)
	gfp4Copy(&e.x, tmp)

	return e
}

// (z + y*w + x*w^2)^(p^2)
// = z^(p^2) + y^(p^2)*w*w^((p^2)-1)+x^(p^2)*w^2*(w^2)^((p^2)-1)
func (e *gfP12) FrobeniusP2(a *gfP12) *gfP12 {
	tx := &e.x
	ty := &e.y
	tz := &e.z

	tz.Conjugate(&a.z)

	ty.Conjugate(&a.y)
	ty.MulGFP(ty, wToP2Minus1)

	tx.Conjugate(&a.x)
	tx.MulGFP(tx, w2ToP2Minus1)
	return e
}

// (z + y*w + x*w^2)^(p^3)
// =z^(p^3) + y^(p^3)*w*w^((p^3)-1)+x^(p^3)*w^2*(w^2)^((p^3)-1)
// =z^(p^3) + y^(p^3)*w*vToPMinus1-x^(p^3)*w^2
// vToPMinus1 * vToPMinus1 = -1
func (e *gfP12) FrobeniusP3(a *gfP12) *gfP12 {
	x, y := &gfP2{}, &gfP2{}

	x.Conjugate(&a.z.x)
	y.Conjugate(&a.z.y)
	x.MulScalar(x, vToPMinus1)
	x.Neg(x)
	e.z.x.Set(x)
	e.z.y.Set(y)

	x.Conjugate(&a.y.x)
	y.Conjugate(&a.y.y)
	//x.MulScalar(x, vToPMinus1)
	//x.Neg(x)
	//x.MulScalar(x, vToPMinus1)
	y.MulScalar(y, vToPMinus1)
	e.y.x.Set(x)
	e.y.y.Set(y)

	x.Conjugate(&a.x.x)
	y.Conjugate(&a.x.y)
	x.MulScalar(x, vToPMinus1)
	y.Neg(y)
	e.x.x.Set(x)
	e.x.y.Set(y)

	return e
}

// (z + y*w + x*w^2)^(p^6)
// = ((z + y*w + x*w^2)^(p^3))^(p^3)
func (e *gfP12) FrobeniusP6(a *gfP12) *gfP12 {
	tx := &e.x
	ty := &e.y
	tz := &e.z

	tz.Conjugate(&a.z)

	ty.Conjugate(&a.y)
	ty.Neg(ty)

	tx.Conjugate(&a.x)

	return e
}

// code logic from https://github.com/miracl/MIRACL/blob/master/source/curve/pairing/zzn12a.h
func (e *gfP12) Conjugate(a *gfP12) *gfP12 {
	e.z.Conjugate(&a.z)
	e.y.Conjugate(&a.y)
	e.y.Neg(&e.y)
	e.x.Conjugate(&a.x)
	return e
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *gfP12) Select(p1, p2 *gfP12, cond int) *gfP12 {
	q.x.Select(&p1.x, &p2.x, cond)
	q.y.Select(&p1.y, &p2.y, cond)
	q.z.Select(&p1.z, &p2.z, cond)
	return q
}
