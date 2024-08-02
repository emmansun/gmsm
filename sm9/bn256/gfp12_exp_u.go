package bn256

// Use special square
func (e *gfP12) Cyclo6PowToU(x *gfP12) *gfP12 {
	// The sequence of 10 multiplications and 61 squarings is derived from the
	// following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
	//
	//	_10    = 2*1
	//	_100   = 2*_10
	//	_101   = 1 + _100
	//	_1001  = _100 + _101
	//	_1011  = _10 + _1001
	//	_1100  = 1 + _1011
	//	i56    = (_1100 << 40 + _1011) << 7 + _1011 + _100
	//	i69    = (2*(i56 << 4 + _1001) + 1) << 6
	//	return   2*(_101 + i69)
	//
	var z = e
	var t0 = new(gfP12)
	var t1 = new(gfP12)
	var t2 = new(gfP12)
	var t3 = new(gfP12)

	t2.Cyclo6SquareNC(x)
	t1.Cyclo6SquareNC(t2)
	z.MulNC(x, t1)
	t0.MulNC(t1, z)
	t2.Mul(t2, t0)
	t3.MulNC(x, t2)
	t3.Cyclo6Squares(t3, 40)
	t3.Mul(t2, t3)
	t3.Cyclo6Squares(t3, 7)
	t2.Mul(t2, t3)
	t1.Mul(t1, t2)
	t1.Cyclo6Squares(t1, 4)
	t0.Mul(t0, t1)
	t0.Cyclo6Square(t0)
	t0.Mul(x, t0)
	t0.Cyclo6Squares(t0, 6)
	z.Mul(z, t0)
	z.Cyclo6Square(z)
	return e
}
