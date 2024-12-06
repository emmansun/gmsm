package bigmod

func (x *Nat) Set(y *Nat) *Nat {
	return x.set(y)
}

// SetOverflowedBytes assigns x = (b mode (m-1)) + 1, where b is a slice of big-endian bytes.
//
// The output will be resized to the size of m and overwritten.
//
//go:norace
func (x *Nat) SetOverflowedBytes(b []byte, m *Modulus) *Nat {
	mMinusOne := NewNat().set(m.nat)
	mMinusOne.limbs[0]-- // due to m is odd, so we can safely subtract 1
	mMinusOneM, _ := NewModulus(mMinusOne.Bytes(m))
	one := NewNat().resetFor(m)
	one.limbs[0] = 1
	x.resetToBytes(b)
	x = NewNat().Mod(x, mMinusOneM) // x = x mod (m-1)
	x.add(one)                      // we can safely add 1, no need to check overflow
	return x
}

// CmpGeq returns 1 if x >= y, and 0 otherwise.
//
// Both operands must have the same announced length.
//
//go:norace
func (x *Nat) CmpGeq(y *Nat) choice {
	return x.cmpGeq(y)
}
