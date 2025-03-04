package subtle

import (
	"math/bits"

	"github.com/emmansun/gmsm/internal/byteorder"
)

func ConstantTimeAllZero(bytes []byte) int {
	var b uint8
	for _, v := range bytes {
		b |= v
	}
	return int((uint32(b) - 1) >> 31)
}

// ConstantTimeLessOrEqBytes returns 1 if x <= y and 0 otherwise. The comparison
// is lexigraphical, or big-endian. The time taken is a function of the length of
// the slices and is independent of the contents. If the lengths of x and y do not
// match it returns 0 immediately.
func ConstantTimeLessOrEqBytes(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}

	// Do a constant time subtraction chain y - x.
	// If there is no borrow at the end, then x <= y.
	var b uint64
	for len(x) > 8 {
		x0 := byteorder.BEUint64(x[len(x)-8:])
		y0 := byteorder.BEUint64(y[len(y)-8:])
		_, b = bits.Sub64(y0, x0, b)
		x = x[:len(x)-8]
		y = y[:len(y)-8]
	}
	if len(x) > 0 {
		xb := make([]byte, 8)
		yb := make([]byte, 8)
		copy(xb[8-len(x):], x)
		copy(yb[8-len(y):], y)
		x0 := byteorder.BEUint64(xb)
		y0 := byteorder.BEUint64(yb)
		_, b = bits.Sub64(y0, x0, b)
	}
	return int(b ^ 1)
}
