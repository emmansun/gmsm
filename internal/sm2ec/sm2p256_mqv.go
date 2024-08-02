package sm2ec

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

var p256Order = [4]uint64{0x53bbf40939d54123, 0x7203df6b21c6052b,
	0xffffffffffffffff, 0xfffffffeffffffff}

func fromBytes(bytes []byte) (*[4]uint64, error) {
	if len(bytes) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	var t [4]uint64
	t[0] = binary.BigEndian.Uint64(bytes[24:])
	t[1] = binary.BigEndian.Uint64(bytes[16:])
	t[2] = binary.BigEndian.Uint64(bytes[8:])
	t[3] = binary.BigEndian.Uint64(bytes)
	return &t, nil
}

func toBytes(t *[4]uint64) []byte {
	var bytes [32]byte

	binary.BigEndian.PutUint64(bytes[:], t[3])
	binary.BigEndian.PutUint64(bytes[8:], t[2])
	binary.BigEndian.PutUint64(bytes[16:], t[1])
	binary.BigEndian.PutUint64(bytes[24:], t[0])

	return bytes[:]
}

// p256OrdAdd sets res = x + y.
func p256OrdAdd(res, x, y *[4]uint64) {
	var c, b uint64
	t1 := make([]uint64, 4)
	t1[0], c = bits.Add64(x[0], y[0], 0)
	t1[1], c = bits.Add64(x[1], y[1], c)
	t1[2], c = bits.Add64(x[2], y[2], c)
	t1[3], c = bits.Add64(x[3], y[3], c)
	t2 := make([]uint64, 4)
	t2[0], b = bits.Sub64(t1[0], p256Order[0], 0)
	t2[1], b = bits.Sub64(t1[1], p256Order[1], b)
	t2[2], b = bits.Sub64(t1[2], p256Order[2], b)
	t2[3], b = bits.Sub64(t1[3], p256Order[3], b)
	// Three options:
	//   - a+b < p
	//     then c is 0, b is 1, and t1 is correct
	//   - p <= a+b < 2^256
	//     then c is 0, b is 0, and t2 is correct
	//   - 2^256 <= a+b
	//     then c is 1, b is 1, and t2 is correct
	t2Mask := (c ^ b) - 1
	res[0] = (t1[0] & ^t2Mask) | (t2[0] & t2Mask)
	res[1] = (t1[1] & ^t2Mask) | (t2[1] & t2Mask)
	res[2] = (t1[2] & ^t2Mask) | (t2[2] & t2Mask)
	res[3] = (t1[3] & ^t2Mask) | (t2[3] & t2Mask)
}

func ImplicitSig(sPriv, ePriv, t []byte) ([]byte, error) {
	mulRes, err := P256OrdMul(ePriv, t)
	if err != nil {
		return nil, err
	}
	t1, err := fromBytes(mulRes)
	if err != nil {
		return nil, err
	}
	t2, err := fromBytes(sPriv)
	if err != nil {
		return nil, err
	}
	var t3 [4]uint64
	p256OrdAdd(&t3, t1, t2)
	return toBytes(&t3), nil
}
