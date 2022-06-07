package sm9

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestSqrt(t *testing.T) {
	tests := []string{
		"9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596",
		"92fe90b700fbd4d8cc177d300ed16e4e15471a681b2c9e3728c1b82c885e49c2",
	}
	for i, test := range tests {
		y2 := bigFromHex(test)
		y21 := new(big.Int).ModSqrt(y2, p)

		y3 := new(big.Int).Mul(y21, y21)
		y3.Mod(y3, p)
		if y2.Cmp(y3) != 0 {
			t.Error("Invalid sqrt")
		}

		tmp := fromBigInt(y2)
		tmp.Sqrt(tmp)
		montDecode(tmp, tmp)
		var res [32]byte
		tmp.Marshal(res[:])
		if hex.EncodeToString(res[:]) != hex.EncodeToString(y21.Bytes()) {
			t.Errorf("case %v, got %v, expected %v\n", i, hex.EncodeToString(res[:]), hex.EncodeToString(y21.Bytes()))
		}
	}
}

func TestInvert(t *testing.T) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	xInv := &gfP{}
	xInv.Invert(x)
	y := &gfP{}
	gfpMul(y, x, xInv)
	if *y != *one {
		t.Errorf("got %v, expected %v", y, one)
	}
}

func TestDiv(t *testing.T) {
	x := fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	ret := &gfP{}
	ret.Div2(x)
	gfpAdd(ret, ret, ret)
	if *ret != *x {
		t.Errorf("got %v, expected %v", ret, x)
	}
}
