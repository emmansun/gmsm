package bn256

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func Test_gfpBasicOperations(t *testing.T) {
	x := &gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}            // fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141"))
	y := &gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}            //fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B"))
	expectedAdd := &gfP{0x1c004000d0e23db8, 0xe1b8e46e129dc2c4, 0x3b65d4624433aa40, 0x3c0e030b72035817}  // fromBigInt(bigFromHex("0691692307d370af56226e57920199fbbe10f216c67fbc9468c7f225a4b1f21f"))
	expectedSub := &gfP{0x30040d4c48e37766, 0x1c11e44fa54fbe12, 0xb68524a31e5efe48, 0x87ebdd26068c318c}  // fromBigInt(bigFromHex("67b381821c52a5624f3304a8149be8461e3bc07adcb872c38aa65051ba53ba97"))
	expectedNeg := &gfP{0xbf6d7481566e6aee, 0xa30d2eec3e842e70, 0xdd0e2ecd44457300, 0x54430fe7465be21f}  // fromBigInt(bigFromHex("7f1d8aad70909be90358f1d02240062433cc3a0248ded72febb879ec33ce6f22"))
	expectedMul := &gfP{0x3f6d0af5b236a05a, 0xd5dc6968e27dd5aa, 0x6f26d5050cf628c2, 0x78ef5c13f390787a}  // fromBigInt(bigFromHex("3d08bbad376584e4f74bd31f78f716372b96ba8c3f939c12b8d54e79b6489e76"))
	expectedMul2 := &gfP{0x3476b30ae9e54c3e, 0xb89d3d169a2b89d4, 0x5d2367ce84f5f23f, 0xb2b54255b1ef0de7} // fromBigInt(bigFromHex("1df94a9e05a559ff38e0ab50cece734dc058d33738ceacaa15986a67cbff1ef6"))

	ret := &gfP{}
	gfpAdd(ret, x, y)
	if *expectedAdd != *ret {
		t.Errorf("add not same")
	}

	gfpSub(ret, y, x)
	if *expectedSub != *ret {
		t.Errorf("sub not same")
	}

	gfpNeg(ret, y)
	if *expectedNeg != *ret {
		t.Errorf("neg not same")
	}

	gfpMul(ret, x, y)
	if *expectedMul != *ret {
		t.Errorf("mul not same")
	}

	gfpMul(ret, ret, ret)
	if *expectedMul2 != *ret {
		t.Errorf("mul not same")
	}
}

func TestGfpExp(t *testing.T) {
	xI := bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596")
	x := &gfP{0x67e1fd5b565a37fe, 0x1b83b61e447de56b, 0x33e6382d2221ea68, 0x6b1de80671f699df} // fromBigInt(xI)
	ret, ret3 := &gfP{}, &gfP{}
	ret.exp(x, pMinus2)

	gfpMul(ret3, x, ret)
	if *ret3 != *one {
		t.Errorf("got %v, expected %v\n", ret3, one)
	}
	montDecode(ret, ret)

	ret2 := new(big.Int).Exp(xI, bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b"), p)
	if hex.EncodeToString(ret2.Bytes()) != ret.String() {
		t.Errorf("exp not same, got %v, expected %v\n", ret, hex.EncodeToString(ret2.Bytes()))
	}

	xInv := new(big.Int).ModInverse(xI, p)
	if hex.EncodeToString(ret2.Bytes()) != hex.EncodeToString(xInv.Bytes()) {
		t.Errorf("exp not same, got %v, expected %v\n", hex.EncodeToString(ret2.Bytes()), hex.EncodeToString(xInv.Bytes()))
	}

	x2 := new(big.Int).Mul(xI, xInv)
	x2.Mod(x2, p)
	if big.NewInt(1).Cmp(x2) != 0 {
		t.Errorf("not same")
	}

	xInvGfp := &gfP{0xab54a05bc4f2fbc4, 0x73d5963d5b0e76c9, 0x54e21ef03bd244e4, 0x83f86b9abc249e79} // fromBigInt(xInv)
	gfpMul(ret, x, xInvGfp)
	if *ret != *one {
		t.Errorf("got %v, expected %v", ret, one)
	}
}

func TestSqrt(t *testing.T) {
	tests := []struct {
		str   string
		value *gfP
	}{
		{
			"9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596",
			&gfP{0x67e1fd5b565a37fe, 0x1b83b61e447de56b, 0x33e6382d2221ea68, 0x6b1de80671f699df},
		},
		{
			"92fe90b700fbd4d8cc177d300ed16e4e15471a681b2c9e3728c1b82c885e49c2",
			&gfP{0xdf2483b8b579bc7, 0xfc281ec2f67e3619, 0x92b36844a274a4c0, 0x1325a3aa5fc9d5a4},
		},
	}
	for i, test := range tests {
		y2 := bigFromHex(test.str)
		y21 := new(big.Int).ModSqrt(y2, p)

		y3 := new(big.Int).Mul(y21, y21)
		y3.Mod(y3, p)
		if y2.Cmp(y3) != 0 {
			t.Error("Invalid sqrt")
		}

		tmp := test.value
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
	x := &gfP{0x67e1fd5b565a37fe, 0x1b83b61e447de56b, 0x33e6382d2221ea68, 0x6b1de80671f699df} // fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	xInv := &gfP{}
	xInv.Invert(x)
	y := &gfP{}
	gfpMul(y, x, xInv)
	if *y != *one {
		t.Errorf("got %v, expected %v", y, one)
	}
}

func TestDiv(t *testing.T) {
	x := &gfP{0x67e1fd5b565a37fe, 0x1b83b61e447de56b, 0x33e6382d2221ea68, 0x6b1de80671f699df} // fromBigInt(bigFromHex("9093a2b979e6186f43a9b28d41ba644d533377f2ede8c66b19774bf4a9c7a596"))
	ret := &gfP{}
	ret.Div2(x)
	gfpAdd(ret, ret, ret)
	if *ret != *x {
		t.Errorf("got %v, expected %v", ret, x)
	}
}
