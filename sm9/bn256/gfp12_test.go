package bn256

import (
	"math/big"
	"testing"
)

func Test_gfP12Square(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		*(&gfP4{}).SetOne(),
	}
	xmulx := &gfP12{}
	xmulx.Mul(x, x)
	xmulx = gfP12Decode(xmulx)

	x2 := &gfP12{}
	x2.Square(x)
	x2 = gfP12Decode(x2)

	if xmulx.x != x2.x || xmulx.y != x2.y || xmulx.z != x2.z {
		t.Errorf("xmulx=%v, x2=%v", xmulx, x2)
	}
}

func Test_gfP12Invert(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		*(&gfP4{}).SetOne(),
	}
	xInv := &gfP12{}
	xInv.Invert(x)

	y := &gfP12{}
	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
	x = &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		*(&gfP4{}).SetZero(),
	}
	xInv.Invert(x)

	y.Mul(x, xInv)
	if !y.IsOne() {
		t.Fail()
	}
}

// Generate wToPMinus1
func Test_gfP12Frobenius_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	i.Exp(i, pMinus1)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0x1a98dfbd4575299f, 0x9ec8547b245c54fd, 0xf51f5eac13df846c, 0x9ef74015d5a16393}) // fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToPMinus1
func Test_gfP12Frobenius_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	i.Exp(i, pMinus1)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0xb626197dce4736ca, 0x8296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992}) //fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate wToP2Minus1
func Test_gfP12FrobeniusP2_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	i.Exp(i, p2)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0xb626197dce4736ca, 0x8296b3557ed0186, 0x9c705db2fd91512a, 0x1c753e748601c992}) // fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToP2Minus1
func Test_gfP12FrobeniusP2_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	p2 := new(big.Int).Mul(p, p)
	p2 = new(big.Int).Sub(p2, big.NewInt(1))
	i.Exp(i, p2)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0x81054fcd94e9c1c4, 0x4c0e91cb8ce2df3e, 0x4877b452e8aedfb4, 0x88f53e748b491776}) //fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate wToP3Minus1
func Test_gfP12FrobeniusP3_Case1(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW()
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	p3 = new(big.Int).Sub(p3, big.NewInt(1))
	i.Exp(i, p3)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0x39b4ef0f3ee72529, 0xdb043bf508582782, 0xb8554ab054ac91e3, 0x9848eec25498cab5}) //fromBigInt(bigFromHex("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

// Generate w2ToP3minus1
func Test_gfP12FrobeniusP3_Case2(t *testing.T) {
	expected := &gfP12{}
	i := &gfP12{}
	i.SetW2()
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	p3 = new(big.Int).Sub(p3, big.NewInt(1))
	i.Exp(i, p3)
	i = gfP12Decode(i)
	expected.z.x.SetZero()
	expected.z.y.x.Set(zero)
	expected.z.y.y.Set(&gfP{0xcadf364fc6a28afa, 0x43e5269634f5ddb7, 0xac07569feb1d8e8a, 0x6c80000005474de3}) //  fromBigInt(bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))
	expected.x.SetZero()
	expected.y.SetZero()
	expected = gfP12Decode(expected)
	if expected.x != i.x || expected.y != i.y || expected.z != i.z {
		t.Errorf("got %v, expected %v", i, expected)
	}
}

func Test_gfP12Frobenius(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
	}
	expected := &gfP12{}
	expected.Exp(x, p)
	got := &gfP12{}
	got.Frobenius(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP2(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
	}
	expected := &gfP12{}
	p2 := new(big.Int).Mul(p, p)
	expected.Exp(x, p2)
	got := &gfP12{}
	got.FrobeniusP2(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP3(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
	}
	expected := &gfP12{}
	p3 := new(big.Int).Mul(p, p)
	p3.Mul(p3, p)
	expected.Exp(x, p3)
	got := &gfP12{}
	got.FrobeniusP3(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_gfP12FrobeniusP6(t *testing.T) {
	x := &gfP12{
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
		gfP4{
			gfP2{
				gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37}, //*fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
				gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1}, //*fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
			},
			gfP2{
				gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53}, // *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
				gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece}, // *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
			},
		},
	}
	expected := &gfP12{}
	p6 := new(big.Int).Mul(p, p)
	p6.Mul(p6, p)
	p6.Mul(p6, p6)
	expected.Exp(x, p6)
	got := &gfP12{}
	got.FrobeniusP6(x)
	if expected.x != got.x || expected.y != got.y || expected.z != got.z {
		t.Errorf("got %v, expected %v", got, expected)
	}
}

func Test_W3(t *testing.T) {
	w1 := (&gfP12{}).SetW()
	w2 := (&gfP12{}).SetW2()

	w1.Mul(w2, w1)
	w1 = gfP12Decode(w1)
	gfp4zero := (&gfP4{}).SetZero()
	gfp4v := (&gfP4{}).SetV()
	gfp4v = gfP4Decode(gfp4v)
	if w1.x != *gfp4zero || w1.y != *gfp4zero || w1.z != *gfp4v {
		t.Errorf("not expected")
	}
}
