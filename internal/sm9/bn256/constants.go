package bn256

import "math/big"

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("sm9: internal error: invalid encoding")
	}
	return b
}

// u is the BN parameter that determines the prime: 600000000058f98a.
var u = bigFromHex("600000000058f98a")

// sixUPlus2 = 6*u+2
var sixUPlus2 = bigFromHex("02400000000215d93e")

var sixUPlus2NAF = []int8{0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1}

// sixUPlus5 = 6*u+5
var sixUPlus5 = bigFromHex("02400000000215d941")

// sixU2Plus1 = 6*u^2+1
var sixU2Plus1 = bigFromHex("d8000000019062ed0000b98b0cb27659")

// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var p = bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d")

var OrderBytes = []byte{
	0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
	0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
	0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
	0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x25,
}

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
var Order = new(big.Int).SetBytes(OrderBytes)

var OrderMinus1Bytes = []byte{
	0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
	0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
	0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
	0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x24,
}

var OrderMinus2Bytes = []byte{
	0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1,
	0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x44,
	0x49, 0xf2, 0x93, 0x4b, 0x18, 0xea, 0x8b, 0xee,
	0xe5, 0x6e, 0xe1, 0x9c, 0xd6, 0x9e, 0xcf, 0x23,
}

// p2 is p, represented as little-endian 64-bit words.
var p2 = [4]uint64{0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

// np is the negative inverse of p, mod 2^256.
var np = [4]uint64{0x892bc42c2f2ee42b, 0x181ae39613c8dbaf, 0x966a4b291522b137, 0xafd2bac5558a13b3}

// Montgomery encoding of 15
var b3 = [4]uint64{0x2dd845ba5a554cbf, 0x3719ead6d3ea67f6, 0x71b2f270db49a754, 0x0cbfffffc8934e29}

// rN1 is R^-1 where R = 2^256 mod p.
var rN1 = &gfP{0x0a1c7970e5df544d, 0xe74504e9a96b56cc, 0xcda02d92d4d62924, 0x7d2bc576fdf597d1}

// r2 is R^2 where R = 2^256 mod p.
var r2 = &gfP{0x27dea312b417e2d2, 0x88f8105fae1a5d3f, 0xe479b522d6706e7b, 0x2ea795a656f62fbd}

// r3 is R^3 where R = 2^256 mod p.
var r3 = &gfP{0x130257769df5827e, 0x36920fc0837ec76e, 0xcbec24519c22a142, 0x219be84a7c687090}

// pMinus2 is p-2.
var pMinus2 = [4]uint64{0xe56f9b27e351457b, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

// pMinus1Over2 is (p-1)/2.
var pMinus1Over2 = [4]uint64{0xf2b7cd93f1a8a2be, 0x90f949a58d3d776d, 0xeb01d5a7fac763a2, 0x5b2000000151d378}

// pMinus1Over2Big is (p-1)/2.
var pMinus1Over2Big = bigFromHex("5b2000000151d378eb01d5a7fac763a290f949a58d3d776df2b7cd93f1a8a2be")

// pMinus1Over4 is (p-1)/4.
var pMinus1Over4 = bigFromHex("2d90000000a8e9bc7580ead3fd63b1d1487ca4d2c69ebbb6f95be6c9f8d4515f")

// pMinus5Over8 is (p-5)/8.
var pMinus5Over8 = [4]uint64{0x7cadf364fc6a28af, 0xa43e5269634f5ddb, 0x3ac07569feb1d8e8, 0x16c80000005474de}

// Montgomery encoding of 2^pMinus5Over8
var twoExpPMinus5Over8 = &gfP{0xd5dd560c5235102a, 0xa3772bab091163ac, 0x0ed7304fd0711ab0, 0x8efb889ed7056e1e}

// Frobenius Constant, frobConstant = i^((p-1)/6)
// 3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
var frobConstant = newGFpFromBytes([]byte{0x3f, 0x23, 0xea, 0x58, 0xe5, 0x72, 0x0b, 0xdb, 0x84, 0x3c, 0x6c, 0xfa, 0x9c, 0x08, 0x67, 0x49, 0x47, 0xc5, 0xc8, 0x6e, 0x0d, 0xdd, 0x04, 0xed, 0xa9, 0x1d, 0x83, 0x54, 0x37, 0x7b, 0x69, 0x8b})

// vToPMinus1 is v^(p-1), vToPMinus1 ^ 2 = p - 1
// 6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011
var vToPMinus1 = newGFpFromBytes([]byte{0x6c, 0x64, 0x8d, 0xe5, 0xdc, 0x0a, 0x3f, 0x2c, 0xf5, 0x5a, 0xcc, 0x93, 0xee, 0x0b, 0xaf, 0x15, 0x9f, 0x9d, 0x41, 0x18, 0x06, 0xdc, 0x51, 0x77, 0xf5, 0xb2, 0x1f, 0xd3, 0xda, 0x24, 0xd0, 0x11})

// wToPMinus1 is w^(p-1)
// 3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
var wToPMinus1 = frobConstant

// w2ToPMinus1 is (w^2)^(p-1)
// 0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334
var w2ToPMinus1 = newGFpFromBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf2, 0x78, 0x02, 0x72, 0x35, 0x4f, 0x8b, 0x78, 0xf4, 0xd5, 0xfc, 0x11, 0x96, 0x7b, 0xe6, 0x53, 0x34})

// wToP2Minus1 is w^(p^2-1)
// 0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334
var wToP2Minus1 = w2ToPMinus1

// w2ToP2Minus1 is (w^2)^(p^2-1), w2ToP2Minus1 = vToPMinus1 * wToPMinus1
// 0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333
var w2ToP2Minus1 = newGFpFromBytes([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0x00, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf2, 0x78, 0x02, 0x72, 0x35, 0x4f, 0x8b, 0x78, 0xf4, 0xd5, 0xfc, 0x11, 0x96, 0x7b, 0xe6, 0x53, 0x33})

// vToPMinus1Mw2ToPMinus1 = vToPMinus1 * w2ToPMinus1
// 2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686
var vToPMinus1Mw2ToPMinus1 = newGFpFromBytes([]byte{0x2d, 0x40, 0xa3, 0x8c, 0xf6, 0x98, 0x33, 0x51, 0x71, 0x1e, 0x5f, 0x99, 0x52, 0x03, 0x47, 0xcc, 0x57, 0xd7, 0x78, 0xa9, 0xf8, 0xff, 0x4c, 0x8a, 0x4c, 0x94, 0x9c, 0x7f, 0xa2, 0xa9, 0x66, 0x86})

// betaToNegPPlus1Over3 = i^(-(p-1)/3)
// b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a
var betaToNegPPlus1Over3 = newGFpFromBytes([]byte{0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf0, 0xe3, 0x03, 0xab, 0x4f, 0xf2, 0xeb, 0x20, 0x52, 0xa9, 0xf0, 0x21, 0x15, 0xca, 0xef, 0x75, 0xe7, 0x0f, 0x73, 0x89, 0x91, 0x67, 0x6a, 0xf2, 0x4a})

// betaToNegPPlus1Over2 = i^(-(p-1)/2)
// 49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c
var betaToNegPPlus1Over2 = newGFpFromBytes([]byte{0x49, 0xdb, 0x72, 0x1a, 0x26, 0x99, 0x67, 0xc4, 0xe0, 0xa8, 0xde, 0xbc, 0x07, 0x83, 0x18, 0x2f, 0x82, 0x55, 0x52, 0x33, 0x13, 0x9e, 0x9d, 0x63, 0xef, 0xbd, 0x7b, 0x54, 0x09, 0x2c, 0x75, 0x6c})

// betaToNegP2Plus1Over3 = i^(-(p^2-1)/3)
// b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249
var betaToNegP2Plus1Over3 = newGFpFromBytes([]byte{0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf0, 0xe3, 0x03, 0xab, 0x4f, 0xf2, 0xeb, 0x20, 0x52, 0xa9, 0xf0, 0x21, 0x15, 0xca, 0xef, 0x75, 0xe7, 0x0f, 0x73, 0x89, 0x91, 0x67, 0x6a, 0xf2, 0x49})

// betaToNegP2Plus1Over2 = i^(-(p^2-1)/2)
// b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c
var betaToNegP2Plus1Over2 = newGFpFromBytes([]byte{0xb6, 0x40, 0x00, 0x00, 0x02, 0xa3, 0xa6, 0xf1, 0xd6, 0x03, 0xab, 0x4f, 0xf5, 0x8e, 0xc7, 0x45, 0x21, 0xf2, 0x93, 0x4b, 0x1a, 0x7a, 0xee, 0xdb, 0xe5, 0x6f, 0x9b, 0x27, 0xe3, 0x51, 0x45, 0x7c})

var sToPMinus1 = w2ToPMinus1

var sTo2PMinus2 = w2ToP2Minus1

var sToPSquaredMinus1 = w2ToP2Minus1

var sTo2PSquaredMinus2 = betaToNegP2Plus1Over3

var sToPMinus1Over2 = frobConstant

var sToPSquaredMinus1Over2 = sToPMinus1
