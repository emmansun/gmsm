package sm9

// u is the BN parameter that determines the prime: 600000000058f98a.
var u = bigFromHex("600000000058f98a")

// sixUPlus2 = 6*u+2
var sixUPlus2 = bigFromHex("02400000000215d93e")

// sixUPlus5 = 6*u+5
var sixUPlus5 = bigFromHex("02400000000215d941")

// sixU2Plus1 = 6*u^2+1
var sixU2Plus1 = bigFromHex("d8000000019062ed0000b98b0cb27659")

// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
var p = bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d")

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
var Order = bigFromHex("b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25")

// p2 is p, represented as little-endian 64-bit words.
var p2 = [4]uint64{0xe56f9b27e351457d, 0x21f2934b1a7aeedb, 0xd603ab4ff58ec745, 0xb640000002a3a6f1}

// np is the negative inverse of p, mod 2^256.
var np = [4]uint64{0x892bc42c2f2ee42b, 0x181ae39613c8dbaf, 0x966a4b291522b137, 0xafd2bac5558a13b3}

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

// pMinus1Over4 is (p-1)/4.
var pMinus1Over4 = bigFromHex("2d90000000a8e9bc7580ead3fd63b1d1487ca4d2c69ebbb6f95be6c9f8d4515f")

// pMinus5Over8 is (p-5)/8.
var pMinus5Over8 = [4]uint64{0x7cadf364fc6a28af, 0xa43e5269634f5ddb, 0x3ac07569feb1d8e8, 0x16c80000005474de}

// Montgomery encoding of 2^pMinus5Over8
var twoExpPMinus5Over8 = &gfP{0xd5dd560c5235102a, 0xa3772bab091163ac, 0x0ed7304fd0711ab0, 0x8efb889ed7056e1e}

// Frobenius Constant, frobConstant = i^((p-1)/6)
var frobConstant = fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b"))

// vToPMinus1 is v^(p-1), vToPMinus1 ^ 2 = p - 1
var vToPMinus1 = fromBigInt(bigFromHex("6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011"))

// wToPMinus1 is w^(p-1)
var wToPMinus1 = fromBigInt(bigFromHex("3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b"))

// w2ToPMinus1 is (w^2)^(p-1)
var w2ToPMinus1 = fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))

// wToP2Minus1 is w^(p^2-1)
var wToP2Minus1 = fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334"))

// w2ToP2Minus1 is (w^2)^(p^2-1), w2ToP2Minus1 = vToPMinus1 * wToPMinus1
var w2ToP2Minus1 = fromBigInt(bigFromHex("0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333"))

// vToPMinus1Mw2ToPMinus1 = vToPMinus1 * w2ToPMinus1
var vToPMinus1Mw2ToPMinus1 = fromBigInt(bigFromHex("2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686"))

// betaToNegPPlus1Over3 = i^(-(p-1)/3)
var betaToNegPPlus1Over3 = fromBigInt(bigFromHex("b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a"))

// betaToNegPPlus1Over2 = i^(-(p-1)/2)
var betaToNegPPlus1Over2 = fromBigInt(bigFromHex("49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c"))

// betaToNegP2Plus1Over3 = i^(-(p^2-1)/3)
var betaToNegP2Plus1Over3 = fromBigInt(bigFromHex("b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249"))

// betaToNegP2Plus1Over2 = i^(-(p^2-1)/2)
var betaToNegP2Plus1Over2 = fromBigInt(bigFromHex("b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c"))
