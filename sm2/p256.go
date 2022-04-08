//go:build !amd64 && !arm64
// +build !amd64,!arm64

package sm2

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// See https://www.imperialviolet.org/2010/12/04/ecc.html ([1]) for background.
// Group Level Optimizations, "Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256"
// SM2 P256 parameters reference GB/T 32918.5-2017 part 5.

type p256Curve struct {
	*elliptic.CurveParams
}

var (
	p256Params *elliptic.CurveParams

	// RInverse contains 1/R mod p - the inverse of the Montgomery constant
	// (2**257).
	p256RInverse *big.Int
)

func initP256() {
	p256Params = &elliptic.CurveParams{Name: "sm2p256v1"}
	// 2**256 - 2**224 - 2**96 + 2**64 - 1
	p256Params.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	p256Params.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	p256Params.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	p256Params.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	p256Params.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	p256Params.BitSize = 256

	// ModeInverse(2**257, P)
	// p256RInverse = big.NewInt(0)
	// r, _ := new(big.Int).SetString("20000000000000000000000000000000000000000000000000000000000000000", 16)
	// p256RInverse.ModInverse(r, p256.P)
	// fmt.Printf("%s\n", hex.EncodeToString(p256RInverse.Bytes()))
	p256RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)

	// Arch-specific initialization, i.e. let a platform dynamically pick a P256 implementation
	initP256Arch()
}

func (curve p256Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func p256GetScalar(out *[32]byte, in []byte) {
	n := new(big.Int).SetBytes(in)
	var scalarBytes []byte

	if n.Cmp(p256.N) >= 0 || len(in) > len(out) {
		n.Mod(n, p256.N)
		scalarBytes = n.Bytes()
	} else {
		scalarBytes = in
	}

	for i, v := range scalarBytes {
		out[len(scalarBytes)-(1+i)] = v
	}
}

func (p256Curve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
	var scalarReversed [32]byte
	p256GetScalar(&scalarReversed, scalar)

	var x1, y1, z1 [p256Limbs]uint32
	p256ScalarBaseMult(&x1, &y1, &z1, &scalarReversed)
	return p256ToAffine(&x1, &y1, &z1)
}

func (p256Curve) ScalarMult(bigX, bigY *big.Int, scalar []byte) (x, y *big.Int) {
	var scalarReversed [32]byte
	p256GetScalar(&scalarReversed, scalar)

	var px, py, x1, y1, z1 [p256Limbs]uint32
	p256FromBig(&px, bigX)
	p256FromBig(&py, bigY)
	p256ScalarMult(&x1, &y1, &z1, &px, &py, &scalarReversed)
	return p256ToAffine(&x1, &y1, &z1)
}

// Field elements are represented as nine, unsigned 32-bit words.
//
// The value of a field element is:
//   x[0] + (x[1] * 2**29) + (x[2] * 2**57) + (x[3] * 2**86) + (x[4] * 2**114) + (x[5] * 2**143) + (x[6] * 2**171) + (x[7] * 2**200) + (x[8] * 2**228)
//
// That is, each limb is alternately 29 or 28-bits wide in little-endian
// order.
//
// This means that a field element hits 2**257, rather than 2**256 as we would
// like. A 28, 29, ... pattern would cause us to hit 2**256, but that causes
// problems when multiplying as terms end up one bit short of a limb which
// would require much bit-shifting to correct.
//
// Finally, the values stored in a field element are in Montgomery form. So the
// value |y| is stored as (y*R) mod p, where p is the P-256 prime and R is
// 2**257.

const (
	p256Limbs    = 9
	bottom28Bits = 0xfffffff
	bottom29Bits = 0x1fffffff
)

var (
	// p256One is the number 1 as a field element.
	p256One  = [p256Limbs]uint32{2, 0, 0x1fffff00, 0x7ff, 0, 0, 0, 0x2000000, 0}
	p256Zero = [p256Limbs]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0}
	// p256P is the prime modulus as a field element.
	p256P = [p256Limbs]uint32{0x1fffffff, 0xfffffff, 0x7f, 0xffffc00, 0x1fffffff, 0xfffffff, 0x1fffffff, 0xeffffff, 0xfffffff}
	// p2562P is the twice prime modulus as a field element.
	p2562P = [p256Limbs]uint32{0x1ffffffe, 0xfffffff, 0xff, 0xffff800, 0x1fffffff, 0xfffffff, 0x1fffffff, 0xdffffff, 0x1fffffff}
	// p256b is the curve param b as a field element
	p256b = [p256Limbs]uint32{0x1781ba84, 0xd230632, 0x1537ab90, 0x9bcd74d, 0xe1e38e7, 0x5417a94, 0x12149e60, 0x17441c5, 0x481fc31}
)

// p256Precomputed contains precomputed values to aid the calculation of scalar
// multiples of the base point, G. It's actually two, equal length, tables
// concatenated.
//
// The first table contains (x,y) field element pairs for 16 multiples of the
// base point, G.
//
//   Index  |  Index (binary) | Value
//       0  |           0000  | 0G (all zeros, omitted)
//       1  |           0001  | G
//       2  |           0010  | 2**64G
//       3  |           0011  | 2**64G + G
//       4  |           0100  | 2**128G
//       5  |           0101  | 2**128G + G
//       6  |           0110  | 2**128G + 2**64G
//       7  |           0111  | 2**128G + 2**64G + G
//       8  |           1000  | 2**192G
//       9  |           1001  | 2**192G + G
//      10  |           1010  | 2**192G + 2**64G
//      11  |           1011  | 2**192G + 2**64G + G
//      12  |           1100  | 2**192G + 2**128G
//      13  |           1101  | 2**192G + 2**128G + G
//      14  |           1110  | 2**192G + 2**128G + 2**64G
//      15  |           1111  | 2**192G + 2**128G + 2**64G + G
//
// The second table follows the same style, but the terms are 2**32G,
// 2**96G, 2**160G, 2**224G.
//      16  |          10000  | 2**32G
//      17  |          10010  | 2**96G
//      18  |          10001  | 2**96G  + 2**32G
//      19  |          10011  | 2**160G
//      20  |          10100  | 2**160G + 2**32G
//      21  |          10101  | 2**160G + 2**96G
//      22  |          10110  | 2**160G + 2**96G + 2**32G
//      23  |          10111  | 2**224G
//      24  |          11000  | 2**224G + 2**32G
//      25  |          11001  | 2**224G + 2**96G
//      26  |          11011  | 2**224G + 2**96G + 2**32G
//      27  |          11100  | 2**224G + 2**160G
//      28  |          11101  | 2**224G + 2**160G  + 2**32G
//      29  |          11110  | 2**224G + 2**160G + 2**96G
//      30  |          11111  | 2**224G + 2**160G + 2**96G + 2**32G
// This is ~2KB of data.
// precompute(1)
// precompute(2**32)
var p256Precomputed = [p256Limbs * 2 * 15 * 2]uint32{
	0x830053d, 0x328990f, 0x6c04fe1, 0xc0f72e5, 0x1e19f3c, 0x666b093, 0x175a87b, 0xec38276, 0x222cf4b,
	0x185a1bba, 0x354e593, 0x1295fac1, 0xf2bc469, 0x47c60fa, 0xc19b8a9, 0xf63533e, 0x903ae6b, 0xc79acba,
	0x15b061a4, 0x33e020b, 0xdffb34b, 0xfcf2c8, 0x16582e08, 0x262f203, 0xfb34381, 0xa55452, 0x604f0ff,
	0x41f1f90, 0xd64ced2, 0xee377bf, 0x75f05f0, 0x189467ae, 0xe2244e, 0x1e7700e8, 0x3fbc464, 0x9612d2e,
	0x1341b3b8, 0xee84e23, 0x1edfa5b4, 0x14e6030, 0x19e87be9, 0x92f533c, 0x1665d96c, 0x226653e, 0xa238d3e,
	0xf5c62c, 0x95bb7a, 0x1f0e5a41, 0x28789c3, 0x1f251d23, 0x8726609, 0xe918910, 0x8096848, 0xf63d028,
	0x152296a1, 0x9f561a8, 0x14d376fb, 0x898788a, 0x61a95fb, 0xa59466d, 0x159a003d, 0x1ad1698, 0x93cca08,
	0x1b314662, 0x706e006, 0x11ce1e30, 0x97b710, 0x172fbc0d, 0x8f50158, 0x11c7ffe7, 0xd182cce, 0xc6ad9e8,
	0x12ea31b2, 0xc4e4f38, 0x175b0d96, 0xec06337, 0x75a9c12, 0xb001fdf, 0x93e82f5, 0x34607de, 0xb8035ed,
	0x17f97924, 0x75cf9e6, 0xdceaedd, 0x2529924, 0x1a10c5ff, 0xb1a54dc, 0x19464d8, 0x2d1997, 0xde6a110,
	0x1e276ee5, 0x95c510c, 0x1aca7c7a, 0xfe48aca, 0x121ad4d9, 0xe4132c6, 0x8239b9d, 0x40ea9cd, 0x816c7b,
	0x632d7a4, 0xa679813, 0x5911fcf, 0x82b0f7c, 0x57b0ad5, 0xbef65, 0xd541365, 0x7f9921f, 0xc62e7a,
	0x3f4b32d, 0x58e50e1, 0x6427aed, 0xdcdda67, 0xe8c2d3e, 0x6aa54a4, 0x18df4c35, 0x49a6a8e, 0x3cd3d0c,
	0xd7adf2, 0xcbca97, 0x1bda5f2d, 0x3258579, 0x606b1e6, 0x6fc1b5b, 0x1ac27317, 0x503ca16, 0xa677435,
	0x57bc73, 0x3992a42, 0xbab987b, 0xfab25eb, 0x128912a4, 0x90a1dc4, 0x1402d591, 0x9ffbcfc, 0xaa48856,
	0x7a7c2dc, 0xcefd08a, 0x1b29bda6, 0xa785641, 0x16462d8c, 0x76241b7, 0x79b6c3b, 0x204ae18, 0xf41212b,
	0x1f567a4d, 0xd6ce6db, 0xedf1784, 0x111df34, 0x85d7955, 0x55fc189, 0x1b7ae265, 0xf9281ac, 0xded7740,
	0xf19468b, 0x83763bb, 0x8ff7234, 0x3da7df8, 0x9590ac3, 0xdc96f2a, 0x16e44896, 0x7931009, 0x99d5acc,
	0x10f7b842, 0xaef5e84, 0xc0310d7, 0xdebac2c, 0x2a7b137, 0x4342344, 0x19633649, 0x3a10624, 0x4b4cb56,
	0x1d809c59, 0xac007f, 0x1f0f4bcd, 0xa1ab06e, 0xc5042cf, 0x82c0c77, 0x76c7563, 0x22c30f3, 0x3bf1568,
	0x7a895be, 0xfcca554, 0x12e90e4c, 0x7b4ab5f, 0x13aeb76b, 0x5887e2c, 0x1d7fe1e3, 0x908c8e3, 0x95800ee,
	0xb36bd54, 0xf08905d, 0x4e73ae8, 0xf5a7e48, 0xa67cb0, 0x50e1067, 0x1b944a0a, 0xf29c83a, 0xb23cfb9,
	0xbe1db1, 0x54de6e8, 0xd4707f2, 0x8ebcc2d, 0x2c77056, 0x1568ce4, 0x15fcc849, 0x4069712, 0xe2ed85f,
	0x2c5ff09, 0x42a6929, 0x628e7ea, 0xbd5b355, 0xaf0bd79, 0xaa03699, 0xdb99816, 0x4379cef, 0x81d57b,
	0x11237f01, 0xe2a820b, 0xfd53b95, 0x6beb5ee, 0x1aeb790c, 0xe470d53, 0x2c2cfee, 0x1c1d8d8, 0xa520fc4,
	0x1518e034, 0xa584dd4, 0x29e572b, 0xd4594fc, 0x141a8f6f, 0x8dfccf3, 0x5d20ba3, 0x2eb60c3, 0x9f16eb0,
	0x11cec356, 0xf039f84, 0x1b0990c1, 0xc91e526, 0x10b65bae, 0xf0616e8, 0x173fa3ff, 0xec8ccf9, 0xbe32790,
	0x11da3e79, 0xe2f35c7, 0x908875c, 0xdacf7bd, 0x538c165, 0x8d1487f, 0x7c31aed, 0x21af228, 0x7e1689d,
	0xdfc23ca, 0x24f15dc, 0x25ef3c4, 0x35248cd, 0x99a0f43, 0xa4b6ecc, 0xd066b3, 0x2481152, 0x37a7688,
	0x15a444b6, 0xb62300c, 0x4b841b, 0xa655e79, 0xd53226d, 0xbeb348a, 0x127f3c2, 0xb989247, 0x71a277d,
	0x19e9dfcb, 0xb8f92d0, 0xe2d226c, 0x390a8b0, 0x183cc462, 0x7bd8167, 0x1f32a552, 0x5e02db4, 0xa146ee9,
	0x1a003957, 0x1c95f61, 0x1eeec155, 0x26f811f, 0xf9596ba, 0x3082bfb, 0x96df083, 0x3e3a289, 0x7e2d8be,
	0x157a63e0, 0x99b8941, 0x1da7d345, 0xcc6cd0, 0x10beed9a, 0x48e83c0, 0x13aa2e25, 0x7cad710, 0x4029988,
	0x13dfa9dd, 0xb94f884, 0x1f4adfef, 0xb88543, 0x16f5f8dc, 0xa6a67f4, 0x14e274e2, 0x5e56cf4, 0x2f24ef,
	0x1e9ef967, 0xfe09bad, 0xfe079b3, 0xcc0ae9e, 0xb3edf6d, 0x3e961bc, 0x130d7831, 0x31043d6, 0xba986f9,
	0x1d28055, 0x65240ca, 0x4971fa3, 0x81b17f8, 0x11ec34a5, 0x8366ddc, 0x1471809, 0xfa5f1c6, 0xc911e15,
	0x8849491, 0xcf4c2e2, 0x14471b91, 0x39f75be, 0x445c21e, 0xf1585e9, 0x72cc11f, 0x4c79f0c, 0xe5522e1,
	0x1874c1ee, 0x4444211, 0x7914884, 0x3d1b133, 0x25ba3c, 0x4194f65, 0x1c0457ef, 0xac4899d, 0xe1fa66c,
	0x130a7918, 0x9b8d312, 0x4b1c5c8, 0x61ccac3, 0x18c8aa6f, 0xe93cb0a, 0xdccb12c, 0xde10825, 0x969737d,
	0xf58c0c3, 0x7cee6a9, 0xc2c329a, 0xc7f9ed9, 0x107b3981, 0x696a40e, 0x152847ff, 0x4d88754, 0xb141f47,
	0x5a16ffe, 0x3a7870a, 0x18667659, 0x3b72b03, 0xb1c9435, 0x9285394, 0xa00005a, 0x37506c, 0x2edc0bb,
	0x19afe392, 0xeb39cac, 0x177ef286, 0xdf87197, 0x19f844ed, 0x31fe8, 0x15f9bfd, 0x80dbec, 0x342e96e,
	0x497aced, 0xe88e909, 0x1f5fa9ba, 0x530a6ee, 0x1ef4e3f1, 0x69ffd12, 0x583006d, 0x2ecc9b1, 0x362db70,
	0x18c7bdc5, 0xf4bb3c5, 0x1c90b957, 0xf067c09, 0x9768f2b, 0xf73566a, 0x1939a900, 0x198c38a, 0x202a2a1,
	0x4bbf5a6, 0x4e265bc, 0x1f44b6e7, 0x185ca49, 0xa39e81b, 0x24aff5b, 0x4acc9c2, 0x638bdd3, 0xb65b2a8,
	0x6def8be, 0xb94537a, 0x10b81dee, 0xe00ec55, 0x2f2cdf7, 0xc20622d, 0x2d20f36, 0xe03c8c9, 0x898ea76,
	0x8e3921b, 0x8905bff, 0x1e94b6c8, 0xee7ad86, 0x154797f2, 0xa620863, 0x3fbd0d9, 0x1f3caab, 0x30c24bd,
	0x19d3892f, 0x59c17a2, 0x1ab4b0ae, 0xf8714ee, 0x90c4098, 0xa9c800d, 0x1910236b, 0xea808d3, 0x9ae2f31,
	0x1a15ad64, 0xa48c8d1, 0x184635a4, 0xb725ef1, 0x11921dcc, 0x3f866df, 0x16c27568, 0xbdf580a, 0xb08f55c,
	0x186ee1c, 0xb1627fa, 0x34e82f6, 0x933837e, 0xf311be5, 0xfedb03b, 0x167f72cd, 0xa5469c0, 0x9c82531,
	0xb92a24b, 0x14fdc8b, 0x141980d1, 0xbdc3a49, 0x7e02bb1, 0xaf4e6dd, 0x106d99e1, 0xd4616fc, 0x93c2717,
	0x1c0a0507, 0xc6d5fed, 0x9a03d8b, 0xa1d22b0, 0x127853e3, 0xc4ac6b8, 0x1a048cf7, 0x9afb72c, 0x65d485d,
	0x72d5998, 0xe9fa744, 0xe49e82c, 0x253cf80, 0x5f777ce, 0xa3799a5, 0x17270cbb, 0xc1d1ef0, 0xdf74977,
	0x114cb859, 0xfa8e037, 0xb8f3fe5, 0xc734cc6, 0x70d3d61, 0xeadac62, 0x12093dd0, 0x9add67d, 0x87200d6,
	0x175bcbb, 0xb29b49f, 0x1806b79c, 0x12fb61f, 0x170b3a10, 0x3aaf1cf, 0xa224085, 0x79d26af, 0x97759e2,
	0x92e19f1, 0xb32714d, 0x1f00d9f1, 0xc728619, 0x9e6f627, 0xe745e24, 0x18ea4ace, 0xfc60a41, 0x125f5b2,
	0xc3cf512, 0x39ed486, 0xf4d15fa, 0xf9167fd, 0x1c1f5dd5, 0xc21a53e, 0x1897930, 0x957a112, 0x21059a0,
	0x1f9e3ddc, 0xa4dfced, 0x8427f6f, 0x726fbe7, 0x1ea658f8, 0x2fdcd4c, 0x17e9b66f, 0xb2e7c2e, 0x39923bf,
	0x1bae104, 0x3973ce5, 0xc6f264c, 0x3511b84, 0x124195d7, 0x11996bd, 0x20be23d, 0xdc437c4, 0x4b4f16b,
	0x11902a0, 0x6c29cc9, 0x1d5ffbe6, 0xdb0b4c7, 0x10144c14, 0x2f2b719, 0x301189, 0x2343336, 0xa0bf2ac,
}

func precompute(params *elliptic.CurveParams, base *big.Int) {
	// 1/32/64/96/128/160/192/224
	var values [4]*big.Int

	values[0] = base
	for i := 1; i < 4; i++ {
		values[i] = new(big.Int)
		values[i].Lsh(values[i-1], 64)
	}
	for i := 0; i < 4; i++ {
		x, y := params.ScalarBaseMult(values[i].Bytes())
		printPoint(params, x, y)
		v := new(big.Int)
		switch i {
		case 1:
			v.Add(values[0], values[1])
			x, y := params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
		case 2:
			v.Add(values[0], values[2])
			x, y := params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[1], values[2])
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[0], v)
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
		case 3:
			v.Add(values[0], values[3])
			x, y := params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[1], values[3])
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[0], v)
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[2], values[3])
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[0], v)
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(values[2], values[3])
			v.Add(v, values[1])
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
			v.Add(v, values[0])
			x, y = params.ScalarBaseMult(v.Bytes())
			printPoint(params, x, y)
		}
	}
}

func printPoint(params *elliptic.CurveParams, x, y *big.Int) {
	var out [p256Limbs]uint32
	p256FromBigAgainstP(&out, x, params.P)
	printp256Limbs(&out)
	p256FromBigAgainstP(&out, y, params.P)
	printp256Limbs(&out)
}

func printp256Limbs(one *[p256Limbs]uint32) {
	for i := 0; i < p256Limbs; i++ {
		fmt.Printf("0x%x, ", one[i])
	}
	fmt.Println()
}

func print1to7(params *elliptic.CurveParams) {
	var out [p256Limbs]uint32
	for i := 1; i < 8; i++ {
		value := big.NewInt(int64(i))
		p256FromBigAgainstP(&out, value, params.P)
		printp256Limbs(&out)
	}
}

// Field element operations:

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
	return ((x - 1) >> 31) - 1
}

// p256ReduceCarry adds a multiple of p in order to cancel |carry|,
// which is a term at 2**257.
//
// On entry: carry < 2**3, inout[0,2,...] < 2**29, inout[1,3,...] < 2**28.
// On exit: inout[0,2,..] < 2**30, inout[1,3,...] < 2**29.
func p256ReduceCarry(inout *[p256Limbs]uint32, carry uint32) {
	carry_mask := nonZeroToAllOnes(carry)
	inout[0] += carry << 1
	// 2**30 = 0x40000000, this doesn't underflow
	inout[2] -= carry << 8
	inout[2] += 0x20000000 & carry_mask

	inout[3] -= 1 & carry_mask
	inout[3] += carry << 11

	// 2**29 = 0x20000000, this doesn't underflow: 0xfffffff + 0x2000000 = 0x11ffffff < 0x20000000
	inout[7] += carry << 25
}

// p256Sum sets out = in+in2.
//
// On entry, in[i]+in2[i] must not overflow a 32-bit word.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29
func p256Sum(out, in, in2 *[p256Limbs]uint32) {
	carry := uint32(0)
	for i := 0; ; i++ {
		out[i] = in[i] + in2[i]
		out[i] += carry
		carry = out[i] >> 29
		out[i] &= bottom29Bits

		i++
		if i == p256Limbs {
			break
		}

		out[i] = in[i] + in2[i]
		out[i] += carry
		carry = out[i] >> 28
		out[i] &= bottom28Bits
	}

	p256ReduceCarry(out, carry)
}

// p256Zero31 is 0 mod p.
// {two31m3, two30m2, two31p10m2, two30m13m2, two31m2, two30m2, two31m2, two30m27m2, two31m2}
var p256Zero31 = [p256Limbs]uint32{0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC, 0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC, 0x7FFFFFFC}

func limbsToBig(in *[p256Limbs]uint32) *big.Int {
	result, tmp := new(big.Int), new(big.Int)

	result.SetInt64(int64(in[p256Limbs-1]))
	for i := p256Limbs - 2; i >= 0; i-- {
		if (i & 1) == 0 {
			result.Lsh(result, 29)
		} else {
			result.Lsh(result, 28)
		}
		tmp.SetInt64(int64(in[i]))
		result.Add(result, tmp)
	}
	return result
}

// p256GetZero31, the func to calucate p256Zero31
func p256GetZero31(out *[p256Limbs]uint32) {
	tmp := big.NewInt(0)
	result := limbsToBig(&[p256Limbs]uint32{1 << 31, 1 << 30, 1 << 31, 1 << 30, 1 << 31, 1 << 30, 1 << 31, 1 << 30, 1 << 31})
	tmp = tmp.Mod(result, p256.P)
	tmp = tmp.Sub(result, tmp)
	for i := 0; i < 9; i++ {
		if bits := tmp.Bits(); len(bits) > 0 {
			out[i] = uint32(bits[0]) & 0x7fffffff
			if out[i] < 0x70000000 {
				out[i] += 0x80000000
			}
		} else {
			out[i] = 0x80000000
		}
		tmp.Sub(tmp, big.NewInt(int64(out[i])))
		tmp.Rsh(tmp, 29)
		i++
		if i == p256Limbs {
			break
		}

		if bits := tmp.Bits(); len(bits) > 0 {
			out[i] = uint32(bits[0]) & 0x3fffffff
			if out[i] < 0x30000000 {
				out[i] += 0x40000000
			}
		} else {
			out[i] = 0x40000000
		}
		tmp.Sub(tmp, big.NewInt(int64(out[i])))
		tmp.Rsh(tmp, 28)
	}
}

// p256Diff sets out = in-in2.
//
// On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
//           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Diff(out, in, in2 *[p256Limbs]uint32) {
	var carry uint32

	for i := 0; ; i++ {
		out[i] = in[i] - in2[i]
		out[i] += p256Zero31[i]
		out[i] += carry
		carry = out[i] >> 29
		out[i] &= bottom29Bits
		i++
		if i == p256Limbs {
			break
		}

		out[i] = in[i] - in2[i]
		out[i] += p256Zero31[i]
		out[i] += carry
		carry = out[i] >> 28
		out[i] &= bottom28Bits
	}

	p256ReduceCarry(out, carry)
}

// p256ReduceDegree sets out = tmp/R mod p where tmp contains 64-bit words with
// the same 29,28,... bit positions as a field element.
//
// The values in field elements are in Montgomery form: x*R mod p where R =
// 2**257. Since we just multiplied two Montgomery values together, the result
// is x*y*R*R mod p. We wish to divide by R in order for the result also to be
// in Montgomery form.
//
// On entry: tmp[i] < 2**64
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29
func p256ReduceDegree(out *[p256Limbs]uint32, tmp [17]uint64) {
	// The following table may be helpful when reading this code:
	//
	// Limb number:   0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10...
	// Width (bits):  29| 28| 29| 28| 29| 28| 29| 28| 29| 28| 29
	// Start bit:     0 | 29| 57| 86|114|143|171|200|228|257|285
	//   (odd phase): 0 | 28| 57| 85|114|142|171|199|228|256|285
	var tmp2 [18]uint32
	var carry, x, xMask uint32

	// tmp contains 64-bit words with the same 29,28,29-bit positions as an
	// field element. So the top of an element of tmp might overlap with
	// another element two positions down. The following loop eliminates
	// this overlap.
	tmp2[0] = uint32(tmp[0]) & bottom29Bits

	tmp2[1] = uint32(tmp[0]) >> 29
	tmp2[1] |= (uint32(tmp[0]>>32) << 3) & bottom28Bits
	tmp2[1] += uint32(tmp[1]) & bottom28Bits
	carry = tmp2[1] >> 28
	tmp2[1] &= bottom28Bits

	for i := 2; i < 17; i++ {
		tmp2[i] = (uint32(tmp[i-2] >> 32)) >> 25
		tmp2[i] += (uint32(tmp[i-1])) >> 28
		tmp2[i] += (uint32(tmp[i-1]>>32) << 4) & bottom29Bits
		tmp2[i] += uint32(tmp[i]) & bottom29Bits
		tmp2[i] += carry
		carry = tmp2[i] >> 29
		tmp2[i] &= bottom29Bits

		i++
		if i == 17 {
			break
		}
		tmp2[i] = uint32(tmp[i-2]>>32) >> 25
		tmp2[i] += uint32(tmp[i-1]) >> 29
		tmp2[i] += ((uint32(tmp[i-1] >> 32)) << 3) & bottom28Bits
		tmp2[i] += uint32(tmp[i]) & bottom28Bits
		tmp2[i] += carry
		carry = tmp2[i] >> 28
		tmp2[i] &= bottom28Bits
	}

	tmp2[17] = uint32(tmp[15]>>32) >> 25
	tmp2[17] += uint32(tmp[16]) >> 29
	tmp2[17] += uint32(tmp[16]>>32) << 3
	tmp2[17] += carry

	// Montgomery elimination of terms:
	//
	// Since R is 2**257, we can divide by R with a bitwise shift if we can
	// ensure that the right-most 257 bits are all zero. We can make that true
	// by adding multiplies of p without affecting the value.
	//
	// So we eliminate limbs from right to left. Since the bottom 29 bits of p
	// are all ones, then by adding tmp2[0]*p to tmp2 we'll make tmp2[0] == 0.
	// We can do that for 8 further limbs and then right shift to eliminate the
	// extra factor of R.
	for i := 0; ; i += 2 {
		tmp2[i+1] += tmp2[i] >> 29
		x = tmp2[i] & bottom29Bits
		xMask = nonZeroToAllOnes(x)
		tmp2[i] = 0

		// The bounds calculations for this loop are tricky. Each iteration of
		// the loop eliminates two words by adding values to words to their
		// right.
		//
		// The following table contains the amounts added to each word (as an
		// offset from the value of i at the top of the loop). The amounts are
		// accounted for from the first and second half of the loop separately
		// and are written as, for example, 28 to mean a value <2**28.
		//
		// Word:                2   3   4   5   6   7   8   9   10
		// Added in top half:   29 28  29  29  29  29  29  28
		//                             29  28  29  28  29
		//                                             29
		// Added in bottom half:   28  29  28  28  28  29  28   28
		//                                 28  29  28  29  28
		//
		//
		// The following table accumulates these values. The sums at the bottom
		// are written as, for example, 29+28, to mean a value < 2**29+2**28.
		//
		// Word:   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17
		//        29  28  29  29  29  29  29  28  28  28  28  28  28  28  28  28
		//            28  29  28  29  28  29  28  29  28  29  28  29  28  29
		//                29  28  28  28  29  28  29  28  29  28  29  28  29
		//                29  28  29  28  29  29  29  29  29  29  29  29  29
		//                    28  29  29  29  28  29  28  29  28  29  28
		//                    28  29  28  29  28  29  28  29  28  29
		//                        29  28  29  28  29  28  29  28  29
		//                        29  28  28  29  29  29  29  29  29
		//                            28  29  28  28  28  28  28
		//                            28  29  28  29  28  29
		//                                29  28  29  28  29
		//                                29  28  29  28  29
		//                                29  28  29
		//                                        29
		//         -------------------------------------------------
		// according the table, from tmp2[6] to tmp[14], consider their initial value,
		// they will overflow the word of 32bits, so we need to normalize them every iteration.
		// This requires more CPU resources than NIST P256.
		//

		tmp2[i+2] += (x << 7) & bottom29Bits
		tmp2[i+3] += (x >> 22)

		// At position 86, which is the starting bit position for word 3, we
		// have a factor of 0xffffc00 = 2**28 - 2**10
		tmp2[i+3] += 0x10000000 & xMask
		tmp2[i+4] += (x - 1) & xMask
		tmp2[i+3] -= (x << 10) & bottom28Bits
		tmp2[i+4] -= x >> 18

		tmp2[i+4] += 0x20000000 & xMask
		tmp2[i+4] -= x
		tmp2[i+5] += (x - 1) & xMask

		tmp2[i+5] += 0x10000000 & xMask
		tmp2[i+5] -= x
		tmp2[i+6] += (x - 1) & xMask

		tmp2[i+6] += 0x20000000 & xMask
		tmp2[i+6] -= x
		tmp2[i+7] += (x - 1) & xMask

		// At position 200, which is the starting bit position for word 7, we
		// have a factor of 0xeffffff = 2**28 - 2**24 - 1
		tmp2[i+7] += 0x10000000 & xMask
		tmp2[i+7] -= x
		tmp2[i+8] += (x - 1) & xMask
		tmp2[i+7] -= (x << 24) & bottom28Bits
		tmp2[i+8] -= x >> 4

		tmp2[i+8] += 0x20000000 & xMask
		tmp2[i+8] -= x
		tmp2[i+8] += (x << 28) & bottom29Bits
		tmp2[i+9] += ((x >> 1) - 1) & xMask

		if i+1 == p256Limbs {
			break
		}

		tmp2[i+2] += tmp2[i+1] >> 28
		x = tmp2[i+1] & bottom28Bits
		xMask = nonZeroToAllOnes(x)
		tmp2[i+1] = 0

		tmp2[i+3] += (x << 7) & bottom28Bits
		tmp2[i+4] += (x >> 21)

		// At position 85, which is the starting bit position for word 3, we
		// have a factor of 0x1ffff800 = 2**29 - 2**11
		tmp2[i+4] += 0x20000000 & xMask
		tmp2[i+5] += (x - 1) & xMask
		tmp2[i+4] -= (x << 11) & bottom29Bits
		tmp2[i+5] -= x >> 18

		tmp2[i+5] += 0x10000000 & xMask
		tmp2[i+5] -= x
		tmp2[i+6] += (x - 1) & xMask

		tmp2[i+6] += 0x20000000 & xMask
		tmp2[i+6] -= x
		tmp2[i+7] += (x - 1) & xMask

		tmp2[i+7] += 0x10000000 & xMask
		tmp2[i+7] -= x
		tmp2[i+8] += (x - 1) & xMask

		// At position 199, which is the starting bit position for word 7, we
		// have a factor of 0x1dffffff = 2**29 - 2**25 - 1
		tmp2[i+8] += 0x20000000 & xMask
		tmp2[i+8] -= x
		tmp2[i+9] += (x - 1) & xMask
		tmp2[i+8] -= (x << 25) & bottom29Bits
		tmp2[i+9] -= x >> 4

		tmp2[i+9] += 0x10000000 & xMask
		tmp2[i+9] -= x
		tmp2[i+10] += (x - 1) & xMask

		// Need to normalize below limbs to avoid overflow the word in the next iteration
		tmp2[i+7] += tmp2[i+6] >> 29
		tmp2[i+6] = tmp2[i+6] & bottom29Bits

		tmp2[i+8] += tmp2[i+7] >> 28
		tmp2[i+7] = tmp2[i+7] & bottom28Bits

		tmp2[i+9] += tmp2[i+8] >> 29
		tmp2[i+8] = tmp2[i+8] & bottom29Bits

		tmp2[i+10] += tmp2[i+9] >> 28
		tmp2[i+9] = tmp2[i+9] & bottom28Bits
	}

	// We merge the right shift with a carry chain. The words above 2**257 have
	// widths of 28,29,... which we need to correct when copying them down.
	carry = 0
	for i := 0; i < 8; i++ {
		// The maximum value of tmp2[i + 9] occurs on the first iteration and
		// is < 2**30+2**29+2**28. Adding 2**29 (from tmp2[i + 10]) is
		// therefore safe.
		out[i] = tmp2[i+9]
		out[i] += carry
		out[i] += (tmp2[i+10] << 28) & bottom29Bits
		carry = out[i] >> 29
		out[i] &= bottom29Bits

		i++
		out[i] = tmp2[i+9] >> 1
		out[i] += carry
		carry = out[i] >> 28
		out[i] &= bottom28Bits
	}

	out[8] = tmp2[17]
	out[8] += carry
	carry = out[8] >> 29
	out[8] &= bottom29Bits

	p256ReduceCarry(out, carry)
}

// p256Square sets out=in*in.
//
// On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Square(out, in *[p256Limbs]uint32) {
	var tmp [17]uint64

	tmp[0] = uint64(in[0]) * uint64(in[0])
	tmp[1] = uint64(in[0]) * (uint64(in[1]) << 1)
	tmp[2] = uint64(in[0])*(uint64(in[2])<<1) +
		uint64(in[1])*(uint64(in[1])<<1)
	tmp[3] = uint64(in[0])*(uint64(in[3])<<1) +
		uint64(in[1])*(uint64(in[2])<<1)
	tmp[4] = uint64(in[0])*(uint64(in[4])<<1) +
		uint64(in[1])*(uint64(in[3])<<2) +
		uint64(in[2])*uint64(in[2])
	tmp[5] = uint64(in[0])*(uint64(in[5])<<1) +
		uint64(in[1])*(uint64(in[4])<<1) +
		uint64(in[2])*(uint64(in[3])<<1)
	tmp[6] = uint64(in[0])*(uint64(in[6])<<1) +
		uint64(in[1])*(uint64(in[5])<<2) +
		uint64(in[2])*(uint64(in[4])<<1) +
		uint64(in[3])*(uint64(in[3])<<1)
	tmp[7] = uint64(in[0])*(uint64(in[7])<<1) +
		uint64(in[1])*(uint64(in[6])<<1) +
		uint64(in[2])*(uint64(in[5])<<1) +
		uint64(in[3])*(uint64(in[4])<<1)
	// tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
	// which is < 2**64 as required.
	tmp[8] = uint64(in[0])*(uint64(in[8])<<1) +
		uint64(in[1])*(uint64(in[7])<<2) +
		uint64(in[2])*(uint64(in[6])<<1) +
		uint64(in[3])*(uint64(in[5])<<2) +
		uint64(in[4])*uint64(in[4])
	tmp[9] = uint64(in[1])*(uint64(in[8])<<1) +
		uint64(in[2])*(uint64(in[7])<<1) +
		uint64(in[3])*(uint64(in[6])<<1) +
		uint64(in[4])*(uint64(in[5])<<1)
	tmp[10] = uint64(in[2])*(uint64(in[8])<<1) +
		uint64(in[3])*(uint64(in[7])<<2) +
		uint64(in[4])*(uint64(in[6])<<1) +
		uint64(in[5])*(uint64(in[5])<<1)
	tmp[11] = uint64(in[3])*(uint64(in[8])<<1) +
		uint64(in[4])*(uint64(in[7])<<1) +
		uint64(in[5])*(uint64(in[6])<<1)
	tmp[12] = uint64(in[4])*(uint64(in[8])<<1) +
		uint64(in[5])*(uint64(in[7])<<2) +
		uint64(in[6])*uint64(in[6])
	tmp[13] = uint64(in[5])*(uint64(in[8])<<1) +
		uint64(in[6])*(uint64(in[7])<<1)
	tmp[14] = uint64(in[6])*(uint64(in[8])<<1) +
		uint64(in[7])*(uint64(in[7])<<1)
	tmp[15] = uint64(in[7]) * (uint64(in[8]) << 1)
	tmp[16] = uint64(in[8]) * uint64(in[8])

	p256ReduceDegree(out, tmp)
}

// p256Mul sets out=in*in2.
//
// On entry: in[0,2,...] < 2**30, in[1,3,...] < 2**29 and
//           in2[0,2,...] < 2**30, in2[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Mul(out, in, in2 *[p256Limbs]uint32) {
	var tmp [17]uint64

	tmp[0] = uint64(in[0]) * uint64(in2[0])
	tmp[1] = uint64(in[0])*(uint64(in2[1])<<0) + //2**29
		uint64(in[1])*(uint64(in2[0])<<0)
	tmp[2] = uint64(in[0])*(uint64(in2[2])<<0) + //2**57
		uint64(in[1])*(uint64(in2[1])<<1) +
		uint64(in[2])*(uint64(in2[0])<<0)
	tmp[3] = uint64(in[0])*(uint64(in2[3])<<0) + //2**86
		uint64(in[1])*(uint64(in2[2])<<0) +
		uint64(in[2])*(uint64(in2[1])<<0) +
		uint64(in[3])*(uint64(in2[0])<<0)
	tmp[4] = uint64(in[0])*(uint64(in2[4])<<0) + //2**114
		uint64(in[1])*(uint64(in2[3])<<1) +
		uint64(in[2])*(uint64(in2[2])<<0) +
		uint64(in[3])*(uint64(in2[1])<<1) +
		uint64(in[4])*(uint64(in2[0])<<0)
	tmp[5] = uint64(in[0])*(uint64(in2[5])<<0) + //2**143
		uint64(in[1])*(uint64(in2[4])<<0) +
		uint64(in[2])*(uint64(in2[3])<<0) +
		uint64(in[3])*(uint64(in2[2])<<0) +
		uint64(in[4])*(uint64(in2[1])<<0) +
		uint64(in[5])*(uint64(in2[0])<<0)
	tmp[6] = uint64(in[0])*(uint64(in2[6])<<0) + //2**171
		uint64(in[1])*(uint64(in2[5])<<1) +
		uint64(in[2])*(uint64(in2[4])<<0) +
		uint64(in[3])*(uint64(in2[3])<<1) +
		uint64(in[4])*(uint64(in2[2])<<0) +
		uint64(in[5])*(uint64(in2[1])<<1) +
		uint64(in[6])*(uint64(in2[0])<<0)
	tmp[7] = uint64(in[0])*(uint64(in2[7])<<0) + //2**200
		uint64(in[1])*(uint64(in2[6])<<0) +
		uint64(in[2])*(uint64(in2[5])<<0) +
		uint64(in[3])*(uint64(in2[4])<<0) +
		uint64(in[4])*(uint64(in2[3])<<0) +
		uint64(in[5])*(uint64(in2[2])<<0) +
		uint64(in[6])*(uint64(in2[1])<<0) +
		uint64(in[7])*(uint64(in2[0])<<0)
	// tmp[8] has the greatest value but doesn't overflow. See logic in
	// p256Square.
	tmp[8] = uint64(in[0])*(uint64(in2[8])<<0) + // 2**228
		uint64(in[1])*(uint64(in2[7])<<1) +
		uint64(in[2])*(uint64(in2[6])<<0) +
		uint64(in[3])*(uint64(in2[5])<<1) +
		uint64(in[4])*(uint64(in2[4])<<0) +
		uint64(in[5])*(uint64(in2[3])<<1) +
		uint64(in[6])*(uint64(in2[2])<<0) +
		uint64(in[7])*(uint64(in2[1])<<1) +
		uint64(in[8])*(uint64(in2[0])<<0)
	tmp[9] = uint64(in[1])*(uint64(in2[8])<<0) + //2**257
		uint64(in[2])*(uint64(in2[7])<<0) +
		uint64(in[3])*(uint64(in2[6])<<0) +
		uint64(in[4])*(uint64(in2[5])<<0) +
		uint64(in[5])*(uint64(in2[4])<<0) +
		uint64(in[6])*(uint64(in2[3])<<0) +
		uint64(in[7])*(uint64(in2[2])<<0) +
		uint64(in[8])*(uint64(in2[1])<<0)
	tmp[10] = uint64(in[2])*(uint64(in2[8])<<0) + //2**285
		uint64(in[3])*(uint64(in2[7])<<1) +
		uint64(in[4])*(uint64(in2[6])<<0) +
		uint64(in[5])*(uint64(in2[5])<<1) +
		uint64(in[6])*(uint64(in2[4])<<0) +
		uint64(in[7])*(uint64(in2[3])<<1) +
		uint64(in[8])*(uint64(in2[2])<<0)
	tmp[11] = uint64(in[3])*(uint64(in2[8])<<0) + //2**314
		uint64(in[4])*(uint64(in2[7])<<0) +
		uint64(in[5])*(uint64(in2[6])<<0) +
		uint64(in[6])*(uint64(in2[5])<<0) +
		uint64(in[7])*(uint64(in2[4])<<0) +
		uint64(in[8])*(uint64(in2[3])<<0)
	tmp[12] = uint64(in[4])*(uint64(in2[8])<<0) + //2**342
		uint64(in[5])*(uint64(in2[7])<<1) +
		uint64(in[6])*(uint64(in2[6])<<0) +
		uint64(in[7])*(uint64(in2[5])<<1) +
		uint64(in[8])*(uint64(in2[4])<<0)
	tmp[13] = uint64(in[5])*(uint64(in2[8])<<0) + //2**371
		uint64(in[6])*(uint64(in2[7])<<0) +
		uint64(in[7])*(uint64(in2[6])<<0) +
		uint64(in[8])*(uint64(in2[5])<<0)
	tmp[14] = uint64(in[6])*(uint64(in2[8])<<0) + //2**399
		uint64(in[7])*(uint64(in2[7])<<1) +
		uint64(in[8])*(uint64(in2[6])<<0)
	tmp[15] = uint64(in[7])*(uint64(in2[8])<<0) + //2**428
		uint64(in[8])*(uint64(in2[7])<<0)
	tmp[16] = uint64(in[8]) * (uint64(in2[8]) << 0) //2**456

	p256ReduceDegree(out, tmp)
}

func p256Assign(out, in *[p256Limbs]uint32) {
	*out = *in
}

// p256Invert calculates |out| = |in|^{-1}
//
// Based on Fermat's Little Theorem:
//   a^p = a (mod p)
//   a^{p-1} = 1 (mod p)
//   a^{p-2} = a^{-1} (mod p)
func p256Invert(out, in *[p256Limbs]uint32) {
	var ftmp, ftmp2 [p256Limbs]uint32

	// each e_I will hold |in|^{2^I - 1}
	var e2, e4, e8, e16, e32, e64 [p256Limbs]uint32
	// 2^32-2
	var e32m2 [p256Limbs]uint32

	p256Square(&ftmp, in) // 2^1
	p256Assign(&ftmp2, &ftmp)
	p256Mul(&ftmp, in, &ftmp) // 2^2 - 2^0
	p256Assign(&e2, &ftmp)
	p256Square(&ftmp, &ftmp) // 2^3 - 2^1
	p256Square(&ftmp, &ftmp) // 2^4 - 2^2
	p256Assign(&e32m2, &ftmp)
	p256Mul(&e32m2, &e32m2, &ftmp2) // 2^4 - 2^2 + 2^1 = 2^4 - 2
	p256Mul(&ftmp, &ftmp, &e2)      // 2^4 - 2^0
	p256Assign(&e4, &ftmp)
	for i := 0; i < 4; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^8 - 2^4
	p256Mul(&e32m2, &e32m2, &ftmp) // 2^8 - 2

	p256Mul(&ftmp, &ftmp, &e4) // 2^8 - 2^0
	p256Assign(&e8, &ftmp)
	for i := 0; i < 8; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^16 - 2^8
	p256Mul(&e32m2, &e32m2, &ftmp) // 2^16 - 2
	p256Mul(&ftmp, &ftmp, &e8)     // 2^16 - 2^0
	p256Assign(&e16, &ftmp)
	for i := 0; i < 16; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^32 - 2^16
	p256Mul(&e32m2, &e32m2, &ftmp) // 2^32 - 2

	p256Mul(&ftmp, &ftmp, &e16) // 2^32 - 2^0
	p256Assign(&e32, &ftmp)
	for i := 0; i < 32; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^64 - 2^32
	p256Assign(&e64, &ftmp)
	p256Mul(&e64, &e64, &e32) // 2^64 - 2^0
	p256Assign(&ftmp, &e64)

	for i := 0; i < 64; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^128 - 2^64
	p256Mul(&ftmp, &ftmp, &e64) // 2^128 - 1

	for i := 0; i < 96; i++ {
		p256Square(&ftmp, &ftmp)
	} // 2^224 - 2^96

	p256Assign(&ftmp2, &e32m2)
	for i := 0; i < 224; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^256 - 2^225

	p256Mul(&ftmp, &ftmp, &ftmp2) // 2^256 - 2^224 - 2^96

	p256Assign(&ftmp2, &e32)

	for i := 0; i < 16; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^48 - 2^16
	p256Mul(&ftmp2, &e16, &ftmp2) // 2^48 - 2^0

	for i := 0; i < 8; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^56 - 2^8
	p256Mul(&ftmp2, &e8, &ftmp2) // 2^56 - 2^0

	for i := 0; i < 4; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^60 - 2^4
	p256Mul(&ftmp2, &e4, &ftmp2) // 2^60 - 2^0

	for i := 0; i < 2; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^62 - 2^2

	p256Mul(&ftmp2, &e2, &ftmp2) // 2^62 - 2^0
	for i := 0; i < 2; i++ {
		p256Square(&ftmp2, &ftmp2)
	} // 2^64 - 2^2
	p256Mul(&ftmp2, in, &ftmp2) // 2^64 - 3
	p256Mul(out, &ftmp2, &ftmp) // 2^256 - 2^224 - 2^96 + 2^64 - 3
}

// p256Scalar3 sets out=3*out.
//
// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Scalar3(out *[p256Limbs]uint32) {
	var carry uint32

	for i := 0; ; i++ {
		out[i] *= 3
		out[i] += carry
		carry = out[i] >> 29
		out[i] &= bottom29Bits

		i++
		if i == p256Limbs {
			break
		}

		out[i] *= 3
		out[i] += carry
		carry = out[i] >> 28
		out[i] &= bottom28Bits
	}

	p256ReduceCarry(out, carry)
}

// p256Scalar4 sets out=4*out.
//
// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Scalar4(out *[p256Limbs]uint32) {
	var carry, nextCarry uint32

	for i := 0; ; i++ {
		nextCarry = out[i] >> 27
		out[i] <<= 2
		out[i] &= bottom29Bits
		out[i] += carry
		carry = nextCarry + (out[i] >> 29)
		out[i] &= bottom29Bits

		i++
		if i == p256Limbs {
			break
		}
		nextCarry = out[i] >> 26
		out[i] <<= 2
		out[i] &= bottom28Bits
		out[i] += carry
		carry = nextCarry + (out[i] >> 28)
		out[i] &= bottom28Bits
	}

	p256ReduceCarry(out, carry)
}

// p256Scalar8 sets out=8*out.
//
// On entry: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
// On exit: out[0,2,...] < 2**30, out[1,3,...] < 2**29.
func p256Scalar8(out *[p256Limbs]uint32) {
	var carry, nextCarry uint32

	for i := 0; ; i++ {
		nextCarry = out[i] >> 26
		out[i] <<= 3
		out[i] &= bottom29Bits
		out[i] += carry
		carry = nextCarry + (out[i] >> 29)
		out[i] &= bottom29Bits

		i++
		if i == p256Limbs {
			break
		}
		nextCarry = out[i] >> 25
		out[i] <<= 3
		out[i] &= bottom28Bits
		out[i] += carry
		carry = nextCarry + (out[i] >> 28)
		out[i] &= bottom28Bits
	}

	p256ReduceCarry(out, carry)
}

// Group operations:
//
// Elements of the elliptic curve group are represented in Jacobian
// coordinates: (x, y, z). An affine point (x', y') is x'=x/z**2, y'=y/z**3 in
// Jacobian form.

// p256PointDouble sets {xOut,yOut,zOut} = 2*{x,y,z}.
//
// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
func p256PointDouble(xOut, yOut, zOut, x, y, z *[p256Limbs]uint32) {
	var delta, gamma, alpha, beta, tmp, tmp2 [p256Limbs]uint32

	p256Square(&delta, z)     // delta = z^2
	p256Square(&gamma, y)     // gamma = y^2
	p256Mul(&beta, x, &gamma) // beta = x * gamma = x * y^2

	p256Sum(&tmp, x, &delta)     // tmp = x + delta = x + z^2
	p256Diff(&tmp2, x, &delta)   // tmp2 = x - delta = x - z^2
	p256Mul(&alpha, &tmp, &tmp2) // alpha = tmp * tmp2 = (x + z^2) * (x - z^2) = x^2 - z^4
	p256Scalar3(&alpha)          // alpha = alpah * 3 = 3*(x^2 - z^4)

	p256Sum(&tmp, y, z)          // tmp = y+z
	p256Square(&tmp, &tmp)       // tmp = (y+z)^2
	p256Diff(&tmp, &tmp, &gamma) // tmp = tmp - gamma = (y+z)^2 - y^2
	p256Diff(zOut, &tmp, &delta) // zOut = tmp - delta = (y+z)^2 - y^2 - z^2

	p256Scalar4(&beta)          // beta = beta * 4 = 4 * x * y^2
	p256Square(xOut, &alpha)    // xOut = alpha ^ 2 = (3*(x^2 - z^4))^2
	p256Diff(xOut, xOut, &beta) // xOut = xOut - beta = (3*(x^2 - z^4))^2 - 4 * x * y^2
	p256Diff(xOut, xOut, &beta) // xOut = xOut - beta = (3*(x^2 - z^4))^2 - 8 * x * y^2

	p256Diff(&tmp, &beta, xOut) // tmp = beta - xOut
	p256Mul(&tmp, &alpha, &tmp) // tmp = 3*(x^2 - z^4) * (beta - xOut)
	p256Square(&tmp2, &gamma)   // tmp2 = gamma^2 = y^4
	p256Scalar8(&tmp2)          // tmp2 = 8*tmp2 = 8*y^4
	p256Diff(yOut, &tmp, &tmp2) // yOut = (3*x^2 - 3*z^4) * (beta - xOut) - 8*y^4
}

// p256PointAddMixed sets {xOut,yOut,zOut} = {x1,y1,z1} + {x2,y2,1}.
// (i.e. the second point is affine.)
//
// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
//
// Note that this function does not handle P+P, infinity+P nor P+infinity
// correctly.
func p256PointAddMixed(xOut, yOut, zOut, x1, y1, z1, x2, y2 *[p256Limbs]uint32) {
	var z1z1, z1z1z1, s2, u2, h, i, j, r, rr, v, tmp [p256Limbs]uint32

	p256Square(&z1z1, z1)
	p256Sum(&tmp, z1, z1)

	p256Mul(&u2, x2, &z1z1)
	p256Mul(&z1z1z1, z1, &z1z1)
	p256Mul(&s2, y2, &z1z1z1)
	p256Diff(&h, &u2, x1)
	p256Sum(&i, &h, &h)
	p256Square(&i, &i)
	p256Mul(&j, &h, &i)
	p256Diff(&r, &s2, y1)
	p256Sum(&r, &r, &r)
	p256Mul(&v, x1, &i)

	p256Mul(zOut, &tmp, &h)
	p256Square(&rr, &r)
	p256Diff(xOut, &rr, &j)
	p256Diff(xOut, xOut, &v)
	p256Diff(xOut, xOut, &v)

	p256Diff(&tmp, &v, xOut)
	p256Mul(yOut, &tmp, &r)
	p256Mul(&tmp, y1, &j)
	p256Diff(yOut, yOut, &tmp)
	p256Diff(yOut, yOut, &tmp)
}

// p256PointAdd sets {xOut,yOut,zOut} = {x1,y1,z1} + {x2,y2,z2}.
//
// See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
//
// Note that this function does not handle P+P, infinity+P nor P+infinity
// correctly.
func p256PointAdd(xOut, yOut, zOut, x1, y1, z1, x2, y2, z2 *[p256Limbs]uint32) {
	var z1z1, z1z1z1, z2z2, z2z2z2, s1, s2, u1, u2, h, i, j, r, rr, v, tmp [p256Limbs]uint32

	p256Square(&z1z1, z1)
	p256Square(&z2z2, z2)
	p256Mul(&u1, x1, &z2z2)

	p256Sum(&tmp, z1, z2)
	p256Square(&tmp, &tmp)
	p256Diff(&tmp, &tmp, &z1z1)
	p256Diff(&tmp, &tmp, &z2z2)

	p256Mul(&z2z2z2, z2, &z2z2)
	p256Mul(&s1, y1, &z2z2z2)

	p256Mul(&u2, x2, &z1z1)
	p256Mul(&z1z1z1, z1, &z1z1)
	p256Mul(&s2, y2, &z1z1z1)
	p256Diff(&h, &u2, &u1)
	p256Sum(&i, &h, &h)
	p256Square(&i, &i)
	p256Mul(&j, &h, &i)
	p256Diff(&r, &s2, &s1)
	p256Sum(&r, &r, &r)
	p256Mul(&v, &u1, &i)

	p256Mul(zOut, &tmp, &h)
	p256Square(&rr, &r)
	p256Diff(xOut, &rr, &j)
	p256Diff(xOut, xOut, &v)
	p256Diff(xOut, xOut, &v)

	p256Diff(&tmp, &v, xOut)
	p256Mul(yOut, &tmp, &r)
	p256Mul(&tmp, &s1, &j)
	p256Diff(yOut, yOut, &tmp)
	p256Diff(yOut, yOut, &tmp)
}

// p256CopyConditional sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
func p256CopyConditional(out, in *[p256Limbs]uint32, mask uint32) {
	for i := 0; i < p256Limbs; i++ {
		tmp := mask & (in[i] ^ out[i])
		out[i] ^= tmp
	}
}

// p256SelectAffinePoint sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
// Constant time table access, safe select.
func p256SelectAffinePoint(xOut, yOut *[p256Limbs]uint32, table []uint32, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}

	for i := uint32(1); i < 16; i++ {
		mask := i ^ index // mask is zero when i equals index, otherwise non-zero. mask = {b3, b2, b1, b0}, ignore unused bits.
		mask |= mask >> 2 // mask = {b3, b2, b1 | b3, b0 | b2}
		mask |= mask >> 1 // mask = {b3, b2 | b3, b1 | b2 | b3, b0 | b1 | b2 | b3}
		mask &= 1         // mask = {0, 0, 0, b0 | b1 | b2 | b3}
		mask--            // mask = 0xffffffff when i equals index, otherwise 0x00000000
		for j := range xOut {
			xOut[j] |= table[0] & mask
			table = table[1:]
		}
		for j := range yOut {
			yOut[j] |= table[0] & mask
			table = table[1:]
		}
	}
}

// p256SelectJacobianPoint sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
func p256SelectJacobianPoint(xOut, yOut, zOut *[p256Limbs]uint32, table *[16][3][p256Limbs]uint32, index uint32) {
	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The implicit value at index 0 is all zero. We don't need to perform that
	// iteration of the loop because we already set out_* to zero.
	for i := uint32(1); i < 16; i++ {
		mask := i ^ index
		mask |= mask >> 2
		mask |= mask >> 1
		mask &= 1
		mask--
		for j := range xOut {
			xOut[j] |= table[i][0][j] & mask
		}
		for j := range yOut {
			yOut[j] |= table[i][1][j] & mask
		}
		for j := range zOut {
			zOut[j] |= table[i][2][j] & mask
		}
	}
}

// p256GetBit returns the bit'th bit of scalar.
func p256GetBit(scalar *[32]uint8, bit uint) uint32 {
	return uint32(((scalar[bit>>3]) >> (bit & 7)) & 1)
}

// p256ScalarBaseMult sets {xOut,yOut,zOut} = scalar*G where scalar is a
// little-endian number. Note that the value of scalar must be less than the
// order of the group.
func p256ScalarBaseMult(xOut, yOut, zOut *[p256Limbs]uint32, scalar *[32]uint8) {
	nIsInfinityMask := ^uint32(0)
	var pIsNoninfiniteMask, mask, tableOffset uint32
	var px, py, tx, ty, tz [p256Limbs]uint32

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}

	// The loop adds bits at positions 0, 64, 128 and 192, followed by
	// positions 32,96,160 and 224 and does this 32 times.
	for i := uint(0); i < 32; i++ {
		if i != 0 {
			p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}
		tableOffset = 0
		for j := uint(0); j <= 32; j += 32 {
			bit0 := p256GetBit(scalar, 31-i+j)
			bit1 := p256GetBit(scalar, 95-i+j)
			bit2 := p256GetBit(scalar, 159-i+j)
			bit3 := p256GetBit(scalar, 223-i+j)
			index := bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3)

			p256SelectAffinePoint(&px, &py, p256Precomputed[tableOffset:], index)
			tableOffset += 30 * p256Limbs

			// Since scalar is less than the order of the group, we know that
			// {xOut,yOut,zOut} != {px,py,1}, unless both are zero, which we handle
			// below.
			p256PointAddMixed(&tx, &ty, &tz, xOut, yOut, zOut, &px, &py)
			// The result of pointAddMixed is incorrect if {xOut,yOut,zOut} is zero
			// (a.k.a.  the point at infinity). We handle that situation by
			// copying the point from the table.
			p256CopyConditional(xOut, &px, nIsInfinityMask)
			p256CopyConditional(yOut, &py, nIsInfinityMask)
			p256CopyConditional(zOut, &p256One, nIsInfinityMask)

			// Equally, the result is also wrong if the point from the table is
			// zero, which happens when the index is zero. We handle that by
			// only copying from {tx,ty,tz} to {xOut,yOut,zOut} if index != 0.
			pIsNoninfiniteMask = nonZeroToAllOnes(index)
			mask = pIsNoninfiniteMask & ^nIsInfinityMask
			p256CopyConditional(xOut, &tx, mask)
			p256CopyConditional(yOut, &ty, mask)
			p256CopyConditional(zOut, &tz, mask)
			// If p was not zero, then n is now non-zero.
			nIsInfinityMask &^= pIsNoninfiniteMask
		}
	}
}

// p256PointToAffine converts a Jacobian point to an affine point. If the input
// is the point at infinity then it returns (0, 0) in constant time.
func p256PointToAffine(xOut, yOut, x, y, z *[p256Limbs]uint32) {
	var zInv, zInvSq [p256Limbs]uint32

	p256Invert(&zInv, z)
	p256Square(&zInvSq, &zInv)
	p256Mul(xOut, x, &zInvSq)
	p256Mul(&zInv, &zInv, &zInvSq)
	p256Mul(yOut, y, &zInv)
}

// p256ToAffine returns a pair of *big.Int containing the affine representation
// of {x,y,z}.
func p256ToAffine(x, y, z *[p256Limbs]uint32) (xOut, yOut *big.Int) {
	var xx, yy [p256Limbs]uint32
	p256PointToAffine(&xx, &yy, x, y, z)
	return p256ToBig(&xx), p256ToBig(&yy)
}

// p256ScalarMult sets {xOut,yOut,zOut} = scalar*{x,y}.
func p256ScalarMult(xOut, yOut, zOut, x, y *[p256Limbs]uint32, scalar *[32]uint8) {
	var px, py, pz, tx, ty, tz [p256Limbs]uint32
	var precomp [16][3][p256Limbs]uint32
	var nIsInfinityMask, index, pIsNoninfiniteMask, mask uint32

	// We precompute 0,1,2,... times {x,y}.
	precomp[1][0] = *x
	precomp[1][1] = *y
	precomp[1][2] = p256One

	for i := 2; i < 16; i += 2 {
		p256PointDouble(&precomp[i][0], &precomp[i][1], &precomp[i][2], &precomp[i/2][0], &precomp[i/2][1], &precomp[i/2][2])
		p256PointAddMixed(&precomp[i+1][0], &precomp[i+1][1], &precomp[i+1][2], &precomp[i][0], &precomp[i][1], &precomp[i][2], x, y)
	}

	for i := range xOut {
		xOut[i] = 0
	}
	for i := range yOut {
		yOut[i] = 0
	}
	for i := range zOut {
		zOut[i] = 0
	}
	nIsInfinityMask = ^uint32(0)

	// We add in a window of four bits each iteration and do this 64 times.
	for i := 0; i < 64; i++ {
		if i != 0 {
			p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
			p256PointDouble(xOut, yOut, zOut, xOut, yOut, zOut)
		}

		index = uint32(scalar[31-i/2])
		if (i & 1) == 1 {
			index &= 15
		} else {
			index >>= 4
		}

		// See the comments in scalarBaseMult about handling infinities.
		p256SelectJacobianPoint(&px, &py, &pz, &precomp, index)
		p256PointAdd(&tx, &ty, &tz, xOut, yOut, zOut, &px, &py, &pz)
		p256CopyConditional(xOut, &px, nIsInfinityMask)
		p256CopyConditional(yOut, &py, nIsInfinityMask)
		p256CopyConditional(zOut, &pz, nIsInfinityMask)

		pIsNoninfiniteMask = nonZeroToAllOnes(index)
		mask = pIsNoninfiniteMask & ^nIsInfinityMask
		p256CopyConditional(xOut, &tx, mask)
		p256CopyConditional(yOut, &ty, mask)
		p256CopyConditional(zOut, &tz, mask)
		nIsInfinityMask &^= pIsNoninfiniteMask
	}
}

// p256FromBig sets out = R*in.
func p256FromBig(out *[p256Limbs]uint32, in *big.Int) {
	p256FromBigAgainstP(out, in, p256.P)
}

func p256FromBigAgainstP(out *[p256Limbs]uint32, in *big.Int, p *big.Int) {
	tmp := new(big.Int).Lsh(in, 257)
	tmp.Mod(tmp, p)

	for i := 0; i < p256Limbs; i++ {
		if bits := tmp.Bits(); len(bits) > 0 {
			out[i] = uint32(bits[0]) & bottom29Bits
		} else {
			out[i] = 0
		}
		tmp.Rsh(tmp, 29)

		i++
		if i == p256Limbs {
			break
		}

		if bits := tmp.Bits(); len(bits) > 0 {
			out[i] = uint32(bits[0]) & bottom28Bits
		} else {
			out[i] = 0
		}
		tmp.Rsh(tmp, 28)
	}
}

// p256ToBig returns a *big.Int containing the value of in.
func p256ToBig(in *[p256Limbs]uint32) *big.Int {
	result := limbsToBig(in)
	result.Mul(result, p256RInverse)
	result.Mod(result, p256.P)
	return result
}
