//go:build (amd64 || arm64 || loong64 || riscv64 || s390x || ppc64le) && !purego

package sm2ec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/internal/deps/cpu"
)

func decodeHexMust(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}
	return b
}

func leftPad32Bytes(in []byte) []byte {
	if len(in) >= 32 {
		return in
	}
	out := make([]byte, 32)
	copy(out[32-len(in):], in)
	return out
}

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out *p256Element, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

func toBigInt(in *p256Element) *big.Int {
	var valBytes [32]byte
	p256LittleToBig(&valBytes, in)
	return new(big.Int).SetBytes(valBytes[:])
}

func p256MulTest(t *testing.T, x, y, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	y1 := new(big.Int).Mul(y, r)
	y1 = y1.Mod(y1, p)
	ax := new(p256Element)
	ay := new(p256Element)
	res := new(p256Element)
	res2 := new(p256Element)
	fromBig(ax, x1)
	fromBig(ay, y1)
	p256Mul(res2, ax, ay)
	p256FromMont(res, res2)
	resInt := toBigInt(res)

	expected := new(big.Int).Mul(x, y)
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.FailNow()
	}
}

func TestP256MulPMinus1(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	p256MulTest(t, pMinus1, pMinus1, p, r)
}

func TestFuzzyP256Mul(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	var scalar2 [32]byte
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}
	for {
		select {
		case <-timeout.C:
			return
		default:
		}
		io.ReadFull(rand.Reader, scalar1[:])
		io.ReadFull(rand.Reader, scalar2[:])
		x := new(big.Int).SetBytes(scalar1[:])
		y := new(big.Int).SetBytes(scalar2[:])
		p256MulTest(t, x, y, p, r)
	}
}

func BenchmarkP256Mul(b *testing.B) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	io.ReadFull(rand.Reader, scalar1[:])
	x := new(big.Int).SetBytes(scalar1[:])
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256Element)
	res := new(p256Element)
	fromBig(ax, x1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256Mul(res, ax, ax)
	}
}

func p256SqrTest(t *testing.T, x, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256Element)
	res := new(p256Element)
	res2 := new(p256Element)
	fromBig(ax, x1)
	p256Sqr(res2, ax, 1)
	p256FromMont(res, res2)
	resInt := toBigInt(res)

	expected := new(big.Int).Mul(x, x)
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.FailNow()
	}
}

func TestP256SqrPMinus1(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	p256SqrTest(t, pMinus1, p, r)
}

func TestFuzzyP256Sqr(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}
	for {
		select {
		case <-timeout.C:
			return
		default:
		}
		io.ReadFull(rand.Reader, scalar1[:])
		x := new(big.Int).SetBytes(scalar1[:])
		p256SqrTest(t, x, p, r)
	}
}

func BenchmarkP256Sqr(b *testing.B) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	io.ReadFull(rand.Reader, scalar1[:])
	x := new(big.Int).SetBytes(scalar1[:])
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256Element)
	res := new(p256Element)
	fromBig(ax, x1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256Sqr(res, ax, 20)
	}
}

func Test_p256Inverse(t *testing.T) {
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	x, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	gx := &p256Element{0x61328990f418029e, 0x3e7981eddca6c050, 0xd6a1ed99ac24c3c3, 0x91167a5ee1c13b05}
	res := new(p256Element)
	p256Inverse(res, gx)
	resInt := toBigInt(res)
	xInv := new(big.Int).ModInverse(x, p)
	xInv = new(big.Int).Mul(xInv, r)
	xInv = new(big.Int).Mod(xInv, p)
	if resInt.Cmp(xInv) != 0 {
		t.Errorf("expected %v, got %v", hex.EncodeToString(xInv.Bytes()), hex.EncodeToString(resInt.Bytes()))
	}
}

func BenchmarkP256SelectAffine(b *testing.B) {
	var t0 p256AffinePoint
	for i := 0; i < b.N; i++ {
		p256SelectAffine(&t0, &p256Precomputed[20], 20)
	}
}

func TestPointDouble(t *testing.T) {
	var double1, double2 SM2P256Point
	p := NewSM2P256Point().SetGenerator()
	p256PointDoubleAsm(&double1, p)
	if hex.EncodeToString(double1.Bytes()) != "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3" {
		t.Errorf("Double one is incorrect %x", double1.Bytes())
	}
	p256PointDoubleAsm(&double1, &double1)
	if hex.EncodeToString(double1.Bytes()) != "04c239507105c683242a81052ff641ed69009a084ad5cc937db21646cd34a0ced5b1bf7ec4080f3c8735f1294ac0db19686bee2e96ab8c71fb7a253666cb66e009" {
		t.Errorf("Double two is incorrect %x", double1.Bytes())
	}
	p256PointDoubleAsm(&double1, &double1)
	if hex.EncodeToString(double1.Bytes()) != "04b9c3faeb4b1610713db4333d4e860e64d4ea35d60c1c29bb675d822ded0bb916c519b309ecf7269c2491d2de9accf2be0366a8a03024b3e03c286da2cfd31a3e" {
		t.Errorf("Double three is incorrect %x", double1.Bytes())
	}
	p256PointDoubleAsm(&double1, &double1)
	if hex.EncodeToString(double1.Bytes()) != "0435648233f554ae51bbce44ef5db3e419ea133cd248a93e2555645bbc8704fb6804d7ac60f6d975ef6117bca9ce885dd6154b1870a6a651664411a9a30eca2046" {
		t.Errorf("Double four is incorrect %x", double1.Bytes())
	}
	p256PointDoubleAsm(&double1, &double1)
	if hex.EncodeToString(double1.Bytes()) != "0425d3debd0950d180a6d5c2b5817f2329791734cd03e5565ca32641e56024666c92d99a70679d61efb938c406dd5cb0e10458895120e208b4d39e100303fa10a2" {
		t.Errorf("Double five is incorrect %x", double1.Bytes())
	}
	p256PointDoubleAsm(&double1, &double1)

	p256PointDouble6TimesAsm(&double2, p)
	if !bytes.Equal(double1.Bytes(), double2.Bytes()) {
		t.Error("PointDouble6Times is incorrect")
	}

	if hex.EncodeToString(double1.Bytes()) != "0497662389f36ce643a47dcf644f700651e988794843797b0c4a69c806e78615c2cd4d9449aea5cac5328b8d67d4ae956f5eb06c4515ff01bd17eef58bf866b33f" {
		t.Errorf("PointDouble6Times 1 is incorrect %x", double1.Bytes())
	}

	if hex.EncodeToString(double2.Bytes()) != "0497662389f36ce643a47dcf644f700651e988794843797b0c4a69c806e78615c2cd4d9449aea5cac5328b8d67d4ae956f5eb06c4515ff01bd17eef58bf866b33f" {
		t.Errorf("PointDouble6Times 2 is incorrect %x", double2.Bytes())
	}
}

func TestPointAdd(t *testing.T) {
	p := NewSM2P256Point().SetGenerator()
	var p1, p2, sum1, sum2 SM2P256Point
	ret := p256PointAddAsm(&sum1, p, p)
	if ret != 1 {
		t.Error("Should return 1")
	}
	p256PointDoubleAsm(&p1, p)
	p256PointAddAsm(&sum1, p, &p1)

	p256PointDouble6TimesAsm(&p2, p)
	p256PointAddAsm(&sum2, p, &p2)

	if hex.EncodeToString(sum1.Bytes()) != "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6" {
		t.Errorf("G + [2]G is incorrect %x", sum1.Bytes())
	}
	if hex.EncodeToString(sum2.Bytes()) != "04403b18162679c05515a8ecd063d726ba7b1eb83b8306ace5cd382e53ed23ae1feb42ebf496a7bd698d61a1c805ef7074df882dfcffcc84bcd0a5d4ebea56f425" {
		t.Errorf("G + [64]G is incorrect %x", sum2.Bytes())
	}
}

// Regression test for the verify-zero-hash vector on the BMI2/ADX point-add path.
// This test is expected to fail until the p256PointAddAsm BMI2/ADX bug is fixed.
func TestP256PointAddAsmBMI2Regression(t *testing.T) {
	if !cpu.X86.HasADX || !cpu.X86.HasBMI2 {
		t.Skip("CPU does not support ADX/BMI2")
	}

	rBytes := decodeHexMust(t, "be0ea64e1ec06f0d247093f3ccbbadcfb6260224272f86ddb78326e7cd6c7560")
	_, p1, p2 := buildVerifyZeroHashOperands(t)

	old := supportBMI2
	defer func() { supportBMI2 = old }()

	supportBMI2 = true
	var sum SM2P256Point
	_ = p256PointAddAsm(&sum, p1, p2)
	rx, err := sum.BytesX()
	if err != nil {
		t.Fatalf("BytesX(sum) failed: %v", err)
	}

	if !bytes.Equal(rx, rBytes) {
		t.Fatalf("p256PointAddAsm BMI2 regression\nexpected r: %x\nactual rx:   %x", rBytes, rx)
	}
}

// Regression test for the known bad p256Mul BMI2 vector found while tracing
// p256Inverse (first divergence at step 29: Mul(t1, t2)).
// This test is expected to fail until mulBMI2 carry-chain bug is fixed.
func TestP256MulBMI2KnownBadVector(t *testing.T) {
	if !cpu.X86.HasADX || !cpu.X86.HasBMI2 {
		t.Skip("CPU does not support ADX/BMI2")
	}

	a := p256Element{0x9e33db4ce976f0d0, 0xbfff13c7cf9058cc, 0xe1a0b4b129d5a082, 0xaab573c26f5a3de8}
	b := p256Element{0xefb0ad3e4d98a44c, 0xdd1c0e16a5de4d21, 0xe02fe084a848fecf, 0x0d0047be9622130f}
	expected := p256Element{0x7b7910319f9c035f, 0xfa5e44de1a9e2894, 0x2ee5b2cac3110ec5, 0xaa4e625fd40acb1b}

	oldBMI2 := supportBMI2
	defer func() {
		supportBMI2 = oldBMI2
	}()

	// Baseline: non-BMI2 path should match the known good result.
	supportBMI2 = false
	var gotOff p256Element
	p256Mul(&gotOff, &a, &b)
	if gotOff != expected {
		t.Fatalf("p256Mul non-BMI2 baseline mismatch\nexpected: %#v\nactual:   %#v", expected, gotOff)
	}

	// Regression target: BMI2 path should match baseline too.
	supportBMI2 = true
	var gotOn p256Element
	p256Mul(&gotOn, &a, &b)
	if gotOn != expected {
		t.Fatalf("p256Mul BMI2 regression\ninput a:  %#v\ninput b:  %#v\nexpected: %#v\nactual:   %#v", a, b, expected, gotOn)
	}
}

func buildVerifyZeroHashOperands(t *testing.T) (*SM2P256Point, *SM2P256Point, *SM2P256Point) {
	pubBytes := decodeHexMust(t, "04ef4de57af00ae424c00c4caadff7193f804a19dd73a7e2954db9d0d15ab4cbba67728c3f4572878b7a674735da9fde1682fe2d9e0799c4a5cde57e3d473039a2")
	rBytes := decodeHexMust(t, "be0ea64e1ec06f0d247093f3ccbbadcfb6260224272f86ddb78326e7cd6c7560")
	sBytes := decodeHexMust(t, "e9f6ab2fcc48a2cef94838e66b5c7e21fd8e4de25990dd98ca5243f4966f2853")
	nBytes := decodeHexMust(t, "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123")

	Q, err := NewSM2P256Point().SetBytes(pubBytes)
	if err != nil {
		t.Fatalf("SetBytes(Q) failed: %v", err)
	}
	p1, err := NewSM2P256Point().ScalarBaseMult(sBytes)
	if err != nil {
		t.Fatalf("ScalarBaseMult failed: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	tScalar := new(big.Int).Add(r, s)
	tScalar.Mod(tScalar, n)
	tScalarBytes := leftPad32Bytes(tScalar.Bytes())
	p2, err := NewSM2P256Point().ScalarMult(Q, tScalarBytes)
	if err != nil {
		t.Fatalf("ScalarMult failed: %v", err)
	}
	return Q, p1, p2
}

func TestSelect(t *testing.T) {
	p := NewSM2P256Point().SetGenerator()
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^32.
	var precomp p256Table
	var t0 SM2P256Point

	// Prepare the table
	precomp[0] = *p // 1

	p256PointDoubleAsm(&precomp[1], p)             //2
	p256PointAddAsm(&precomp[2], &precomp[1], p)   //3
	p256PointDoubleAsm(&precomp[3], &precomp[1])   //4
	p256PointAddAsm(&precomp[4], &precomp[3], p)   //5
	p256PointDoubleAsm(&precomp[5], &precomp[2])   //6
	p256PointAddAsm(&precomp[6], &precomp[5], p)   //7
	p256PointDoubleAsm(&precomp[7], &precomp[3])   //8
	p256PointAddAsm(&precomp[8], &precomp[7], p)   //9
	p256PointDoubleAsm(&precomp[9], &precomp[4])   //10
	p256PointAddAsm(&precomp[10], &precomp[9], p)  //11
	p256PointDoubleAsm(&precomp[11], &precomp[5])  //12
	p256PointAddAsm(&precomp[12], &precomp[11], p) //13
	p256PointDoubleAsm(&precomp[13], &precomp[6])  //14
	p256PointAddAsm(&precomp[14], &precomp[13], p) //15
	p256PointDoubleAsm(&precomp[15], &precomp[7])  //16

	p256PointAddAsm(&precomp[16], &precomp[15], p) //17
	p256PointDoubleAsm(&precomp[17], &precomp[8])  //18
	p256PointAddAsm(&precomp[18], &precomp[17], p) //19
	p256PointDoubleAsm(&precomp[19], &precomp[9])  //20
	p256PointAddAsm(&precomp[20], &precomp[19], p) //21
	p256PointDoubleAsm(&precomp[21], &precomp[10]) //22
	p256PointAddAsm(&precomp[22], &precomp[21], p) //23
	p256PointDoubleAsm(&precomp[23], &precomp[11]) //24
	p256PointAddAsm(&precomp[24], &precomp[23], p) //25
	p256PointDoubleAsm(&precomp[25], &precomp[12]) //26
	p256PointAddAsm(&precomp[26], &precomp[25], p) //27
	p256PointDoubleAsm(&precomp[27], &precomp[13]) //28
	p256PointAddAsm(&precomp[28], &precomp[27], p) //29
	p256PointDoubleAsm(&precomp[29], &precomp[14]) //30
	p256PointAddAsm(&precomp[30], &precomp[29], p) //31
	p256PointDoubleAsm(&precomp[31], &precomp[15]) //32

	for i := 1; i <= 32; i++ {
		p256Select(&t0, &precomp, i, 32)
		if !bytes.Equal(t0.Bytes(), precomp[i-1].Bytes()) {
			t.Errorf("Select %d failed %x, %x", i, t0.Bytes(), precomp[i-1].Bytes())
		}
	}
}

func TestP256PointAddAffineAsm(t *testing.T) {
	var t0 p256AffinePoint
	p := NewSM2P256Point().SetGenerator()

	p256SelectAffine(&t0, &p256Precomputed[0], 3)
	p.x, p.y, p.z = t0.x, t0.y, p256One
	p256SelectAffine(&t0, &p256Precomputed[32], 3)
	p1 := NewSM2P256Point()
	p256PointAddAffineAsm(p1, p, &t0, 0, 3, 1)
	if hex.EncodeToString(p1.Bytes()) != "04f1dd662afa8046798bb6dcf34c4b1e1e9d7e88aff4ba8b43de4acf7e8f62a60f16a9cb1bbd2eacb000382c13303ef83b7a0b7a821390db3887c96683af0e7bd6" {
		t.Errorf("PointAddAffine is incorrect %x", p1.Bytes())
	}

	p256PointAddAffineAsm(p1, p, &t0, 1, 3, 1)
	if hex.EncodeToString(p1.Bytes()) != "040e0703211fd58fc3f11b675db4317809ca492851eb8bb9feeaa18c4d05282cd875a74e1684fb24b7fd9cce2d1d7bf3072bd04b0edb237e4f31d68af2f6b81470" {
		t.Errorf("PointAddAffine is incorrect %x", p1.Bytes())
	}

	p256PointAddAffineAsm(p1, p, &t0, 0, 0, 1)
	if hex.EncodeToString(p1.Bytes()) != "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6" {
		t.Errorf("PointAddAffine is incorrect %x", p1.Bytes())
	}

	p256PointAddAffineAsm(p1, p, &t0, 0, 3, 0)
	if hex.EncodeToString(p1.Bytes()) != "04ccc69dcd48c3cdd56e164408eb8f345ff512ce57673bcb32c5b0fd8fe13eb9128fe410fe8bc0792948ad23d074346f66e842857399981e91f0c920e6e0afa3cc" {
		t.Errorf("PointAddAffine is incorrect %x.%x.%x.%x %x.%x.%x.%x %x.%x.%x.%x - %x.%x.%x.%x %x.%x.%x.%x", p1.x[0], p1.x[1], p1.x[2], p1.x[3], p1.y[0], p1.y[1], p1.y[2], p1.y[3], p1.z[0], p1.z[1], p1.z[2], p1.z[3], t0.x[0], t0.x[1], t0.x[2], t0.x[3], t0.y[0], t0.y[1], t0.y[2], t0.y[3])
	}
}
