//go:build (amd64 || arm64 || s390x || ppc64le) && !purego

package sm2ec

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	"time"
)

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
	p256PointDoubleAsm(&double1, &double1)
	p256PointDoubleAsm(&double1, &double1)
	p256PointDoubleAsm(&double1, &double1)
	p256PointDoubleAsm(&double1, &double1)
	p256PointDoubleAsm(&double1, &double1)

	p256PointDouble6TimesAsm(&double2, p)
	if !bytes.Equal(double1.Bytes(), double2.Bytes()) {
		t.Error("PointDouble6Times is incorrect")
	}

	if hex.EncodeToString(double1.Bytes()) != "0497662389f36ce643a47dcf644f700651e988794843797b0c4a69c806e78615c2cd4d9449aea5cac5328b8d67d4ae956f5eb06c4515ff01bd17eef58bf866b33f" {
		t.Errorf("PointDouble6Times is incorrect %x", double1.Bytes())
	}
}

func TestPointAdd(t *testing.T) {
	p := NewSM2P256Point().SetGenerator()
	var p1, p2, sum1, sum2 SM2P256Point
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
