//go:build s390x && !purego

package sm2ec

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"
	"time"
)

var bigOne = big.NewInt(1)

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out *[4]uint64, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

func montFromBig(out *[4]uint64, n *big.Int) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r := new(big.Int).Lsh(bigOne, 256)
	// out = big * R mod P
	outBig := new(big.Int).Mul(n, r)
	outBig.Mod(outBig, p)
	fromBig(out, outBig)
}

func toBigInt(in *p256Element) *big.Int {
	var valBytes [32]byte
	p256LittleToBig(&valBytes, in)
	return new(big.Int).SetBytes(valBytes[:])
}

func ordElmToBigInt(in *p256OrdElement) *big.Int {
	var valBytes [32]byte
	p256OrdLittleToBig(&valBytes, in)
	return new(big.Int).SetBytes(valBytes[:])
}

func testP256FromMont(v *big.Int, t *testing.T) {
	val := new(p256Element)
	montFromBig((*[4]uint64)(val), v)
	res := new(p256Element)
	p256FromMont(res, val)
	if toBigInt(res).Cmp(v) != 0 {
		t.Errorf("p256FromMont failed for %x", v.Bytes())
	}
}

func TestP256FromMont(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	for i := 0; i < 20; i++ {
		bigVal := big.NewInt(int64(i))
		testP256FromMont(bigVal, t)
		if i != 0 {
			bigVal = new(big.Int).Sub(p, big.NewInt(int64(i)))
			testP256FromMont(bigVal, t)
		}
	}
}

func testP256OrderReduce(v, expected *big.Int, t *testing.T) {
	val := new(p256OrdElement)
	fromBig((*[4]uint64)(val), v)
	p256OrdReduce(val)
	if ordElmToBigInt(val).Cmp(expected) != 0 {
		t.Errorf("p256OrdReduce failed for %x, expected %x", v.Bytes(), expected.Bytes())
	}
}

func TestP256OrderReduce(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	for i := 0; i < 20; i++ {
		bigVal := big.NewInt(int64(i))
		testP256OrderReduce(bigVal, bigVal, t)
		bigVal = new(big.Int).Add(p, big.NewInt(int64(i)))
		testP256OrderReduce(bigVal, big.NewInt(int64(i)), t)
	}
	testP256OrderReduce(p, big.NewInt(0), t)
	for i := 1; i < 20; i++ {
		bigVal := new(big.Int).Sub(p, big.NewInt(int64(i)))
		testP256OrderReduce(bigVal, bigVal, t)
	}
}

func p256OrderFromMont(in *p256OrdElement) []byte {
	// Montgomery multiplication by R⁻¹, or 1 outside the domain as R⁻¹×R = 1,
	// converts a Montgomery value out of the domain.
	one := &p256OrdElement{1}
	p256OrdMul(in, in, one)

	var xOut [32]byte
	p256OrdLittleToBig(&xOut, in)
	return xOut[:]
}

func p256OrdMulTest(t *testing.T, x, y, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	y1 := new(big.Int).Mul(y, r)
	y1 = y1.Mod(y1, p)
	ax := new(p256OrdElement)
	ay := new(p256OrdElement)
	res2 := new(p256OrdElement)
	fromBig((*[4]uint64)(ax), x1)
	fromBig((*[4]uint64)(ay), y1)
	p256OrdMul(res2, ax, ay)
	resInt := new(big.Int).SetBytes(p256OrderFromMont(res2))

	expected := new(big.Int).Mul(x, y)
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.FailNow()
	}
}

func TestP256OrdMulOrdMinus1(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	p256OrdMulTest(t, pMinus1, pMinus1, p, r)
}

func TestFuzzyP256OrdMul(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
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
		p256OrdMulTest(t, x, y, p, r)
	}
}
