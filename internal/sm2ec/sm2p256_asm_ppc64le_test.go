//go:build ppc64le && !purego

package sm2ec

import (
	"math/big"
	"testing"
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
		bigVal = new(big.Int).Sub(p, big.NewInt(int64(i)))
		testP256FromMont(bigVal, t)
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
