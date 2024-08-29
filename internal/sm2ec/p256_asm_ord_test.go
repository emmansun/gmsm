//go:build (amd64 || arm64 || s390x || ppc64le) && !purego

package sm2ec

import (
	"crypto/rand"
	"io"
	"math/big"
	"testing"
	"time"
)

func ordFromBig(out *p256OrdElement, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

func p256OrderSqrTest(t *testing.T, x, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256OrdElement)
	res2 := new(p256OrdElement)
	ordFromBig(ax, x1)
	p256OrdSqr(res2, ax, 1)
	resInt := new(big.Int).SetBytes(p256OrderFromMont(res2))

	expected := new(big.Int).Mul(x, x)
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.Fatalf("expected %x, got %x", expected.Bytes(), resInt.Bytes())
	}
}

func TestP256OrdSqrOrdMinus1(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	p256OrderSqrTest(t, pMinus1, p, r)
}

func TestFuzzyP256OrdSqr(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
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
		p256OrderSqrTest(t, x, p, r)
	}
}

func BenchmarkP25OrdSqr(b *testing.B) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	io.ReadFull(rand.Reader, scalar1[:])
	x := new(big.Int).SetBytes(scalar1[:])
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256OrdElement)
	res := new(p256OrdElement)
	ordFromBig(ax, x1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256OrdSqr(res, ax, 20)
	}
}

func p256OrdMulTest(t *testing.T, x, y, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	y1 := new(big.Int).Mul(y, r)
	y1 = y1.Mod(y1, p)
	ax := new(p256OrdElement)
	ay := new(p256OrdElement)
	res2 := new(p256OrdElement)
	ordFromBig(ax, x1)
	ordFromBig(ay, y1)
	p256OrdMul(res2, ax, ay)
	resInt := new(big.Int).SetBytes(p256OrderFromMont(res2))

	expected := new(big.Int).Mul(x, y)
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.Fatalf("expected %x, got %x", expected.Bytes(), resInt.Bytes())
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

func BenchmarkP25OrdMul(b *testing.B) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	var scalar1 [32]byte
	io.ReadFull(rand.Reader, scalar1[:])
	x := new(big.Int).SetBytes(scalar1[:])
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	ax := new(p256OrdElement)
	res := new(p256OrdElement)
	ordFromBig(ax, x1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256OrdMul(res, ax, ax)
	}
}
