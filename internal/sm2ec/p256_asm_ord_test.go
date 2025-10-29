//go:build (amd64 || arm64 || s390x || ppc64le || loong64 || riscv64) && !purego

package sm2ec

import (
	"crypto/rand"
	"fmt"
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
	expected := new(big.Int).Mul(x, y)
	expected = expected.Mod(expected, p)
	expected = expected.Mul(expected, r)
	expected = expected.Mod(expected, p)
	var xOut [32]byte
	p256OrdLittleToBig(&xOut, res2)
	resInt := new(big.Int).SetBytes(xOut[:])
	if resInt.Cmp(expected) != 0 {
		t.Fatalf("expected %x, got %x", expected.Bytes(), resInt.Bytes())
	}

	resInt = new(big.Int).SetBytes(p256OrderFromMont(res2))

	expected = new(big.Int).Mul(x, y)
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

/*
func main() {
	mod := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64
	p2 := []*big.Int{
		new(big.Int).SetUint64(0x53bbf40939d54123),
		new(big.Int).SetUint64(0x7203df6b21c6052b),
		new(big.Int).SetUint64(0xffffffffffffffff),
		new(big.Int).SetUint64(0xfffffffeffffffff),
	}
	mult := new(big.Int).SetUint64(0x327f9e8872350975)

	for i, v := range p2 {
		// y = (-1) * modinv(p2[i], 2^64) mod 2^64
		y := new(big.Int).ModInverse(v, mod)
		y.Neg(y)
		y.Mod(y, mod)

		// x = y * modinv(mult, 2^64) mod 2^64
		x := new(big.Int).ModInverse(mult, mod)
		x.Mul(x, y)
		x.Mod(x, mod)

		// Verify
		y2 := new(big.Int).Mul(x, mult)
		y2.Mod(y2, mod)

		result := new(big.Int).Mul(y2, v)
		result.Mod(result, mod)

		fmt.Printf("p2[%d]: 0x%x\n", i, v.Uint64())
		fmt.Printf("  x: 0x%x\n", x.Uint64())
		fmt.Printf("  (x * mult) %% 2^64 = 0x%x\n", y2.Uint64())
		fmt.Printf("  ((x * mult) * p2[i]) %% 2^64 = 0x%x\n", result.Uint64())
		fmt.Printf("  Is all 1? %v\n\n", result.Uint64() == ^uint64(0))
	}
}
*/
func TestP256OrdMulWithCarry(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	data := bigFromHex("E6194D19C62ABEDDAC440BF6C62ABEDD7203DF6B21C6052B")
	p256OrdMulTest(t, data, big.NewInt(1), p, r)
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

func TestP256OrderMinusOne(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(r, p)
	fmt.Printf("p256 order: %x\n", pMinus1.Bytes())
}
