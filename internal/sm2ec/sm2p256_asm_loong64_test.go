//go:build loong64 && !purego

package sm2ec

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestP256BigToLittle(t *testing.T) {
	// 构造一个已知的 32 字节大端输入
	var in [32]byte
	for i := 0; i < 32; i++ {
		in[i] = byte(i + 1)
	}
	var out p256Element

	p256BigToLittle(&out, &in)

	// 检查每个 limb 是否为小端解包
	for i := 0; i < 4; i++ {
		expected := binary.BigEndian.Uint64(in[i*8 : (i+1)*8])
		k := 3 - i // 逆序存储
		if out[k] != expected {
			t.Errorf("limb %d: got 0x%x, want 0x%x", k, out[k], expected)
		}
	}

	// 逆操作测试
	var back [32]byte
	p256LittleToBig(&back, &out)
	if !bytes.Equal(in[:], back[:]) {
		t.Errorf("p256LittleToBig(p256BigToLittle(...)) mismatch\nin:   %x\nback: %x", in, back)
	}
}

func TestP256NegCond(t *testing.T) {
	var tests = []struct {
		input    p256Element
		cond     int
		expected p256Element
	}{
		{
			input:    p256Element{1, 0, 0, 0},
			cond:     1,
			expected: p256Element{0xfffffffffffffffe, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff},
		},
		{
			input:    p256Element{1, 0, 0, 0},
			cond:     0,
			expected: p256Element{1, 0, 0, 0},
		},
		{
			input:    p256Element{0x1, 0xffffffff00000001, 0xfffffffffffffffe, 0xfffffffeffffffff},
			cond:     1,
			expected: p256Element{0xfffffffffffffffe, 0xffffffffffffffff, 0, 0},
		},
	}

	for i, test := range tests {
		var result p256Element
		copy(result[:], test.input[:])
		p256NegCond(&result, test.cond)
		if result != test.expected {
			t.Errorf("test %d: got %x, want %x", i, result, test.expected)
		}
	}
}

func newPoint(x, y, z uint64) *SM2P256Point1 {
	return &SM2P256Point1{
		x: p256Element{x, x + 1, x + 2, x + 3},
		y: p256Element{y, y + 1, y + 2, y + 3},
		z: p256Element{z, z + 1, z + 2, z + 3},
	}
}

func TestP256MovCond(t *testing.T) {
	fmt.Printf("supportLSX=%v, supportLASX=%v\n", supportLSX, supportLASX)
	a := newPoint(10, 20, 30)
	b := newPoint(100, 200, 300)
	var res SM2P256Point1

	// cond == 0: res = b
	p256MovCond(&res, a, b, 0)
	if !reflect.DeepEqual(res, *b) {
		t.Errorf("cond=0: got %+v, want %+v", res, *b)
	}

	// cond != 0: res = a
	p256MovCond(&res, a, b, 1)
	if !reflect.DeepEqual(res, *a) {
		t.Errorf("cond=1: got %+v, want %+v", res, *a)
	}

	// cond < 0: res = a (should treat any nonzero as true)
	p256MovCond(&res, a, b, -123)
	if !reflect.DeepEqual(res, *a) {
		t.Errorf("cond=-123: got %+v, want %+v", res, *a)
	}
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
		t.Fatalf("p256Mul(%x, %x) = %x, want %x", x, y, resInt, expected)
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
		t.Fatalf("p256Sqr(%x) = %x, want %x", x, resInt, expected)
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

func TestP256OrdReduce(t *testing.T) {
	p256Ord := &p256OrdElement{0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff}
	// s < p256Ord
	var s1 p256OrdElement
	copy(s1[:], p256Ord[:])
	s1[0] -= 1 // s1 = p256Ord - 1
	s1Orig := s1
	p256OrdReduce(&s1)
	if s1 != s1Orig {
		t.Errorf("p256OrdReduce changed s when s < p256Ord: got %x, want %x", s1, s1Orig)
	}

	// s >= p256Ord
	var s2 p256OrdElement
	copy(s2[:], p256Ord[:])
	// s2 = p256Ord
	p256OrdReduce(&s2)
	zero := p256OrdElement{}
	if s2 != zero {
		t.Errorf("p256OrdReduce failed for s == p256Ord: got %x, want 0", s2)
	}

	// s2 = p256Ord + 1
	copy(s2[:], p256Ord[:])
	s2[0] += 1
	p256OrdReduce(&s2)
	one := p256OrdElement{1, 0, 0, 0}
	if s2 != one {
		t.Errorf("p256OrdReduce failed for s == p256Ord+1: got %x, want %x", s2, one)
	}
}

func TestP256Sub(t *testing.T) {
	// in1 > in2
	in1 := p256Element{5, 0, 0, 0}
	in2 := p256Element{3, 0, 0, 0}
	var res p256Element
	p256Sub(&res, &in1, &in2)
	want := p256Element{2, 0, 0, 0}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("in1 > in2: got %v, want %v", res, want)
	}

	// in1 == in2
	in1 = p256Element{7, 8, 9, 10}
	in2 = p256Element{7, 8, 9, 10}
	p256Sub(&res, &in1, &in2)
	want = p256Element{0, 0, 0, 0}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("in1 == in2: got %v, want %v", res, want)
	}

	// in1 < in2
	in1 = p256Element{1, 0, 0, 0}
	in2 = p256Element{2, 0, 0, 0}
	p256Sub(&res, &in1, &in2)
	// 1 - 2 mod 2^64 = 0xFFFFFFFFFFFFFFFF
	want = p256Element{0xfffffffffffffffe, 0xffffffff00000000,
		0xffffffffffffffff, 0xfffffffeffffffff}
	if !reflect.DeepEqual(res, want) {
		t.Errorf("in1 < in2: got %v, want %v", res, want)
	}
}

func p256MulBy2Test(t *testing.T, x, p, r *big.Int) {
	x1 := new(big.Int).Mul(x, r)
	x1 = x1.Mod(x1, p)
	y1 := new(big.Int).Mul(big.NewInt(2), r)
	y1 = y1.Mod(y1, p)
	ax := new(p256Element)
	res := new(p256Element)
	res2 := new(p256Element)
	fromBig(ax, x1)
	p256MulBy2(res2, ax)
	p256FromMont(res, res2)
	resInt := toBigInt(res)

	expected := new(big.Int).Mul(x, big.NewInt(2))
	expected = expected.Mod(expected, p)
	if resInt.Cmp(expected) != 0 {
		t.Fatalf("p256MulBy2(%x) = %x, want %x", x, resInt, expected)
	}
}

func TestP256MulBy2(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	r, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	p256MulBy2Test(t, pMinus1, p, r)
	p256MulBy2Test(t, big.NewInt(0), p, r)
	p256MulBy2Test(t, big.NewInt(1), p, r)
}
