//go:build loong64 && go1.25 && !purego

package sm2ec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
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
