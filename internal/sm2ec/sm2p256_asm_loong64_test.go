//go:build loong64 && !purego

package sm2ec

import (
	"bytes"
	"encoding/binary"
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
