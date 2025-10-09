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
		if out[i] != expected {
			t.Errorf("limb %d: got 0x%x, want 0x%x", i, out[i], expected)
		}
	}

	// 逆操作测试
	var back [32]byte
	p256LittleToBig(&back, &out)
	if !bytes.Equal(in[:], back[:]) {
		t.Errorf("p256LittleToBig(p256BigToLittle(...)) mismatch\nin:   %x\nback: %x", in, back)
	}
}
