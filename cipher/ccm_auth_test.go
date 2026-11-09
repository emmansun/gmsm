package cipher

import (
	"bytes"
	"testing"
)

type recordingBlock struct {
	calls [][]byte
}

func (b *recordingBlock) BlockSize() int { return ccmBlockSize }

func (b *recordingBlock) Encrypt(dst, src []byte) {
	b.calls = append(b.calls, append([]byte(nil), src...))
	copy(dst, src)
}

func (b *recordingBlock) Decrypt(dst, src []byte) {
	copy(dst, src)
}

func TestCCMAADLengthEncoding(t *testing.T) {
	tests := []struct {
		name   string
		length int
		prefix []byte
	}{
		{name: "two-byte", length: 0xfeff, prefix: []byte{0xfe, 0xff}},
		{name: "six-byte", length: 0xff00, prefix: []byte{0xff, 0xfe, 0x00, 0x00, 0xff, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := new(recordingBlock)
			c := &ccm{cipher: block, nonceSize: 12, tagSize: 16}
			var tagMask [ccmBlockSize]byte
			c.auth(make([]byte, c.nonceSize), nil, make([]byte, tt.length), &tagMask)

			if len(block.calls) < 2 {
				t.Fatalf("got %d block-cipher calls, want at least 2", len(block.calls))
			}
			var want [ccmBlockSize]byte
			want[0] = 0x7a
			for i, b := range tt.prefix {
				want[i] ^= b
			}
			if !bytes.Equal(block.calls[1], want[:]) {
				t.Errorf("first AAD MAC input = %x, want %x", block.calls[1], want)
			}
		})
	}
}
