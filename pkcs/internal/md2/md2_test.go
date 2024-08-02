package md2

import (
	"bytes"
	"encoding"
	"fmt"
	"io"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest"
)

type md2Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []md2Test{
	{"8350e5a3e24c153df2275c9f80692773", "", "md2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"32ec01ec4a6dac72c0ab96fb34c0b5d1", "a", "md2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"da853b0d3f88d99b30283a69e6ded6bb", "abc", "md2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"ab4f496bfb2a530b219ff33031fe06b0", "message digest", "md2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00message\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\a"},
	{"4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz", "md2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00abcdefghijklm\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r"},
	{"da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "md2\x01\xa3k\x01X\x1a\xe6\x01\xfc\xe9\x8eH\xb5>\x8b:\xf9ho\x8a\xb1\x8f\xe1\xaf\xe4\xc5\x02¨Xs\xbb\xf8QRSTUVWXYZabcde\x00\x00\x00\x00\x00\x00\x00\x00\x1f"},
	{"d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "md2\x01\x8d\xd7h\x84\x8b1\x19E\x92\xcfA\xd3\x00k\x83\xfa\xd1\xeb\xb3\\\xe8S\xac6:$j\x93\xe8=\x03\x8534567890\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00("},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", Sum([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum function: md2(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		buf := make([]byte, len(g.in)+4)
		for j := 0; j < 3+4; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else if j == 2 {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			} else if j > 2 {
				// test unaligned write
				buf = buf[1:]
				copy(buf, g.in)
				c.Write(buf[:len(g.in)])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("md2[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

type binaryAppender interface {
	// AppendBinary appends the binary representation of itself to the end of b
	// (allocating a larger slice if necessary) and returns the updated slice.
	//
	// Implementations must not retain b, nor mutate any bytes within b[:len(b)].
	AppendBinary(b []byte) ([]byte, error)
}

func TestGoldenMarshal(t *testing.T) {
	for _, g := range golden {
		h := New()
		h2 := New()

		io.WriteString(h, g.in[:len(g.in)/2])

		state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			continue
		}

		stateAppend, err := h.(binaryAppender).AppendBinary(make([]byte, 4, 32))
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			continue
		}
		stateAppend = stateAppend[4:]

		if string(state) != g.halfState {
			t.Errorf("md2(%q) state = %q, want %q", g.in, state, g.halfState)
			continue
		}

		if string(stateAppend) != g.halfState {
			t.Errorf("md2(%q) stateAppend = %q, want %q", g.in, stateAppend, g.halfState)
			continue
		}

		if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			t.Errorf("could not unmarshal: %v", err)
			continue
		}

		io.WriteString(h, g.in[len(g.in)/2:])
		io.WriteString(h2, g.in[len(g.in)/2:])

		if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
			t.Errorf("md2(%q) = 0x%x != marshaled 0x%x", g.in, actual, actual2)
		}
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
}

func TestMD2Hash(t *testing.T) {
	t.Run("MD2", func(t *testing.T) {
		cryptotest.TestHash(t, New)
	})
}

func TestAllocations(t *testing.T) {
	in := []byte("hello, world!")
	out := make([]byte, 0, Size)
	h := New()
	n := int(testing.AllocsPerRun(10, func() {
		h.Reset()
		h.Write(in)
		out = h.Sum(out[:0])
	}))
	if n > 0 {
		t.Errorf("allocs = %d, want 0", n)
	}
}
