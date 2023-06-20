package sm3

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"testing"

	"golang.org/x/sys/cpu"
)

type sm3Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []sm3Test{
	{"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "abc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 "},
	{"952eb84cacee9c10bde4d6882d29d63140ba72af6fe485085095dccd5b872453", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03s\x80\x16oI\x14\xb2\xb9\x17$B\xd7ڊ\x06\x00\xa9o0\xbc\x1618\xaa\xe3\x8d\xeeM\xb0\xfb\x0eNabcdabcdabcdabcdabcdabcdabcdabcda\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"},
	{"e1c53f367a9c5d19ab6ddd30248a7dafcc607e74e6bcfa52b00e0ba35e470421", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc", "sm3\x03YPށF\x86d\xebB\xfdL\x86\x1e|\xa0\n\xc0\xa5\x91\v\xae\x9aU\xea\x1aۍ\x17v<\xa2\"a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00A"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		h := Sum([]byte(g.in))
		s := fmt.Sprintf("%x", h)
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(h[:]))
		if s != g.out {
			t.Fatalf("SM3 function: sm3(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		for j := 0; j < 3; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else {
				io.WriteString(c, g.in[0:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("sm3[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		gold    []sm3Test
	}{
		{"", New, golden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, g := range tt.gold {
				h := tt.newHash()
				h2 := tt.newHash()

				io.WriteString(h, g.in[:len(g.in)/2])

				state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Errorf("could not marshal: %v", err)
					continue
				}

				if string(state) != g.halfState {
					t.Errorf("sm3%s(%q) state = %q, want %q", tt.name, g.in, state, g.halfState)
					continue
				}

				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
					t.Errorf("could not unmarshal: %v", err)
					continue
				}

				io.WriteString(h, g.in[len(g.in)/2:])
				io.WriteString(h2, g.in[len(g.in)/2:])

				if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
					t.Errorf("sm3%s(%q) = 0x%x != marshaled 0x%x", tt.name, g.in, actual, actual2)
				}
			}
		})
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
	fmt.Printf("ARM64 has sm3 %v, has sm4 %v, has aes %v\n", cpu.ARM64.HasSM3, cpu.ARM64.HasSM4, cpu.ARM64.HasAES)
}

var bench = New()
var benchSH256 = sha256.New()
var buf = make([]byte, 8192)

func benchmarkSize(hash hash.Hash, b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		hash.Reset()
		hash.Write(buf[:size])
		hash.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(bench, b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(bench, b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(bench, b, 8192)
}

func BenchmarkHash8K_SH256(b *testing.B) {
	benchmarkSize(benchSH256, b, 8192)
}

/*
func round1(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = %s ^ %s ^ %s + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, c, d, i, i+4)
	fmt.Printf("tt2 = %s ^ %s ^ %s + %s + ss1 + w[%d]\n", e, f, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func round2(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("w[%d] = p1(w[%d]^w[%d]^bits.RotateLeft32(w[%d], 15)) ^ bits.RotateLeft32(w[%d], 7) ^ w[%d]\n", i+4, i-12, i-5, i+1, i-9, i-2)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = %s ^ %s ^ %s + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, c, d, i, i+4)
	fmt.Printf("tt2 = %s ^ %s ^ %s + %s + ss1 + w[%d]\n", e, f, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func round3(a, b, c, d, e, f, g, h string, i int) {
	fmt.Printf("//Round %d\n", i+1)
	fmt.Printf("w[%d] = p1(w[%d]^w[%d]^bits.RotateLeft32(w[%d], 15)) ^ bits.RotateLeft32(w[%d], 7) ^ w[%d]\n", i+4, i-12, i-5, i+1, i-9, i-2)
	fmt.Printf("tt2 = bits.RotateLeft32(%s, 12)\n", a)
	fmt.Printf("ss1 = bits.RotateLeft32(tt2+%s+_K[%d], 7)\n", e, i)
	fmt.Printf("%s = (%s & %s) | (%s & %s) | (%s & %s) + %s + (ss1 ^ tt2) + (w[%d] ^ w[%d])\n", d, a, b, a, c, b, c, d, i, i+4)
	fmt.Printf("tt2 = (%s & %s) | (^%s & %s) + %s + ss1 + w[%d]\n", e, f, e, g, h, i)
	fmt.Printf("%s = bits.RotateLeft32(%s, 9)\n", b, b)
	fmt.Printf("%s = bits.RotateLeft32(%s, 19)\n", f, f)
	fmt.Printf("%s = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)\n\n", h)
}

func TestGenerateBlock(t *testing.T) {
	round1("a", "b", "c", "d", "e", "f", "g", "h", 0)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 1)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 2)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 3)

	round1("a", "b", "c", "d", "e", "f", "g", "h", 4)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 5)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 6)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 7)

	round1("a", "b", "c", "d", "e", "f", "g", "h", 8)
	round1("d", "a", "b", "c", "h", "e", "f", "g", 9)
	round1("c", "d", "a", "b", "g", "h", "e", "f", 10)
	round1("b", "c", "d", "a", "f", "g", "h", "e", 11)

	round2("a", "b", "c", "d", "e", "f", "g", "h", 12)
	round2("d", "a", "b", "c", "h", "e", "f", "g", 13)
	round2("c", "d", "a", "b", "g", "h", "e", "f", 14)
	round2("b", "c", "d", "a", "f", "g", "h", "e", 15)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 16)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 17)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 18)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 19)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 20)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 21)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 22)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 23)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 24)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 25)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 26)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 27)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 28)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 29)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 30)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 31)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 32)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 33)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 34)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 35)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 36)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 37)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 38)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 39)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 40)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 41)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 42)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 43)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 44)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 45)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 46)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 47)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 48)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 49)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 50)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 51)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 52)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 53)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 54)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 55)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 56)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 57)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 58)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 59)

	round3("a", "b", "c", "d", "e", "f", "g", "h", 60)
	round3("d", "a", "b", "c", "h", "e", "f", "g", 61)
	round3("c", "d", "a", "b", "g", "h", "e", "f", 62)
	round3("b", "c", "d", "a", "f", "g", "h", "e", 63)
}

func TestGenerateT(t *testing.T) {
	for i := 0; i < 16; i++ {
		fmt.Printf("0x%x, ", bits.RotateLeft32(_T0, i))
	}
	fmt.Println()
	for i := 16; i < 64; i++ {
		fmt.Printf("0x%x, ", bits.RotateLeft32(_T1, i))
	}
	fmt.Println()
}
*/
