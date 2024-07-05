package md2

import (
	"fmt"
	"testing"
)

type md2Test struct {
	out string
	in  string
}

var golden = []md2Test{
	{"8350e5a3e24c153df2275c9f80692773", ""},
	{"32ec01ec4a6dac72c0ab96fb34c0b5d1", "a"},
	{"da853b0d3f88d99b30283a69e6ded6bb", "abc"},
	{"ab4f496bfb2a530b219ff33031fe06b0", "message digest"},
	{"4e8ddff3650292ab5a4108c3aa47940b", "abcdefghijklmnopqrstuvwxyz"},
	{"da33def2a42df13975352846c30338cd", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"},
	{"d5976f79d83d3a0dc9806c3c66f3efd8", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		h := Sum([]byte(g.in))
		s := fmt.Sprintf("%x", h)
		if s != g.out {
			t.Fatalf("MD2 function: md2(%s) = %s want %s", g.in, s, g.out)
		}
	}
}
