package subtle

import (
	"fmt"
	"testing"
)

func TestConstantTimeAllZero(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"all zero", args{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, 1},
		{"not all zero", args{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConstantTimeAllZero(tt.args.bytes); got != tt.want {
				t.Errorf("ConstantTimeAllZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkConstantTimeAllZero(b *testing.B) {
	data := make([]byte, 1<<15)
	sizes := []int64{1 << 3, 1 << 4, 1 << 5, 1 << 7, 1 << 11, 1 << 13, 1 << 15}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dBytes", size), func(b *testing.B) {
			s0 := data[:size]
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				ConstantTimeAllZero(s0)
			}
		})
	}
}
