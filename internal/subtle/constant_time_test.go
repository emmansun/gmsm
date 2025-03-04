package subtle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestConstantTimeLessOrEqBytes(t *testing.T) {
	r := rand.Reader
	for l := 0; l < 20; l++ {
		a := make([]byte, l)
		b := make([]byte, l)
		empty := make([]byte, l)
		r.Read(a)
		r.Read(b)
		exp := 0
		if bytes.Compare(a, b) <= 0 {
			exp = 1
		}
		if got := ConstantTimeLessOrEqBytes(a, b); got != exp {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want %d", a, b, got, exp)
		}
		exp = 0
		if bytes.Compare(b, a) <= 0 {
			exp = 1
		}
		if got := ConstantTimeLessOrEqBytes(b, a); got != exp {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want %d", b, a, got, exp)
		}
		if got := ConstantTimeLessOrEqBytes(empty, a); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", empty, a, got)
		}
		if got := ConstantTimeLessOrEqBytes(empty, b); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", empty, b, got)
		}
		if got := ConstantTimeLessOrEqBytes(a, a); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", a, a, got)
		}
		if got := ConstantTimeLessOrEqBytes(b, b); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", b, b, got)
		}
		if got := ConstantTimeLessOrEqBytes(empty, empty); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", empty, empty, got)
		}
		if l == 0 {
			continue
		}
		max := make([]byte, l)
		for i := range max {
			max[i] = 0xff
		}
		if got := ConstantTimeLessOrEqBytes(a, max); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", a, max, got)
		}
		if got := ConstantTimeLessOrEqBytes(b, max); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", b, max, got)
		}
		if got := ConstantTimeLessOrEqBytes(empty, max); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", empty, max, got)
		}
		if got := ConstantTimeLessOrEqBytes(max, max); got != 1 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", max, max, got)
		}
		aPlusOne := make([]byte, l)
		copy(aPlusOne, a)
		for i := l - 1; i >= 0; i-- {
			if aPlusOne[i] == 0xff {
				aPlusOne[i] = 0
				continue
			}
			aPlusOne[i]++
			if got := ConstantTimeLessOrEqBytes(a, aPlusOne); got != 1 {
				t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 1", a, aPlusOne, got)
			}
			if got := ConstantTimeLessOrEqBytes(aPlusOne, a); got != 0 {
				t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 0", aPlusOne, a, got)
			}
			break
		}
		shorter := make([]byte, l-1)
		copy(shorter, a)
		if got := ConstantTimeLessOrEqBytes(a, shorter); got != 0 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 0", a, shorter, got)
		}
		if got := ConstantTimeLessOrEqBytes(shorter, a); got != 0 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 0", shorter, a, got)
		}
		if got := ConstantTimeLessOrEqBytes(b, shorter); got != 0 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 0", b, shorter, got)
		}
		if got := ConstantTimeLessOrEqBytes(shorter, b); got != 0 {
			t.Errorf("ConstantTimeLessOrEqBytes(%x, %x) = %d, want 0", shorter, b, got)
		}
	}
}

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
