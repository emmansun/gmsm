package fiat_test

import (
	"testing"

	"github.com/emmansun/gmsm/internal/sm2ec/fiat"
)

func BenchmarkMul(b *testing.B) {
	v := new(fiat.SM2P256Element).One()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.Mul(v, v)
	}
}

func BenchmarkSquare(b *testing.B) {
	v := new(fiat.SM2P256Element).One()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.Square(v)
	}
}
