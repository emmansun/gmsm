package kdf

import (
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestKdf(t *testing.T) {
	type args struct {
		md  hash.Hash
		z   []byte
		len int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sm3 case 1", args{sm3.New(), []byte("emmansun"), 16}, "708993ef1388a0ae4245a19bb6c02554"},
		{"sm3 case 2", args{sm3.New(), []byte("emmansun"), 32}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd4"},
		{"sm3 case 3", args{sm3.New(), []byte("emmansun"), 48}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"},
		{"sm3 case 4", args{sm3.New(), []byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f"},
		{"sm3 case 5", args{sm3.New(), []byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 128}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb"},
	}
	for _, tt := range tests {
		wantBytes, _ := hex.DecodeString(tt.want)
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(tt.args.md, tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v) = %x, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestKdfOldCase(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result := Kdf(sm3.New(), append(x2.Bytes(), y2.Bytes()...), 19)

	resultStr := hex.EncodeToString(result)

	if expected != resultStr {
		t.Fatalf("expected %s, real value %s", expected, resultStr)
	}
}

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() { _ = recover() }()
	f()
	t.Errorf("should have panicked")
}

// This case should be failed on 32bits system.
func TestKdfPanic(t *testing.T) {
	shouldPanic(t, func() {
		Kdf(sm3.New(), []byte("123456"), 1<<37)
	})
}

func BenchmarkKdf(b *testing.B) {
	tests := []struct {
		zLen int
		kLen int
	}{
		{32, 32},
		{32, 64},
		{32, 128},
		{64, 32},
		{64, 64},
		{64, 128},
		{440, 32},
	}
	sm3Hash := sm3.New()
	z := make([]byte, 512)
	for _, tt := range tests {
		b.Run(fmt.Sprintf("zLen=%v-kLen=%v", tt.zLen, tt.kLen), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(sm3Hash, z[:tt.zLen], tt.kLen)
			}
		})
	}
}
