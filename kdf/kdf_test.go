package kdf

import (
	"crypto/sha256"
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
			if got := Kdf(sm3.New, tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v) = %x, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestKdfOldCase(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result := Kdf(sm3.New, append(x2.Bytes(), y2.Bytes()...), 19)

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

func TestKdfWithSHA256(t *testing.T) {
	type args struct {
		z   []byte
		len int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sha256 case 1", args{[]byte("emmansun"), 16}, "1bca7e7d05a858f5852a6e0ce7e99852"},
		{"sha256 case 2", args{[]byte("emmansun"), 32}, "1bca7e7d05a858f5852a6e0ce7e9985294ebdc82c7f1c6539f89356d9c0a2856"},
		{"sha256 case 3", args{[]byte("emmansun"), 48}, "1bca7e7d05a858f5852a6e0ce7e9985294ebdc82c7f1c6539f89356d9c0a28569500417f9b74de4ea18a85813b8968ba"},
		{"sha256 case 4", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48}, "61cc5b862a0a6511b3558536112c7ba4f21c9d65025505c0099bbba7196a35ed34d7805e5c4d779fcd0d950f693ec0f8"},
		{"sha256 case 5", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 128}, "61cc5b862a0a6511b3558536112c7ba4f21c9d65025505c0099bbba7196a35ed34d7805e5c4d779fcd0d950f693ec0f8b1fdc996e97eadb5b7bee7ac44dd1a7954a44dd92c71c465f4ab20479c92748f179bd03bdad1768c65b59d62a0735dcf08837a04f32f53d45b5bdb00f5fd1bee003f6fcc01c003594d33014161862030"},
	}
	for _, tt := range tests {
		wantBytes, _ := hex.DecodeString(tt.want)
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(sha256.New, tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v) = %x, want %v", tt.name, got, tt.want)
			}
		})
	}
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
		{64, 256},
		{64, 512},
		{64, 1024},
	}
	z := make([]byte, 512)
	for _, tt := range tests {
		b.Run(fmt.Sprintf("zLen=%v-kLen=%v", tt.zLen, tt.kLen), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(sm3.New, z[:tt.zLen], tt.kLen)
			}
		})
	}
}
