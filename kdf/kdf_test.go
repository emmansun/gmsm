package kdf

import (
	"encoding/hex"
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
		want []byte
	}{
		{"sm3 case 1", args{sm3.New(), []byte("emmansun"), 16}, []byte{112, 137, 147, 239, 19, 136, 160, 174, 66, 69, 161, 155, 182, 192, 37, 84}},
		{"sm3 case 2", args{sm3.New(), []byte("emmansun"), 32}, []byte{112, 137, 147, 239, 19, 136, 160, 174, 66, 69, 161, 155, 182, 192, 37, 84, 198, 50, 99, 62, 53, 109, 219, 152, 155, 235, 128, 79, 218, 150, 207, 212}},
		{"sm3 case 3", args{sm3.New(), []byte("emmansun"), 48}, []byte{112, 137, 147, 239, 19, 136, 160, 174, 66, 69, 161, 155, 182, 192, 37, 84, 198, 50, 99, 62, 53, 109, 219, 152, 155, 235, 128, 79, 218, 150, 207, 212, 126, 186, 79, 164, 96, 231, 178, 119, 188, 107, 76, 228, 208, 126, 212, 147}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(tt.args.md, tt.args.z, tt.args.len); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Kdf() = %v, want %v", got, tt.want)
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
