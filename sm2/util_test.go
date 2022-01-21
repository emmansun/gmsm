package sm2

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
)

func Test_toBytes(t *testing.T) {
	type args struct {
		value string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"less than 32", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "00d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
		{"equals 32", args{"58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := new(big.Int).SetString(tt.args.value, 16)
			if got := toBytes(elliptic.P256(), v); !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("toBytes() = %v, want %v", hex.EncodeToString(got), tt.want)
			}
		})
	}
}

func Test_getLastBitOfY(t *testing.T) {
	type args struct {
		y string
	}
	tests := []struct {
		name string
		args args
		want uint
	}{
		// TODO: Add test cases.
		{"0", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, 0},
		{"1", args{"d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865ff"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y, _ := new(big.Int).SetString(tt.args.y, 16)
			if got := getLastBitOfY(y, y); got != tt.want {
				t.Errorf("getLastBitOfY() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_toPointXY(t *testing.T) {
	type args struct {
		bytes string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"has zero padding", args{"00d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
		{"no zero padding", args{"58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"}, "58d20d27d0632957f8028c1e024f6b02edf23102a566c932ae8bd613a8e865fe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, _ := hex.DecodeString(tt.args.bytes)
			expectedInt, _ := new(big.Int).SetString(tt.want, 16)
			if got := toPointXY(bytes); !reflect.DeepEqual(got, expectedInt) {
				t.Errorf("toPointXY() = %v, want %v", got, expectedInt)
			}
		})
	}
}
