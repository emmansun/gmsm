// https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining

package padding

import (
	"reflect"
	"testing"
)

func Test_ansiX923Padding_Pad(t *testing.T) {
	x923 := NewANSIX923Padding(16)
	tests := []struct {
		name string
		src  []byte
		want []byte
	}{
		{"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}},
		{"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}},
		{"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2}},
		{"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 3}},
		{"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 4}},
		{"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 5}},
		{"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 6}},
		{"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 7}},
		{"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 8}},
		{"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 9}},
		{"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}},
		{"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11}},
		{"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}},
		{"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13}},
		{"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14}},
		{"1 bytes", []byte{0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := x923.Pad(tt.src); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ansiX923Padding.Pad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ansiX923Padding_Unpad(t *testing.T) {
	x923 := NewANSIX923Padding(16)
	tests := []struct {
		name    string
		want    []byte
		src     []byte
		wantErr bool
	}{
		{"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}, false},
		{"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}, false},
		{"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2}, false},
		{"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 3}, false},
		{"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0, 0, 0, 4}, false},
		{"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 5}, false},
		{"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 6}, false},
		{"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 7}, false},
		{"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 8}, false},
		{"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 9}, false},
		{"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, false},
		{"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11}, false},
		{"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12}, false},
		{"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13}, false},
		{"2 bytes", []byte{0, 1}, []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14}, false},
		{"1 bytes", []byte{0}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}, false},
		{"invalid src length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15}, true},
		{"invalid padding length", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17}, true},
		{"invalid padding bytes", nil, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 15}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := x923.Unpad(tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ansiX923Padding.Unpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ansiX923Padding.Unpad() = %v, want %v", got, tt.want)
			}
		})
	}
}
