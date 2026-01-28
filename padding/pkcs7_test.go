// https://datatracker.ietf.org/doc/html/rfc5652#section-6.3

package padding

import (
	"reflect"
	"testing"
)

func Test_pkcs7Padding_Pad(t *testing.T) {
	pkcs7 := NewPKCS7Padding(16)

	tests := []struct {
		name string
		src  []byte
		want []byte
	}{
		{"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}},
		{"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}},
		{"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 2, 2}},
		{"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 3, 3}},
		{"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 4, 4, 4, 4}},
		{"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 5, 5, 5, 5, 5}},
		{"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 6, 6, 6, 6, 6, 6}},
		{"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7, 7, 7, 7, 7}},
		{"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}},
		{"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 9, 9, 9, 9, 9, 9, 9, 9, 9}},
		{"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}},
		{"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}},
		{"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}},
		{"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13}},
		{"2 bytes", []byte{0, 1}, []byte{0, 1, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14}},
		{"1 bytes", []byte{0}, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pkcs7.Pad(tt.src); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkcs7Padding.Pad() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkcs7Padding_Unpad(t *testing.T) {
	pkcs7 := NewPKCS7Padding(16)
	tests := []struct {
		name    string
		want    []byte
		src     []byte
		wantErr bool
	}{
		{"16 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}, false},
		{"15 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1}, false},
		{"14 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 2, 2}, false},
		{"13 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 3, 3, 3}, false},
		{"12 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 4, 4, 4, 4}, false},
		{"11 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 5, 5, 5, 5, 5}, false},
		{"10 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 6, 6, 6, 6, 6, 6}, false},
		{"9 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 7, 7, 7, 7, 7, 7, 7}, false},
		{"8 bytes", []byte{0, 1, 2, 3, 4, 5, 6, 7}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8}, false},
		{"7 bytes", []byte{0, 1, 2, 3, 4, 5, 6}, []byte{0, 1, 2, 3, 4, 5, 6, 9, 9, 9, 9, 9, 9, 9, 9, 9}, false},
		{"6 bytes", []byte{0, 1, 2, 3, 4, 5}, []byte{0, 1, 2, 3, 4, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, false},
		{"5 bytes", []byte{0, 1, 2, 3, 4}, []byte{0, 1, 2, 3, 4, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11}, false},
		{"4 bytes", []byte{0, 1, 2, 3}, []byte{0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12}, false},
		{"3 bytes", []byte{0, 1, 2}, []byte{0, 1, 2, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13}, false},
		{"2 bytes", []byte{0, 1}, []byte{0, 1, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14}, false},
		{"1 bytes", []byte{0}, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}, false},
		{"invalid src length", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}, true},
		{"invalid padding byte", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 17}, true},
		{"inconsistent padding bytes", nil, []byte{0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 14, 15}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkcs7.Unpad(tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("pkcs7Padding.Unpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkcs7Padding.Unpad() = %v, want %v", got, tt.want)
			}

			got, err = pkcs7.ConstantTimeUnpad(tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("pkcs7Padding.ConstantTimeUnpad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pkcs7Padding.ConstantTimeUnpad() = %v, want %v", got, tt.want)
			}
		})
	}
}
