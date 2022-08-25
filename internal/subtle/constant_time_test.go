package subtle

import "testing"

func TestConstantTimeAllZero(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"all zero", args{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}, true},
		{"not all zero", args{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConstantTimeAllZero(tt.args.bytes); got != tt.want {
				t.Errorf("ConstantTimeAllZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
