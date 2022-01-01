//go:build arm64
// +build arm64

//go:noescape
func tblAsm(in, imm, out *byte)

func TestTblAsm(t *testing.T) {
	in := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	imm := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	out := make([]byte, 16)
	tblAsm(&in[0], &imm[0], &out[0])
	if !reflect.DeepEqual(out, imm) {
		t.Errorf("expected=%v, result=%v\n", imm, out)
	}
}