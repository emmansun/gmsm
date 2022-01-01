//go:build arm64
// +build arm64

//go:noescape
func tblAsm(in, imm, out *byte)

func TestTblAsm(t *testing.T) {
	in := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

}