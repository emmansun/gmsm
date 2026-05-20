// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build loong64 && !purego

package mlkem

import (
	"testing"
)

// TestLASXTwiddleL5Layout validates that the Layer 5 twiddle table matches
// the actual XVILVLV/XVILVHV data layout.
func TestLASXTwiddleL5Layout(t *testing.T) {
	// For block=0: z4 = 32, groups 0..3 use zetas[32..35]
	// LASX layout after XVILVLV X10,X9,X0/XVILVHV X10,X9,X1:
	//   int16 positions [0..3] (memory bytes [0..7])   → g2 (from X10.lane0 lo) → needs zetasMontgomery[34]
	//   int16 positions [4..7] (memory bytes [8..15])  → g0 (from X9.lane0 lo)  → needs zetasMontgomery[32]
	//   int16 positions [8..11] (memory bytes [16..23])→ g3 (from X10.lane1 lo) → needs zetasMontgomery[35]
	//   int16 positions [12..15](memory bytes [24..31])→ g1 (from X9.lane1 lo)  → needs zetasMontgomery[33]
	for block := 0; block < 8; block++ {
		base4 := block * 16
		z4 := 32 + block*4
		for i := 0; i < 4; i++ {
			if nttTwiddleL4PrecompLASX[base4+i] != zetasMontgomery[z4+2] {
				t.Errorf("block=%d [%d] (g2): got %v, want %v", block, base4+i,
					nttTwiddleL4PrecompLASX[base4+i], zetasMontgomery[z4+2])
			}
			if nttTwiddleL4PrecompLASX[base4+4+i] != zetasMontgomery[z4] {
				t.Errorf("block=%d [%d] (g0): got %v, want %v", block, base4+4+i,
					nttTwiddleL4PrecompLASX[base4+4+i], zetasMontgomery[z4])
			}
			if nttTwiddleL4PrecompLASX[base4+8+i] != zetasMontgomery[z4+3] {
				t.Errorf("block=%d [%d] (g3): got %v, want %v", block, base4+8+i,
					nttTwiddleL4PrecompLASX[base4+8+i], zetasMontgomery[z4+3])
			}
			if nttTwiddleL4PrecompLASX[base4+12+i] != zetasMontgomery[z4+1] {
				t.Errorf("block=%d [%d] (g1): got %v, want %v", block, base4+12+i,
					nttTwiddleL4PrecompLASX[base4+12+i], zetasMontgomery[z4+1])
			}
		}
	}
}

// TestLASXTwiddleL6Layout validates that the Layer 6 twiddle table matches
// the actual XVSHUF4IW+XVILVLV/XVILVHV data layout.
func TestLASXTwiddleL6Layout(t *testing.T) {
	// For block=0: z2=64, groups 0..7 use zetas[64..71]
	// LASX layout after XVSHUF4IW+XVILVLV X12,X11,X0/XVILVHV X12,X11,X1:
	//   [0..3]  (g4,g5 from X10.lane0 lo) → z4v=z2+4, z5=z2+5
	//   [4..7]  (g0,g1 from X9.lane0 lo)  → z0=z2+0, z1=z2+1
	//   [8..11] (g6,g7 from X10.lane1 lo) → z6=z2+6, z7=z2+7
	//   [12..15](g2,g3 from X9.lane1 lo)  → z2v=z2+2, z3=z2+3
	for block := 0; block < 8; block++ {
		base2 := block * 16
		z2 := 64 + block*8
		checks := []struct {
			pos   int
			want  fieldElement
			label string
		}{
			{0, zetasMontgomery[z2+4], "g4"},
			{1, zetasMontgomery[z2+4], "g4"},
			{2, zetasMontgomery[z2+5], "g5"},
			{3, zetasMontgomery[z2+5], "g5"},
			{4, zetasMontgomery[z2+0], "g0"},
			{5, zetasMontgomery[z2+0], "g0"},
			{6, zetasMontgomery[z2+1], "g1"},
			{7, zetasMontgomery[z2+1], "g1"},
			{8, zetasMontgomery[z2+6], "g6"},
			{9, zetasMontgomery[z2+6], "g6"},
			{10, zetasMontgomery[z2+7], "g7"},
			{11, zetasMontgomery[z2+7], "g7"},
			{12, zetasMontgomery[z2+2], "g2"},
			{13, zetasMontgomery[z2+2], "g2"},
			{14, zetasMontgomery[z2+3], "g3"},
			{15, zetasMontgomery[z2+3], "g3"},
		}
		for _, c := range checks {
			if nttTwiddleL2PrecompLASX[base2+c.pos] != c.want {
				t.Errorf("block=%d pos=%d (%s): got %v, want %v",
					block, c.pos, c.label,
					nttTwiddleL2PrecompLASX[base2+c.pos], c.want)
			}
		}
	}
}
