//go:build (amd64 && !generic) || (arm64 && !generic)
// +build amd64,!generic arm64,!generic

package sm2ec

import (
	"fmt"
	"testing"
)

func TestP256PrecomputedTable(t *testing.T) {
	base := NewP256Point().SetGenerator()

	for i := 0; i < 43; i++ {
		t.Run(fmt.Sprintf("table[%d]", i), func(t *testing.T) {
			testP256AffineTable(t, base, &p256Precomputed[i])
		})

		for k := 0; k < 6; k++ {
			base.Double(base)
		}
	}
}

func testP256AffineTable(t *testing.T, base *P256Point, table *p256AffineTable) {
	p := NewP256Point()
	zInv := new(p256Element)
	zInvSq := new(p256Element)

	for j := 0; j < 32; j++ {
		p.Add(p, base)

		// Convert p to affine coordinates.
		p256Inverse(zInv, &p.z)
		p256Sqr(zInvSq, zInv, 1)
		p256Mul(zInv, zInv, zInvSq)

		p256Mul(&p.x, &p.x, zInvSq)
		p256Mul(&p.y, &p.y, zInv)
		p.z = p256One

		if p256Equal(&table[j].x, &p.x) != 1 || p256Equal(&table[j].y, &p.y) != 1 {
			t.Fatalf("incorrect table entry at index %d", j)
		}
	}
}
