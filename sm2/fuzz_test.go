package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

var _ = elliptic.P256()

func TestFuzz(t *testing.T) {
	p256 := P256()
	p256Generic := p256.Params()

	var scalar1 [32]byte
	var scalar2 [32]byte
	var timeout *time.Timer

	if testing.Short() {
		timeout = time.NewTimer(10 * time.Millisecond)
	} else {
		timeout = time.NewTimer(2 * time.Second)
	}

	for {
		select {
		case <-timeout.C:
			return
		default:
		}

		io.ReadFull(rand.Reader, scalar1[:])
		io.ReadFull(rand.Reader, scalar2[:])

		x, y := p256.ScalarBaseMult(scalar1[:])
		x2, y2 := p256Generic.ScalarBaseMult(scalar1[:])

		xx, yy := p256.ScalarMult(x, y, scalar2[:])
		xx2, yy2 := p256Generic.ScalarMult(x2, y2, scalar2[:])

		if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
			t.Fatalf("ScalarBaseMult does not match reference result with scalar: %x, please report this error to https://github.com/emmansun/gmsm/issues", scalar1)
		}

		if xx.Cmp(xx2) != 0 || yy.Cmp(yy2) != 0 {
			t.Fatalf("ScalarMult does not match reference result with scalars: %x and %x, please report this error to https://github.com/emmansun/gmsm/issues", scalar1, scalar2)
		}
	}
}
