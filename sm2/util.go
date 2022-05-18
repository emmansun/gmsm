package sm2

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	result := make([]byte, byteLen)
	value.FillBytes(result)
	return result
}

func bytes2Point(curve elliptic.Curve, bytes []byte) (*big.Int, *big.Int, int, error) {
	if len(bytes) < 1+(curve.Params().BitSize/8) {
		return nil, nil, 0, fmt.Errorf("invalid bytes length %d", len(bytes))
	}
	format := bytes[0]
	byteLen := (curve.Params().BitSize + 7) >> 3
	switch format {
	case uncompressed, mixed06, mixed07: // what's the mixed format purpose?
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("invalid uncompressed bytes length %d", len(bytes))
		}
		data := make([]byte, 1+byteLen*2)
		data[0] = uncompressed
		copy(data[1:], bytes[1:1+byteLen*2])
		x, y := elliptic.Unmarshal(curve, data)
		if x == nil || y == nil {
			return nil, nil, 0, fmt.Errorf("point is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case compressed02, compressed03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("invalid compressed bytes length %d", len(bytes))
		}
		// Make sure it's NIST curve or SM2 P-256 curve
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, p256.CurveParams.Name) {
			// y² = x³ - 3x + b, prime curves
			x, y := elliptic.UnmarshalCompressed(curve, bytes[:1+byteLen])
			if x == nil || y == nil {
				return nil, nil, 0, fmt.Errorf("point is not on curve %s", curve.Params().Name)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("unsupport bytes format %d, curve %s", format, curve.Params().Name)
	}
	return nil, nil, 0, fmt.Errorf("unknown bytes format %d", format)
}

var (
	closedChanOnce sync.Once
	closedChan     chan struct{}
)

// maybeReadByte reads a single byte from r with ~50% probability. This is used
// to ensure that callers do not depend on non-guaranteed behaviour, e.g.
// assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream.
//
// This does not affect tests that pass a stream of fixed bytes as the random
// source (e.g. a zeroReader).
func maybeReadByte(r io.Reader) {
	closedChanOnce.Do(func() {
		closedChan = make(chan struct{})
		close(closedChan)
	})

	select {
	case <-closedChan:
		return
	case <-closedChan:
		var buf [1]byte
		r.Read(buf[:])
	}
}
