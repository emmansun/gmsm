package sm2

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

var zero = big.NewInt(0)

func toBytes(curve elliptic.Curve, value *big.Int) []byte {
	bytes := value.Bytes()
	byteLen := (curve.Params().BitSize + 7) >> 3
	if byteLen == len(bytes) {
		return bytes
	}
	result := make([]byte, byteLen)
	copy(result[byteLen-len(bytes):], bytes)
	return result
}

func point2UncompressedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	return elliptic.Marshal(curve, x, y)
}

func point2CompressedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	buffer := make([]byte, (curve.Params().BitSize+7)>>3+1)
	copy(buffer[1:], toBytes(curve, x))
	if getLastBitOfY(x, y) > 0 {
		buffer[0] = compressed03
	} else {
		buffer[0] = compressed02
	}
	return buffer
}

func point2MixedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	buffer := elliptic.Marshal(curve, x, y)
	if getLastBitOfY(x, y) > 0 {
		buffer[0] = mixed07
	} else {
		buffer[0] = mixed06
	}
	return buffer
}

func getLastBitOfY(x, y *big.Int) uint {
	if x.Cmp(zero) == 0 {
		return 0
	}
	return y.Bit(0)
}

func toPointXY(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}

func calculatePrimeCurveY(curve elliptic.Curve, x *big.Int) (*big.Int, error) {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)
	y := x3.ModSqrt(x3, curve.Params().P)

	if y == nil {
		return nil, errors.New("can't calculate y based on x")
	}
	return y, nil
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
		x := toPointXY(bytes[1 : 1+byteLen])
		y := toPointXY(bytes[1+byteLen : 1+byteLen*2])
		if !curve.IsOnCurve(x, y) {
			return nil, nil, 0, fmt.Errorf("point c1 is not on curve %s", curve.Params().Name)
		}
		return x, y, 1 + byteLen*2, nil
	case compressed02, compressed03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("invalid compressed bytes length %d", len(bytes))
		}
		if strings.HasPrefix(curve.Params().Name, "P-") || strings.EqualFold(curve.Params().Name, p256.CurveParams.Name) {
			// y² = x³ - 3x + b, prime curves
			x := toPointXY(bytes[1 : 1+byteLen])
			y, err := calculatePrimeCurveY(curve, x)
			if err != nil {
				return nil, nil, 0, err
			}

			if (getLastBitOfY(x, y) > 0 && format == compressed02) || (getLastBitOfY(x, y) == 0 && format == compressed03) {
				y.Sub(curve.Params().P, y)
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
