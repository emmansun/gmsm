package sm2

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var zero = new(big.Int).SetInt64(0)

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
		buffer[0] = Compressed_03
	} else {
		buffer[0] = Compressed_02
	}
	return buffer
}

func point2MixedBytes(curve elliptic.Curve, x, y *big.Int) []byte {
	buffer := elliptic.Marshal(curve, x, y)
	if getLastBitOfY(x, y) > 0 {
		buffer[0] = Mixed_07
	} else {
		buffer[0] = Mixed_06
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
	case Uncompressed:
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("invalid uncompressed bytes length %d", len(bytes))
		}
		x := toPointXY(bytes[1 : 1+byteLen])
		y := toPointXY(bytes[1+byteLen : 1+byteLen*2])
		return x, y, 1 + byteLen*2, nil
	case Compressed_02, Compressed_03:
		if len(bytes) < 1+byteLen {
			return nil, nil, 0, fmt.Errorf("invalid compressed bytes length %d", len(bytes))
		}
		if strings.HasPrefix(curve.Params().Name, "P-") {
			// y² = x³ - 3x + b
			x := toPointXY(bytes[1 : 1+byteLen])
			y, err := calculatePrimeCurveY(curve, x)
			if err != nil {
				return nil, nil, 0, err
			}

			if (getLastBitOfY(x, y) > 0 && format == Compressed_02) || (getLastBitOfY(x, y) == 0 && format == Compressed_03) {
				y.Sub(curve.Params().P, y)
			}
			return x, y, 1 + byteLen, nil
		}
		return nil, nil, 0, fmt.Errorf("unsupport bytes format %d, curve %s", format, curve.Params().Name)
	case Mixed_06, Mixed_07:
		// what's the mixed format purpose?
		if len(bytes) < 1+byteLen*2 {
			return nil, nil, 0, fmt.Errorf("invalid mixed bytes length %d", len(bytes))
		}
		x := toPointXY(bytes[1 : 1+byteLen])
		y := toPointXY(bytes[1+byteLen : 1+byteLen*2])
		return x, y, 1 + byteLen*2, nil
	}
	return nil, nil, 0, fmt.Errorf("unknown bytes format %d", format)
}
