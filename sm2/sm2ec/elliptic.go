package sm2ec

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once

func initAll() {
	initSM2P256()
}

func P256() elliptic.Curve {
	initonce.Do(initAll)
	return sm2p256
}

// Since golang 1.19
// unmarshaler is implemented by curves with their own constant-time Unmarshal.
// There isn't an equivalent interface for Marshal/MarshalCompressed because
// that doesn't involve any mathematical operations, only FillBytes and Bit.
type unmarshaler interface {
	Unmarshal([]byte) (x, y *big.Int)
	UnmarshalCompressed([]byte) (x, y *big.Int)
}

func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	if c, ok := curve.(unmarshaler); ok {
		return c.Unmarshal(data)
	}
	return elliptic.Unmarshal(curve, data)
}

// UnmarshalCompressed converts a point, serialized by MarshalCompressed, into
// an x, y pair. It is an error if the point is not in compressed form, is not
// on the curve, or is the point at infinity. On error, x = nil.
func UnmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	if c, ok := curve.(unmarshaler); ok {
		return c.UnmarshalCompressed(data)
	}
	return elliptic.UnmarshalCompressed(curve, data)
}
