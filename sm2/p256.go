package sm2

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

type p256Curve struct {
	*elliptic.CurveParams
}

var (
	p256     p256Curve
	initonce sync.Once
)

func initP256() {
	p256.CurveParams = &elliptic.CurveParams{Name: "P-256/SM2"}
	p256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	p256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	p256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	p256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	p256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	p256.BitSize = 256
}

// P256 init and return the singleton
func P256() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}
