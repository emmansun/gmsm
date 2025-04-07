package sm2ec

import (
	"crypto/elliptic"
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
