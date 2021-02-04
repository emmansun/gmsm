package sm4

import (
	"crypto/cipher"
	"fmt"
	"unsafe"
)

// BlockSize the sm4 block size in bytes.
const BlockSize = 16

const rounds = 32

// A cipher is an instance of SM4 encryption using a particular key.
type sm4Cipher struct {
	enc []uint32
	dec []uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the SM4 key,
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, fmt.Errorf("sm4: invalid key size %d", k)
	case 16:
		break
	}
	return newCipher(key)
}

// newCipher creates and returns a new cipher.Block
// implemented in pure Go.
func newCipher(key []byte) (cipher.Block, error) {
	c := sm4Cipher{make([]uint32, rounds), make([]uint32, rounds)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *sm4Cipher) BlockSize() int { return BlockSize }

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	encryptBlockGo(c.enc, dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}
	if InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
		panic("sm4: invalid buffer overlap")
	}
	decryptBlockGo(c.dec, dst, src)
}

// AnyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func AnyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// InexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// InexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func InexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return AnyOverlap(x, y)
}
