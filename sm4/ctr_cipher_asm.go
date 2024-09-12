//go:build (amd64 || arm64) && !purego

package sm4

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/internal/alias"
	"github.com/emmansun/gmsm/internal/subtle"
)

// Assert that sm4CipherAsm implements the ctrAble interface.
var _ ctrAble = (*sm4CipherAsm)(nil)

type ctr struct {
	b       *sm4CipherAsm
	ctr     []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512

// NewCTR returns a Stream which encrypts/decrypts using the SM4 block
// cipher in counter mode. The length of iv must be the same as BlockSize.
func (c *sm4CipherAsm) NewCTR(iv []byte) cipher.Stream {
	if len(iv) != BlockSize {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < BlockSize {
		bufSize = BlockSize
	}
	s := &ctr{
		b:       c,
		ctr:     make([]byte, c.blocksSize),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
	copy(s.ctr, iv)
	for i := 1; i < c.batchBlocks; i++ {
		s.genCtr(i * BlockSize)
	}
	return s

}

func (x *ctr) genCtr(start int) {
	if start >= BlockSize {
		copy(x.ctr[start:], x.ctr[start-BlockSize:start])
	} else {
		copy(x.ctr[0:], x.ctr[len(x.ctr)-BlockSize:])
	}
	// Increment counter
	buffer := x.ctr[start : start+BlockSize]
	for i := BlockSize - 1; i >= 0; i-- {
		buffer[i]++
		if buffer[i] != 0 {
			break
		}
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	for remain <= len(x.out)-x.b.blocksSize {
		encryptBlocksAsm(&x.b.enc[0], x.out[remain:], x.ctr, INST_AES)

		remain += x.b.blocksSize

		// Generate complelte [x.b.batchBlocks] counters
		for i := 0; i < x.b.batchBlocks; i++ {
			x.genCtr(i * BlockSize)
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-BlockSize {
			x.refill()
		}
		n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}
