//go:build !purego

package sm3

import "encoding/binary"

// p || state || words
// p = 64 * 8 * 2 = 1024
// state = 8 * 32 = 256
// words = 68 * 32 = 2176
const preallocSizeBy8 = 3456

const parallelSize8 = 8

func kdfBy8(baseMD *digest, keyLen int, limit int) []byte {
	var t uint64
	blocks := 1
	len := baseMD.len + 4
	remainlen := len % 64
	if remainlen < 56 {
		t = 56 - remainlen
	} else {
		t = 64 + 56 - remainlen
		blocks = 2
	}
	len <<= 3

	var ct uint32 = 1
	k := make([]byte, keyLen)
	ret := k

	// prepare temporary buffer
	tmpStart := parallelSize8 * blocks * BlockSize
	buffer := make([]byte, preallocSizeBy8)
	tmp := buffer[tmpStart:]
	// prepare processing data
	var data [parallelSize8]*byte
	var digs [parallelSize8]*[8]uint32
	var states [parallelSize8][8]uint32
	for j := 0; j < parallelSize8; j++ {
		digs[j] = &states[j]
	}

	times := limit / parallelSize8
	for i := 0; i < times; i++ {
		for j := 0; j < parallelSize8; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			p := buffer[blocks*BlockSize*j:]
			data[j] = &p[0]
			prepareData(baseMD, p, ct, len, t)
			ct++
		}
		blockMultBy8(&digs[0], &data[0], &tmp[0], blocks)
		for j := 0; j < parallelSize8; j++ {
			copyResult(ret, digs[j])
			ret = ret[Size:]
		}
	}

	remain := limit % parallelSize8
	if remain >= 4 {
		for j := 0; j < 4; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			p := buffer[blocks*BlockSize*j:]
			data[j] = &p[0]
			prepareData(baseMD, p, ct, len, t)
			ct++
		}
		blockMultBy4(&digs[0], &data[0], &tmp[0], blocks)
		for j := 0; j < 4; j++ {
			copyResult(ret, digs[j])
			ret = ret[Size:]
		}
		remain -= 4
	}

	for i := 0; i < remain; i++ {
		binary.BigEndian.PutUint32(tmp[:], ct)
		md := *baseMD
		md.Write(tmp[:4])
		h := md.checkSum()
		copy(ret[i*Size:], h[:])
		ct++
	}

	return k
}

//go:noescape
func blockMultBy8(dig **[8]uint32, p **byte, buffer *byte, blocks int)

//go:noescape
func transposeMatrix8x8(dig **[8]uint32)
