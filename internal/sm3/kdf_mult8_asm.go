// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || loong64) && !purego

package sm3

import "github.com/emmansun/gmsm/internal/byteorder"

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
	k := make([]byte, limit*Size)
	ret := k

	// prepare temporary buffer
	tmpStart := parallelSize8 * blocks * BlockSize
	buffer := make([]byte, preallocSizeBy8)
	tmp := buffer[tmpStart:]
	// prepare processing data
	var dataPtrs [parallelSize8]*byte
	var data [parallelSize8][]byte
	var digs [parallelSize8]*[8]uint32
	var states [parallelSize8][8]uint32

	for j := 0; j < parallelSize8; j++ {
		digs[j] = &states[j]
		p := buffer[blocks*BlockSize*j:]
		data[j] = p
		dataPtrs[j] = &p[0]
		if j == 0 {
			prepareInitData(baseMD, p, len, t)
		} else {
			copy(p, data[0])
		}
	}

	times := limit / parallelSize8
	for i := 0; i < times; i++ {
		for j := 0; j < parallelSize8; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			byteorder.BEPutUint32(data[j][baseMD.nx:], ct)
			ct++
		}
		blockMultBy8(&digs[0], &dataPtrs[0], &tmp[0], blocks)
		copyResultsBy8(&states[0][0], &ret[0])
		ret = ret[Size*parallelSize8:]
	}

	remain := limit % parallelSize8
	if remain >= parallelSize4 {
		for j := 0; j < parallelSize4; j++ {
			// prepare states
			states[j] = baseMD.h
			// prepare data
			byteorder.BEPutUint32(data[j][baseMD.nx:], ct)
			ct++
		}
		blockMultBy4(&digs[0], &dataPtrs[0], &tmp[0], blocks)
		copyResultsBy4(&states[0][0], &ret[0])
		ret = ret[Size*parallelSize4:]
		remain -= parallelSize4
	}

	for i := range remain {
		byteorder.BEPutUint32(tmp, ct)
		md := *baseMD
		md.Write(tmp[:4])
		h := md.checkSum()
		copy(ret[i*Size:], h[:])
		ct++
	}

	return k[:keyLen]
}

//go:noescape
func blockMultBy8(dig **[8]uint32, p **byte, buffer *byte, blocks int)

//go:noescape
func transposeMatrix8x8(dig **[8]uint32)

//go:noescape
func copyResultsBy8(dig *uint32, p *byte)
