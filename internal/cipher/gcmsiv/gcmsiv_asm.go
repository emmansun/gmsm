// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build (amd64 || arm64) && !purego

package cipher

import "github.com/emmansun/gmsm/internal/cpuid"

// supportPolyvalAsm is true when the CPU has CMUL.
var supportPolyvalAsm = cpuid.HasGFMUL

// polyvalAsmTable is a 256-byte Karatsuba-precomputed hash table for the
// CMUL POLYVAL implementation.  The layout is identical to gcmSm4Data's
// productTable so the multiply loop can be shared:
//
//	offsets 16*14, 16*15 → H^1  and its Karatsuba precomp (H[0]^H[1])
//	offsets 16*12, 16*13 → H^2  and its Karatsuba precomp
//	...
//	offsets 16*0,  16*1  → H^8  and its Karatsuba precomp
type polyvalAsmTable [256]byte

// polyvalTableInit builds the Karatsuba product table from the 16-byte POLYVAL
// authentication key h (little-endian byte order, as returned by
// deriveMessageKeys).
//
//go:noescape
func polyvalTableInitAsm(h *[16]byte, table *polyvalAsmTable)

// polyvalBlocksUpdate processes len(blocks)/16 complete 16-byte blocks,
// updating the accumulator y in-place.  blocks must be a multiple of 16 bytes.
//
//go:noescape
func polyvalBlocksUpdateAsm(table *polyvalAsmTable, y *[16]byte, blocks []byte)

// computePolyval runs POLYVAL(authKey, aad‖plaintext‖lengthBlock) and returns
// the 16-byte result.  Uses PCLMULQDQ when available, otherwise falls back to
// the pure-Go path.
func computePolyval(authKey [16]byte, aad, plaintext []byte, lengthBlock [16]byte) (s [16]byte) {
	if !supportPolyvalAsm {
		return computePolyvalGeneric(authKey, aad, plaintext, lengthBlock)
	}

	// POLYVAL elements are already in natural polynomial bit order (bit 0 = x^0),
	// which matches PCLMULQDQ's convention directly.  Pass authKey as-is;
	// polyvalTableInit loads it without any byte-reversal.
	var table polyvalAsmTable
	polyvalTableInitAsm(&authKey, &table)

	// Process each input segment.  Blocks are passed as-is; polyvalBlocksUpdate
	// loads them with plain MOVOU (no PSHUFB), XORs with the accumulator, and
	// multiplies in the POLYVAL field.
	var y [16]byte
	polyvalAsmUpdatePadded(&table, &y, aad)
	polyvalAsmUpdatePadded(&table, &y, plaintext)
	polyvalBlocksUpdateAsm(&table, &y, lengthBlock[:])

	// y is already in POLYVAL output format:
	//   y[0:8]  = LE(lower 64 polynomial bits)  matches finalizePolyval s[0:8]
	//   y[8:16] = LE(upper 64 polynomial bits)  matches finalizePolyval s[8:16]
	return y
}

// polyvalAsmUpdatePadded processes data through the PCLMULQDQ path.
// Blocks are passed directly without any byte-reversal.
func polyvalAsmUpdatePadded(table *polyvalAsmTable, y *[16]byte, data []byte) {
	if full := len(data) &^ 15; full > 0 {
		polyvalBlocksUpdateAsm(table, y, data[:full])
	}
	if rem := len(data) % 16; rem != 0 {
		var block [16]byte
		copy(block[:], data[len(data)-rem:])
		polyvalBlocksUpdateAsm(table, y, block[:])
	}
}
