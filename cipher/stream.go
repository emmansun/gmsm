// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher

import "crypto/cipher"

type SeekableStream interface {
	cipher.Stream
	// XORKeyStreamAt XORs the given src with the key stream at the given offset and writes the result to dst.
	XORKeyStreamAt(dst, src []byte, offset uint64)
}
