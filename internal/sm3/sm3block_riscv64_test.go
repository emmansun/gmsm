// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build riscv64 && !purego

package sm3

import (
	"fmt"
	"testing"
)

func TestBlocktest(t *testing.T) {
	data := []byte{1,2,3,4}
	blocktest(data)
	fmt.Printf("%x", data)
}