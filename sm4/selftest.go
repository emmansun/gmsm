// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm4

import (
	"errors"

	sm4internal "github.com/emmansun/gmsm/internal/sm4"
)

// SelfTest performs a known-answer test of the SM4 block cipher.
// It is a pure deterministic function: no randomness, no external dependencies.
// It returns nil on success, or an error describing the failure.
// This function is not called automatically; the application decides when to invoke it.
func SelfTest() error {
	if err := sm4internal.KATEncryptDecrypt(); err != nil {
		return errors.New("sm4 selftest: " + err.Error())
	}
	return nil
}
