// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import (
	"errors"

	sm3internal "github.com/emmansun/gmsm/internal/sm3"
)

// SelfTest performs known-answer tests of the SM3 hash function.
// It is a pure deterministic function: no randomness, no external dependencies.
// It returns nil on success, or an error describing the failure.
// This function is not called automatically; the application decides when to invoke it.
func SelfTest() error {
	if err := sm3internal.KATHash(); err != nil {
		return errors.New("sm3 selftest: " + err.Error())
	}
	if err := sm3internal.KATBlock(); err != nil {
		return errors.New("sm3 selftest: " + err.Error())
	}
	if err := sm3internal.KATIncremental(); err != nil {
		return errors.New("sm3 selftest: " + err.Error())
	}
	return nil
}
