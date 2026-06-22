// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"errors"

	sm2internal "github.com/emmansun/gmsm/internal/sm2"
)

// SelfTest performs a known-answer test of SM2 deterministic signing and verification.
// It is a pure deterministic function: no randomness, no external dependencies.
// It returns nil on success, or an error describing the failure.
// This function is not called automatically; the application decides when to invoke it.
func SelfTest() error {
	if err := sm2internal.KATSignDeterministic(); err != nil {
		return errors.New("sm2 selftest: " + err.Error())
	}
	return nil
}
