// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zuc

import (
	"errors"

	zucinternal "github.com/emmansun/gmsm/internal/zuc"
)

// SelfTest performs known-answer tests for ZUC EEA (encryption) and EIA (integrity).
// It is a pure deterministic function: no randomness, no external dependencies.
// It returns nil on success, or an error describing the failure.
// This function is not called automatically; the application decides when to invoke it.
func SelfTest() error {
	if err := zucinternal.KATEEA(); err != nil {
		return errors.New("zuc selftest: " + err.Error())
	}
	if err := zucinternal.KATEIA(); err != nil {
		return errors.New("zuc selftest: " + err.Error())
	}
	return nil
}
