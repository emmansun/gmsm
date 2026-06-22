// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9

import (
	"errors"

	sm9internal "github.com/emmansun/gmsm/internal/sm9"
)

// SelfTest performs known-answer tests of SM9 sign, key exchange, wrap and encrypt primitives.
// It is a pure deterministic function: no randomness, no external dependencies.
// It returns nil on success, or an error describing the failure.
// This function is not called automatically; the application decides when to invoke it.
func SelfTest() error {
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"sign", sm9internal.KATSignSample},
		{"keyex", sm9internal.KATKeyExchangeSample},
		{"wrap", sm9internal.KATWrapKeySample},
		{"encrypt", sm9internal.KATEncryptSample},
	} {
		if err := tc.fn(); err != nil {
			return errors.New("sm9 selftest: " + tc.name + ": " + err.Error())
		}
	}
	return nil
}
