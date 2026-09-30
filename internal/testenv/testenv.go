// Copyright 2026 The gmsm Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package testenv provides test environment helpers adapted from the Go tree.
package testenv

import "os"

// HasExternalNetwork reports whether tests may access the external network.
func HasExternalNetwork() bool {
	return os.Getenv("GO_TEST_EXTERNAL_NETWORK") == "1"
}
