// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm9

import "testing"

func TestKATSignSample(t *testing.T) {
	if err := KATSignSample(); err != nil {
		t.Fatal(err)
	}
}

func TestKATKeyExchangeSample(t *testing.T) {
	if err := KATKeyExchangeSample(); err != nil {
		t.Fatal(err)
	}
}

func TestKATWrapKeySample(t *testing.T) {
	if err := KATWrapKeySample(); err != nil {
		t.Fatal(err)
	}
}

func TestKATEncryptSample(t *testing.T) {
	if err := KATEncryptSample(); err != nil {
		t.Fatal(err)
	}
}
