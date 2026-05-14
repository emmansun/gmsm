// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import (
	"bytes"
	"testing"
)

func TestRepetitionCountTest_Pass(t *testing.T) {
	// Normal data with no long repeats should pass
	samples := make([]uint8, 1024)
	for i := range samples {
		samples[i] = uint8(i % 256)
	}
	if err := RepetitionCountTest(samples); err != nil {
		t.Errorf("RepetitionCountTest failed on normal data: %v", err)
	}
}

func TestRepetitionCountTest_Fail(t *testing.T) {
	// 41 consecutive identical values should fail
	samples := make([]uint8, 1024)
	for i := range samples {
		samples[i] = uint8(i % 256)
	}
	// Insert 41 consecutive zeros
	for i := 100; i < 141; i++ {
		samples[i] = 0
	}
	if err := RepetitionCountTest(samples); err == nil {
		t.Error("RepetitionCountTest should have failed on 41 consecutive identical values")
	}
}

func TestRepetitionCountTest_BarelyPass(t *testing.T) {
	// 40 consecutive identical values should pass (threshold is 41)
	samples := make([]uint8, 1024)
	for i := range samples {
		samples[i] = uint8(i % 256)
	}
	for i := 100; i < 140; i++ {
		samples[i] = 42
	}
	// Make sure surrounding values are different
	samples[99] = 41
	samples[140] = 43
	if err := RepetitionCountTest(samples); err != nil {
		t.Errorf("RepetitionCountTest should pass with 40 repeats: %v", err)
	}
}

func TestRepetitionCountTest_Empty(t *testing.T) {
	if err := RepetitionCountTest(nil); err != nil {
		t.Errorf("RepetitionCountTest should pass on nil: %v", err)
	}
	if err := RepetitionCountTest([]uint8{}); err != nil {
		t.Errorf("RepetitionCountTest should pass on empty: %v", err)
	}
}

func TestAdaptiveProportionTest_Pass(t *testing.T) {
	// Well-distributed data should pass
	samples := make([]uint8, 1024)
	for i := range samples {
		samples[i] = uint8(i % 256)
	}
	if err := AdaptiveProportionTest(samples); err != nil {
		t.Errorf("AdaptiveProportionTest failed on normal data: %v", err)
	}
}

func TestAdaptiveProportionTest_Fail(t *testing.T) {
	// All same value should fail (410 out of 512 in any window)
	samples := bytes.Repeat([]byte{0x42}, 1024)
	if err := AdaptiveProportionTest(samples); err == nil {
		t.Error("AdaptiveProportionTest should have failed on constant data")
	}
}

func TestAdaptiveProportionTest_HighlyBiased(t *testing.T) {
	// 410 out of 512 same value in a window should fail
	samples := make([]uint8, 1024)
	for i := range samples {
		samples[i] = 0 // all zeros
	}
	// Sprinkle some variety in first part to delay failure
	for i := 0; i < 103; i++ {
		samples[i] = uint8(i%255) + 1
	}
	if err := AdaptiveProportionTest(samples); err == nil {
		t.Error("AdaptiveProportionTest should have failed on highly biased data")
	}
}

func TestAdaptiveProportionTest_Empty(t *testing.T) {
	if err := AdaptiveProportionTest(nil); err != nil {
		t.Errorf("AdaptiveProportionTest should pass on nil: %v", err)
	}
	if err := AdaptiveProportionTest([]uint8{}); err != nil {
		t.Errorf("AdaptiveProportionTest should pass on empty: %v", err)
	}
}
