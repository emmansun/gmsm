// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import "errors"

var errInsufficientSamples = errors.New("entropy: at least 1024 samples are required for startup health tests")

// RepetitionCountTest implements the repetition count test per GM/T 0105-2021
// Appendix D.2 (also SP 800-90B Section 4.4.1). It returns an error if any
// symbol is repeated C = 41 or more times in a row.
//
// This test serves as both the startup health test (上电健康测试, run on the
// first ≥1024 samples per Section 5.5.a) and the continuous health test
// (连续健康测试, run on every subsequent sample batch per Section 5.5.b).
//
// C = 1 + ⌈-log₂(α) / h⌉ = 1 + ⌈20 / 0.5⌉ = 41
// where α = 2⁻²⁰ and h = 0.5 bits per sample.
func RepetitionCountTest(samples []uint8) error {
	if len(samples) < 2 {
		return nil
	}
	x := samples[0]
	count := 1
	for _, y := range samples[1:] {
		if y == x {
			count++
			if count >= 41 {
				return errors.New("entropy: repetition count health test failed")
			}
		} else {
			x = y
			count = 1
		}
	}
	return nil
}

// AdaptiveProportionTest implements the adaptive proportion test per GM/T
// 0105-2021 Appendix D.3 (also SP 800-90B Section 4.4.2). It returns an error
// if any symbol appears C = 410 or more times in a window of W = 512 samples.
//
// Like RepetitionCountTest, this serves as both the startup and continuous
// health test (see GM/T 0105-2021 Section 5.5 and Appendix D).
//
// C ≈ 410 for α = 2⁻²⁰, W = 512, h = 0.5 bits per sample (non-binary).
func AdaptiveProportionTest(samples []uint8) error {
	var counts [256]int
	for i, x := range samples {
		counts[x]++
		if i >= 512 {
			counts[samples[i-512]]--
		}
		if counts[x] >= 410 {
			return errors.New("entropy: adaptive proportion health test failed")
		}
	}
	return nil
}
