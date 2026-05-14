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

// LagPredictorTest detects sequential autocorrelation in the sample sequence.
// A lag-1 lookup-table predictor maps each observed value to the most recently
// seen successor. If the predictor is correct too often within a non-overlapping
// window of W = 512 samples, the source has predictable sequential patterns that
// are not captured by the repetition count or adaptive proportion tests.
//
// Classic failing case: an alternating source (v₀→v₁→v₀→v₁→...) passes both
// RCT (no repeated run) and APT (each value appears only W/2 times) but fails
// here because the predictor is correct for nearly every pair.
//
// Parameters are consistent with RCT and APT (h = 0.5 bits/sample, α = 2⁻²⁰):
//
//	W = 512 (non-overlapping window, same as APT)
//	C = 411 (≈ p_max × W + z_α × σ, p_max = 2^(-0.5), z_α ≈ 4.75)
//
// Inspired by the LAG predictor health test in jitterentropy-library v3
// (Stephan Müller), simplified to non-overlapping windows and uint8 samples.
func LagPredictorTest(samples []uint8) error {
	if len(samples) < 1024 {
		return errInsufficientSamples
	}
	const (
		lagW = 512
		lagC = 411
	)
	// Process each non-overlapping window of lagW samples.
	for start := 0; start+lagW <= len(samples); start += lagW {
		window := samples[start : start+lagW]

		// table[prev] = last observed successor of prev within this window.
		// initialized[prev] = whether table[prev] has been set.
		var table [256]uint8
		var initialized [256]bool
		hits := 0

		for i := 1; i < lagW; i++ {
			prev, curr := window[i-1], window[i]
			if initialized[prev] && table[prev] == curr {
				hits++
			}
			// Always update the prediction for prev.
			table[prev] = curr
			initialized[prev] = true
		}

		if hits >= lagC {
			return errors.New("entropy: lag predictor health test failed")
		}
	}
	return nil
}
