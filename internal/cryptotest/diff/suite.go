// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"runtime"
	"testing"
)

// Run executes one implementation for one case. The implementation must
// treat b as its only input/output memory. Cleanup callbacks run before the
// next implementation. Run may panic; the suite captures panics as part of
// the outcome and compares them against the reference.
type Run[O any] func(t testing.TB, c Case, b *Buffers) O

// Implementation describes one implementation under differential test.
type Implementation[O any] struct {
	Name string
	Run  Run[O]
	// Available reports whether this implementation can run on the current
	// host (nil means always). It must consult real CPU features or package
	// dispatch state, never the output of a previous run.
	Available func() bool
	// Required marks implementations that must be available on the host
	// running the test. Register an implementation as required only when
	// the runner guarantees the feature (native hardware, SDE, QEMU with
	// the extension enabled); the runner fails if it is unavailable.
	Required bool
	// Primary marks the public dispatch path, i.e. the implementation that
	// users of the package get by default. It is documentation; verifying
	// which implementation the public path selected requires a
	// package-internal observability check (see docs/difftest.md).
	Primary bool
}

// CompareFunc reports whether got matches the reference want.
type CompareFunc[O any] func(got, want O) error

// SuiteOption configures a Suite.
type SuiteOption[O any] func(*Suite[O])

// WithCompare overrides the output comparison (default for ByteSuite is
// byte equality).
func WithCompare[O any](f CompareFunc[O]) SuiteOption[O] { return func(s *Suite[O]) { s.compare = f } }

// WithDiffBytes provides a raw byte view of an output for failure
// diagnostics (first-difference offset and hex dump).
func WithDiffBytes[O any](f func(O) []byte) SuiteOption[O] {
	return func(s *Suite[O]) { s.diffBytes = f }
}

// WithSrcBytes provides a byte view of the case input for failure
// diagnostics (rendered next to got/want in the hex dump).
func WithSrcBytes[O any](f func(Case) []byte) SuiteOption[O] {
	return func(s *Suite[O]) { s.srcOf = f }
}

// WithPanicContract declares the expected panic behavior per case. When the
// contract requires a panic for a case, both the reference and every
// implementation must panic with a value satisfying the expectation.
func WithPanicContract[O any](f func(Case) PanicExpectation) SuiteOption[O] {
	return func(s *Suite[O]) { s.panicContract = f }
}

// WithNormalize validates and repairs decoded cases (used by fuzzing) before
// they run; it returns false for cases that must be skipped. It has no
// effect on cases produced by Enumerate.
func WithNormalize[O any](f func(*Case) bool) SuiteOption[O] {
	return func(s *Suite[O]) { s.normalize = f }
}

// Suite runs a reference implementation and a set of implementations over a
// Domain and reports any semantic divergence. A Suite is local to the API
// shape under test; construct one per API shape, never register globally.
type Suite[O any] struct {
	refName       string
	refRun        Run[O]
	compare       CompareFunc[O]
	diffBytes     func(O) []byte
	srcOf         func(Case) []byte
	panicContract func(Case) PanicExpectation
	normalize     func(*Case) bool
	impls         []Implementation[O]
}

type executionTB struct {
	testing.TB
	cleanups []func()
}

func (t *executionTB) Cleanup(cleanup func()) {
	t.cleanups = append(t.cleanups, cleanup)
}

func (t *executionTB) cleanup() {
	for len(t.cleanups) > 0 {
		last := len(t.cleanups) - 1
		cleanup := t.cleanups[last]
		t.cleanups = t.cleanups[:last]
		cleanup()
	}
}

// NewSuite returns a Suite comparing every added implementation against
// refRun. The default comparison requires reflect-free equality via
// CompareFunc, so callers should always pass a comparison suitable for O,
// or use ByteSuite.
func NewSuite[O any](refName string, refRun Run[O], opts ...SuiteOption[O]) *Suite[O] {
	s := &Suite[O]{refName: refName, refRun: refRun}
	for _, opt := range opts {
		opt(s)
	}
	if s.compare == nil {
		panic("diff: suite without compare function; use WithCompare or ByteSuite")
	}
	return s
}

// Add registers an implementation.
func (s *Suite[O]) Add(impl Implementation[O]) { s.impls = append(s.impls, impl) }

// Run enumerates d under the current profile and executes the suite, one
// subtest per case. Tests that mutate global dispatch state inside Run
// closures must not use t.Parallel.
func (s *Suite[O]) Run(t *testing.T, d Domain) {
	t.Helper()
	for _, c := range Enumerate(d, CurrentProfile()) {
		c := c
		t.Run(c.SubtestName(), func(t *testing.T) { s.RunCase(t, c) })
	}
}

// RunCase executes the reference and every available implementation for one
// case and compares outcomes.
func (s *Suite[O]) RunCase(t testing.TB, c Case) {
	t.Helper()
	exp := PanicExpectation{}
	if s.panicContract != nil {
		exp = s.panicContract(c)
	}
	refOut, refPanicked, refPanic := s.exec(t, s.refRun, c, exp)
	if t.Failed() {
		return
	}
	for _, impl := range s.impls {
		if impl.Available != nil && !impl.Available() {
			if impl.Required {
				t.Errorf("implementation %q is marked required but is unavailable on this host (%s/%s, VLEN=%s)",
					impl.Name, runtime.GOOS, runtime.GOARCH, vlenString())
			}
			continue
		}
		out, panicked, panicVal := s.exec(t, impl.Run, c, exp)
		if t.Failed() {
			continue
		}
		switch {
		case panicked != refPanicked:
			var detail string
			if panicked {
				detail = fmt.Sprintf("implementation panicked (%v) but reference did not", panicVal)
			} else {
				detail = fmt.Sprintf("reference panicked (%v) but implementation did not", refPanic)
			}
			t.Errorf("%s", s.report(t.Name(), impl.Name, c, fmt.Errorf("%s", detail), refOut, out))
		case panicked:
			if fmt.Sprint(panicVal) != fmt.Sprint(refPanic) {
				t.Errorf("%s", s.report(t.Name(), impl.Name, c,
					fmt.Errorf("panic values differ: ref %v, impl %v", refPanic, panicVal), refOut, out))
			}
		default:
			if err := s.compare(out, refOut); err != nil {
				t.Errorf("%s", s.report(t.Name(), impl.Name, c, err, refOut, out))
			}
		}
	}
}

// exec runs one implementation with freshly materialized buffers, verifies
// the buffer guards and applies the panic contract.
func (s *Suite[O]) exec(t testing.TB, r Run[O], c Case, exp PanicExpectation) (out O, panicked bool, panicVal any) {
	t.Helper()
	b := Materialize(c)
	defer b.Verify(t, c)
	runTB := &executionTB{TB: t}
	defer runTB.cleanup()
	func() {
		defer func() {
			if v := recover(); v != nil {
				panicked = true
				panicVal = v
			}
		}()
		out = r(runTB, c, b)
	}()
	if exp.Required {
		if !panicked {
			t.Errorf("expected %s for case %s (%s), got none", exp.describe(), c.ID(), c.Descriptor())
			return out, false, nil
		}
		if err := exp.Verify(panicVal); err != nil {
			t.Errorf("case %s (%s): %v", c.ID(), c.Descriptor(), err)
		}
	}
	return out, panicked, panicVal
}

// ByteSuite returns a Suite for []byte outputs with byte equality as the
// comparison and byte-level failure diagnostics (first divergent offset plus
// capped hex dump of input, want and got).
func ByteSuite(refName string, refRun Run[[]byte], opts ...SuiteOption[[]byte]) *Suite[[]byte] {
	s := &Suite[[]byte]{
		refName: refName,
		refRun:  refRun,
		compare: func(got, want []byte) error {
			if len(got) != len(want) {
				return fmt.Errorf("output length %d, want %d", len(got), len(want))
			}
			if off := firstDiff(want, got); off >= 0 {
				return fmt.Errorf("output differs from reference at offset %d", off)
			}
			return nil
		},
	}
	s.diffBytes = func(b []byte) []byte { return b }
	s.srcOf = func(c Case) []byte {
		if len(c.Content) > 0 {
			return c.Content
		}
		return nil
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}
