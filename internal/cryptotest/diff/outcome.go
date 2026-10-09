// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"strings"
)

// Outcome captures the result of one implementation execution, including
// whether it panicked. Illegal-instruction or segmentation faults from broken
// assembly terminate the test process and are handled by CI failure logs,
// not captured here.
type Outcome[O any] struct {
	Value    O
	Panicked bool
	PanicVal any
}

// PanicExpectation documents the panic contract of an execution for a case.
// Exact takes precedence over Contains, which takes precedence over Match;
// an expectation without any of them accepts any panic value but still
// requires a panic when Required is set.
type PanicExpectation struct {
	Required bool
	Exact    string
	Contains string
	Match    func(v any) bool
}

// Verify reports whether the panic value v satisfies the expectation.
func (p PanicExpectation) Verify(v any) error {
	if p.Exact != "" && fmt.Sprint(v) != p.Exact {
		return fmt.Errorf("panic value %q does not match expected %q", fmt.Sprint(v), p.Exact)
	}
	if p.Contains != "" && !strings.Contains(fmt.Sprint(v), p.Contains) {
		return fmt.Errorf("panic value %q does not contain %q", fmt.Sprint(v), p.Contains)
	}
	if p.Match != nil && !p.Match(v) {
		return fmt.Errorf("panic value %q rejected by matcher", fmt.Sprint(v))
	}
	return nil
}

func (p PanicExpectation) describe() string {
	switch {
	case p.Exact != "":
		return fmt.Sprintf("panic %q", p.Exact)
	case p.Contains != "":
		return fmt.Sprintf("panic containing %q", p.Contains)
	case p.Match != nil:
		return "panic matching matcher"
	default:
		return "a panic"
	}
}
