// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// report renders the diagnostic block for a differential mismatch. It
// contains everything needed to reproduce and locate the failure: the
// implementation and reference names, the stable case ID, the full case
// descriptor, the platform (including the RISC-V vector length where
// applicable), the exact rerun command and a capped hex dump around the
// first divergent byte.
func (s *Suite[O]) report(testName, impl string, c Case, err error, want, got O) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "differential mismatch: impl=%s ref=%s", impl, s.refName)
	if impl == s.refName {
		sb.WriteString(" (reference-vs-reference? check registration)")
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "  case: %s %s\n", c.ID(), c.Descriptor())
	fmt.Fprintf(&sb, "  env: GOOS=%s GOARCH=%s VLEN=%s\n", runtime.GOOS, runtime.GOARCH, vlenString())
	fmt.Fprintf(&sb, "  rerun: go test -run '^%s$' -args -diff.seed=%#x\n",
		escapeTestName(topLevelTestName(testName)), MasterSeed())
	fmt.Fprintf(&sb, "  error: %v\n", err)
	if s.diffBytes != nil && !DumpBuffers() {
		gotB, wantB := s.diffBytes(got), s.diffBytes(want)
		if off := firstDiff(wantB, gotB); off >= 0 {
			fmt.Fprintf(&sb, "  first difference at offset %d:\n", off)
			fmt.Fprintf(&sb, "    input %s\n", hexWindow(s.srcBytes(c), off))
			fmt.Fprintf(&sb, "    want  %s\n", hexWindow(wantB, off))
			fmt.Fprintf(&sb, "    got   %s\n", hexWindow(gotB, off))
		}
	} else if s.diffBytes != nil {
		fmt.Fprintf(&sb, "  want: %x\n", s.diffBytes(want))
		fmt.Fprintf(&sb, "  got:  %x\n", s.diffBytes(got))
	}
	return sb.String()
}

// srcBytes returns the materialized input bytes of a case (without
// materializing buffers when the suite has no diff accessor).
func (s *Suite[O]) srcBytes(c Case) []byte {
	if s.srcOf == nil {
		return nil
	}
	return s.srcOf(c)
}

// topLevelTestName strips the subtest path from a test name.
func topLevelTestName(name string) string {
	if i := strings.Index(name, "/"); i >= 0 {
		return name[:i]
	}
	return name
}

// escapeTestName escapes regular expression metacharacters so the name can
// be passed to go test -run.
func escapeTestName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

const hexWindowRadius = 16

// hexWindow renders up to hexWindowRadius bytes on each side of off, with
// ellipsis markers for elided parts.
func hexWindow(b []byte, off int) string {
	if len(b) == 0 {
		return "<empty>"
	}
	lo := maxInt(0, off-hexWindowRadius)
	hi := minInt(len(b), off+hexWindowRadius+1)
	var sb strings.Builder
	if lo > 0 {
		sb.WriteString("...")
	}
	sb.WriteString(fmt.Sprintf("%x", b[lo:hi]))
	if hi < len(b) {
		sb.WriteString("...")
	}
	return sb.String()
}

// vlenString renders the RISC-V vector register length for diagnostics.
func vlenString() string {
	if n := VectorLengthBits(); n != 0 {
		return strconv.Itoa(n)
	}
	return "n/a"
}
