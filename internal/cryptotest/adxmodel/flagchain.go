// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package adxmodel

import "strings"

// Finding reports one ADOXQ instruction whose OF input cannot be traced to the
// ADOX chain or to an instruction that clears the flags. Such an instruction
// consumes semantics it did not produce; that is exactly the defect class of
// issue #560, where the reduction chain's first ADOXQ read the signed-overflow
// OF left behind by the SBB borrow chain.
type Finding struct {
	// Line is the 1-based line number of the ADOXQ.
	Line int
	// Text is the trimmed instruction text.
	Text string
	// Producer describes the instruction that last wrote OF, or "" when the
	// chain starts at a TEXT boundary and the incoming OF is undefined.
	Producer string
	// ProducerLine is the 1-based line number of the producer.
	ProducerLine int
}

// ofProducer classifies how the tracked instruction affects OF.
type ofProducer int

const (
	ofUnknown ofProducer = iota // TEXT entry: OF inherited from the caller
	ofAdox                      // ADOXQ: the chain's own carry
	ofZero                      // logical op: clears OF
	ofArith                     // arithmetic/flag-writing instruction: foreign OF
)

// flagZeroOps clear both CF and OF.
var flagZeroOps = map[string]bool{
	"XORQ": true, "XORL": true, "XORW": true, "XORB": true,
	"ANDQ": true, "ANDL": true, "ANDW": true, "ANDB": true,
	"ORQ": true, "ORL": true, "ORW": true, "ORB": true,
	"TESTQ": true, "TESTL": true, "TESTW": true, "TESTB": true,
}

// arithOps write OF with signed arithmetic semantics, which is not what an
// ADOX carry chain expects.
var arithOps = map[string]bool{
	"ADDQ": true, "ADDL": true, "ADDW": true, "ADDB": true,
	"ADCQ": true, "ADCL": true, "ADCW": true, "ADCB": true,
	"SUBQ": true, "SUBL": true, "SUBW": true, "SUBB": true,
	"SBBQ": true, "SBBL": true, "SBBW": true, "SBBB": true,
	"CMPQ": true, "CMPL": true, "CMPW": true, "CMPB": true,
	"INCQ": true, "INCL": true, "INCW": true, "INCB": true,
	"DECQ": true, "DECL": true, "DECW": true, "DECB": true,
	"NEGQ": true, "NEGL": true, "NEGW": true, "NEGB": true,
	"IMULQ": true, "IMULL": true, "MULQ": true, "MULL": true,
	"SHLQ": true, "SHLL": true, "SHLW": true, "SHLB": true,
	"SHRQ": true, "SHRL": true, "SHRW": true, "SHRB": true,
	"SARQ": true, "SARL": true, "SARW": true, "SARB": true,
	"RCLQ": true, "RCRQ": true,
	"POPFQ": true, "POPFL": true,
}

// CheckADOXChains scans assembly source for ADOXQ instructions that read an OF
// value written by an unrelated instruction. It is a text-level dataflow check
// over the OF channel: MOV/MULX/CMOV/LEA/Jcc do not write flags and are
// transparent, ADCX writes only CF, and SUB/SBB/SHL/SHR/ADD write the signed
// overflow OF.
//
// The check is deliberately conservative at TEXT boundaries: an ADOXQ reached
// with no prior flag writer in the same function consumes caller-defined OF,
// which is reported as well. Labels are treated as transparent; that is sound
// for the straight-line carry chains used in this repository but should be
// revisited if a kernel starts receiving OF through a branch.
func CheckADOXChains(src []byte) []Finding {
	var findings []Finding
	last := ofUnknown
	lastOp := ""
	lastLine := 0

	for i, raw := range strings.Split(string(src), "\n") {
		lineNo := i + 1
		line := raw
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "TEXT") {
			last, lastOp, lastLine = ofUnknown, "", 0
			continue
		}
		op := line
		if idx := strings.IndexAny(op, " \t"); idx >= 0 {
			op = op[:idx]
		}
		if strings.HasSuffix(op, ":") || strings.HasPrefix(op, "#") || op == "\\" {
			continue
		}
		op = strings.ToUpper(op)

		if op == "ADOXQ" {
			if last == ofArith || last == ofUnknown {
				findings = append(findings, Finding{
					Line:         lineNo,
					Text:         line,
					Producer:     lastOp,
					ProducerLine: lastLine,
				})
			}
			last, lastOp, lastLine = ofAdox, op, lineNo
			continue
		}
		switch {
		case flagZeroOps[op]:
			last, lastOp, lastLine = ofZero, op, lineNo
		case arithOps[op]:
			last, lastOp, lastLine = ofArith, op, lineNo
		}
		// ADCXQ and flag-transparent instructions leave the OF producer
		// unchanged.
	}
	return findings
}
