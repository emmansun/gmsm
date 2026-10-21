//go:build (amd64 || arm64 || loong64 || riscv64 || s390x || ppc64le) && !purego

// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2ec

import (
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest/vectors"
	"github.com/emmansun/gmsm/internal/deps/cpu"
)

// TestP256KernelVectors replays the constructed kernel-boundary vectors
// against both the BMI2 and the generic multiplication path.
//
// The FieldMul cases pin the exact Montgomery product at the straddling carry
// windows where the pre-fix ADOX reduction chain silently corrupted the result
// (issue #560, about one failure per 2^33 multiplications, so random
// differential fuzzing cannot reach them). The FieldSqr cases pin the
// Montgomery squaring path on the same operands.
func TestP256KernelVectors(t *testing.T) {
	suite, err := vectors.Load("sm2ec_p256_mul_bmi2.json")
	if err != nil {
		t.Fatal(err)
	}

	for _, typ := range []string{"FieldMul", "FieldSqr"} {
		group, err := suite.Group(typ)
		if err != nil {
			t.Fatal(err)
		}
		ok, missing, err := group.Requires(runtime.GOARCH, map[string]bool{
			"adx":  cpu.X86.HasADX,
			"bmi2": cpu.X86.HasBMI2,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Skipf("%s: group requires %v", typ, missing)
		}

		for _, tc := range group.Tests {
			aBE, err := vectors.DecodeHex32(tc.A)
			if err != nil {
				t.Fatalf("%s tc%d: %v", typ, tc.TCID, err)
			}
			wantBE, err := vectors.DecodeHex32(tc.Expected)
			if err != nil {
				t.Fatalf("%s tc%d: %v", typ, tc.TCID, err)
			}
			var a, b, want p256Element
			p256BigToLittle(&a, &aBE)
			p256BigToLittle(&want, &wantBE)
			if tc.B != "" {
				bBE, err := vectors.DecodeHex32(tc.B)
				if err != nil {
					t.Fatalf("%s tc%d: %v", typ, tc.TCID, err)
				}
				p256BigToLittle(&b, &bBE)
			}

			for _, path := range []struct {
				name string
				bmi2 bool
			}{{"generic", false}, {"bmi2", true}} {
				old := supportBMI2
				supportBMI2 = path.bmi2

				var got p256Element
				switch typ {
				case "FieldMul":
					p256Mul(&got, &a, &b)
				case "FieldSqr":
					p256Sqr(&got, &a, 1)
				}

				supportBMI2 = old
				if got != want {
					t.Errorf("%s tc%d (%s, %s): got %016x%016x%016x%016x, want %016x%016x%016x%016x",
						typ, tc.TCID, path.name, tc.Comment,
						got[3], got[2], got[1], got[0],
						want[3], want[2], want[1], want[0])
				}
			}
		}
	}
}
