// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.25

package mlkem

import (
	stdmlkem "crypto/mlkem"
	"crypto/rand"
	"testing"
)

// This file compares gmsm ML-KEM performance against Go standard library
// crypto/mlkem. ML-KEM-512 is intentionally excluded because stdlib does not
// provide it.

func BenchmarkCompareKeyGen768(b *testing.B) {
	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, err := GenerateKey768(rand.Reader); err != nil {
				b.Fatalf("GenerateKey768: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			if _, err := stdmlkem.GenerateKey768(); err != nil {
				b.Fatalf("stdmlkem.GenerateKey768: %v", err)
			}
		}
	})
}

func BenchmarkCompareEncapsulate768(b *testing.B) {
	gmsmDK, err := GenerateKey768(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey768: %v", err)
	}
	gmsmEK := gmsmDK.EncapsulationKey()

	stdDK, err := stdmlkem.GenerateKey768()
	if err != nil {
		b.Fatalf("stdmlkem.GenerateKey768: %v", err)
	}
	stdEK := stdDK.EncapsulationKey()

	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, _, err := gmsmEK.Encapsulate(rand.Reader); err != nil {
				b.Fatalf("Encapsulate: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			_, _ = stdEK.Encapsulate()
		}
	})
}

func BenchmarkCompareDecapsulate768(b *testing.B) {
	gmsmDK, err := GenerateKey768(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey768: %v", err)
	}
	gmsmEK := gmsmDK.EncapsulationKey()
	_, gmsmC, err := gmsmEK.Encapsulate(rand.Reader)
	if err != nil {
		b.Fatalf("Encapsulate: %v", err)
	}

	stdDK, err := stdmlkem.GenerateKey768()
	if err != nil {
		b.Fatalf("stdmlkem.GenerateKey768: %v", err)
	}
	stdEK := stdDK.EncapsulationKey()
	_, stdC := stdEK.Encapsulate()

	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, err := gmsmDK.Decapsulate(gmsmC); err != nil {
				b.Fatalf("Decapsulate: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			if _, err := stdDK.Decapsulate(stdC); err != nil {
				b.Fatalf("stdmlkem.Decapsulate: %v", err)
			}
		}
	})
}

func BenchmarkCompareKeyGen1024(b *testing.B) {
	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, err := GenerateKey1024(rand.Reader); err != nil {
				b.Fatalf("GenerateKey1024: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			if _, err := stdmlkem.GenerateKey1024(); err != nil {
				b.Fatalf("stdmlkem.GenerateKey1024: %v", err)
			}
		}
	})
}

func BenchmarkCompareEncapsulate1024(b *testing.B) {
	gmsmDK, err := GenerateKey1024(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey1024: %v", err)
	}
	gmsmEK := gmsmDK.EncapsulationKey()

	stdDK, err := stdmlkem.GenerateKey1024()
	if err != nil {
		b.Fatalf("stdmlkem.GenerateKey1024: %v", err)
	}
	stdEK := stdDK.EncapsulationKey()

	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, _, err := gmsmEK.Encapsulate(rand.Reader); err != nil {
				b.Fatalf("Encapsulate: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			_, _ = stdEK.Encapsulate()
		}
	})
}

func BenchmarkCompareDecapsulate1024(b *testing.B) {
	gmsmDK, err := GenerateKey1024(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey1024: %v", err)
	}
	gmsmEK := gmsmDK.EncapsulationKey()
	_, gmsmC, err := gmsmEK.Encapsulate(rand.Reader)
	if err != nil {
		b.Fatalf("Encapsulate: %v", err)
	}

	stdDK, err := stdmlkem.GenerateKey1024()
	if err != nil {
		b.Fatalf("stdmlkem.GenerateKey1024: %v", err)
	}
	stdEK := stdDK.EncapsulationKey()
	_, stdC := stdEK.Encapsulate()

	b.Run("gmsm", func(b *testing.B) {
		for b.Loop() {
			if _, err := gmsmDK.Decapsulate(gmsmC); err != nil {
				b.Fatalf("Decapsulate: %v", err)
			}
		}
	})

	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			if _, err := stdDK.Decapsulate(stdC); err != nil {
				b.Fatalf("stdmlkem.Decapsulate: %v", err)
			}
		}
	})
}
