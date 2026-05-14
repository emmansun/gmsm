// Package entropy implements entropy sources and health testing for the
// software random number generator per GM/T 0105-2021.
//
// It provides multiple independent entropy sources (OS, CPU jitter, runtime noise),
// SP 800-90B health tests, and SM3-based conditioning to produce seeds for DRBG.
package entropy
