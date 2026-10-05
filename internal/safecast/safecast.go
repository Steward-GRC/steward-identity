// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package safecast provides bounds-checked integer conversions. It routes
// every narrowing cast through a single audited choke point instead of
// scattered inline conversions, satisfying gosec's G115 (integer overflow)
// rule with an explicit, justified guard rather than a suppressed warning.
package safecast

import "math"

// Int32 clamps n into the int32 range before converting.
func Int32(n int) int32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n) //nosec G115 -- bounded by the guards above
	}
}

// Uint32FromInt64 clamps n into the uint32 range before converting.
func Uint32FromInt64(n int64) uint32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint32:
		return math.MaxUint32
	default:
		return uint32(n) //nosec G115 -- bounded by the guards above
	}
}

// ByteFromInt64 clamps n into the byte (uint8) range before converting.
func ByteFromInt64(n int64) byte {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint8:
		return math.MaxUint8
	default:
		return byte(n) //nosec G115 -- bounded by the guards above
	}
}
