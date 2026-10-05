// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"fmt"
	"strings"
)

// errMutuallyExclusiveFlag reports a pair of flags passed together.
func errMutuallyExclusiveFlag(a, b string) error {
	return fmt.Errorf("%s and %s are mutually exclusive", a, b)
}

// errSurfaceMissingFlags names the required flags that were left out.
func errSurfaceMissingFlags(flags ...string) error {
	return fmt.Errorf("required flags missing: %s", strings.Join(flags, ", "))
}
