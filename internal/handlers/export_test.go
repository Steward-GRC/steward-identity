// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import "github.com/Bugs5382/go-log"

// SetLoggerForTest swaps the package logger and returns a restore function.
func SetLoggerForTest(l log.Logger) func() {
	prev := logger
	logger = l
	return func() { logger = prev }
}
