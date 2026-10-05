// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package vendorwords guards the repository against the sign-in backends
// Steward never runs: sign-in is Ory Kratos and Ory Polis only.
package vendorwords

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Spelled in parts so this file doesn't match itself.
var retired = [][]byte{[]byte("key" + "cloak"), []byte("ll" + "dap")}

var skipDirs = map[string]bool{".git": true, ".protos": true, ".local": true}

func TestNoRetiredSignInBackends(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		lowerPath := bytes.ToLower([]byte(rel))
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lowerBody := bytes.ToLower(body)
		for _, w := range retired {
			if bytes.Contains(lowerPath, w) || bytes.Contains(lowerBody, w) {
				t.Errorf("%s names a retired sign-in backend (%s)", rel, w)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
