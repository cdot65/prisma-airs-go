//go:build integration

// Package testutil provides shared test helpers for integration tests.
package testutil

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// LoadEnv reads a .env file and sets environment variables.
// Lines starting with # and blank lines are skipped.
// Values may be optionally quoted with single or double quotes.
func LoadEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Strip surrounding quotes
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if err := os.Setenv(key, val); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// ProjectRoot returns the root of the prisma-airs-go project by walking up from this file.
func ProjectRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// testutil/env.go -> aisec/internal/testutil -> aisec/internal -> aisec -> project root
	return filepath.Join(filepath.Dir(filename), "..", "..", "..")
}

// RequireEnv skips the test if any of the given environment variables are empty.
func RequireEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if os.Getenv(k) == "" {
			t.Skipf("skipping: %s not set", k)
		}
	}
}

// LoadProjectEnv loads the .env file from the project root.
func LoadProjectEnv(t *testing.T) {
	t.Helper()
	envPath := filepath.Join(ProjectRoot(), ".env")
	if err := LoadEnv(envPath); err != nil {
		t.Logf("warning: could not load .env: %v", err)
	}
}
