//go:build !integration

package gateway

import (
	"os"
	"strings"
	"testing"
)

// TestMain clears PANW_* variables so unit tests are hermetic: they must pass
// the same whether or not the developer has live credentials exported. The
// integration suite (build tag "integration") deliberately keeps them.
func TestMain(m *testing.M) {
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, "PANW_") {
			_ = os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}
