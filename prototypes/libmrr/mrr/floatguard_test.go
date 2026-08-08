package mrr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Determinism mandate: no floating point anywhere in geometry/retarget/weights.
// This is the Go analogue of the C++ CI grep + -Wdouble-promotion gate. It
// fails the build if a float type or float-producing package sneaks into a
// non-test source file in this package.
func TestNoFloatingPoint(t *testing.T) {
	banned := regexp.MustCompile(`\bfloat32\b|\bfloat64\b|"math"\b|math\.(Pow|Exp|Log|Sqrt)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if loc := banned.FindIndex(b); loc != nil {
			t.Errorf("%s: banned float/nondeterministic token near byte %d: %q",
				f, loc[0], string(b[loc[0]:loc[1]]))
		}
	}
}
