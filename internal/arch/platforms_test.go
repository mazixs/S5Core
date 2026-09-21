package arch

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// F09 in docs/reports/code-quality-audit-2026-09-20.md: both binaries named
// syscall.SIGUSR1, which does not exist on Windows. Nothing said so until a
// tag was pushed, because CI builds on Linux and the release workflow builds
// Windows in the job *after* the one that pushes the Docker image. The
// release was therefore half published before the failure was known.
//
// This test is the missing statement: every platform the release workflow
// promises a binary for must compile. The list is read out of the workflow
// rather than written here, because two lists is how they drift - a platform
// added to the release and not to the test is exactly the case that got us
// here.

var releaseBuild = regexp.MustCompile(`GOOS=(\w+)\s+GOARCH=(\w+)\s+go build`)

type platform struct{ goos, goarch string }

// promisedPlatforms reads the release workflow and returns the platforms it
// builds binaries for.
func promisedPlatforms(t *testing.T) []platform {
	t.Helper()

	workflow := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	body, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read %s: %v", workflow, err)
	}

	seen := map[platform]bool{}
	for _, m := range releaseBuild.FindAllStringSubmatch(string(body), -1) {
		seen[platform{goos: m[1], goarch: m[2]}] = true
	}
	if len(seen) == 0 {
		t.Fatalf("%s promises no binaries; either the workflow changed shape or this test stopped reading it", workflow)
	}

	out := make([]platform, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].goos != out[j].goos {
			return out[i].goos < out[j].goos
		}
		return out[i].goarch < out[j].goarch
	})
	return out
}

func TestEveryPlatformTheReleasePromisesCompiles(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiles both binaries for every released platform")
	}

	platforms := promisedPlatforms(t)
	// The host's own platform is built by every other test in the tree; the
	// ones worth the seconds are the ones nothing else compiles.
	t.Logf("release promises %d platforms", len(platforms))

	for _, p := range platforms {
		t.Run(p.goos+"/"+p.goarch, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command("go", "build", "-o", os.DevNull, "./cmd/...")
			cmd.Dir = filepath.Join("..", "..")
			cmd.Env = append(os.Environ(),
				"GOOS="+p.goos,
				"GOARCH="+p.goarch,
				"CGO_ENABLED=0",
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("the release workflow builds %s/%s, but it does not compile:\n%s",
					p.goos, p.goarch, strings.TrimSpace(string(out)))
			}
		})
	}
}
