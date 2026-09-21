// Package buildinfo answers one question at runtime: which build is this.
//
// Without it, "the fix is deployed" is a claim nobody can check on a running
// server, and a metric labelled by version has nothing to put in the label.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// version is set at link time:
//
//	go build -ldflags "-X github.com/mazixs/S5Core/internal/buildinfo.version=v1.2.3"
//
// When it is empty, Version falls back to what the Go toolchain recorded in
// the binary, so even a plain `go build` reports something usable.
var version string

// Version returns the build identity: an explicit version if one was linked
// in, otherwise the module version or the VCS revision, with a -dirty suffix
// when the tree had uncommitted changes.
func Version() string {
	if version != "" {
		return version
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var revision string
	var modified bool
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "devel"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		return revision + "-dirty"
	}
	return revision
}

// GoVersion returns the toolchain the binary was built with.
func GoVersion() string {
	return runtime.Version()
}
