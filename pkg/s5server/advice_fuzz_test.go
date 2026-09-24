package s5server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// adviceSpellings writes an accepted advice back in the two syntaxes
// TRANSPORT_ADVICE allows: key=value pairs separated by spaces, and the
// transport as a bare word with commas and tabs between the fields.
func adviceSpellings(a obfs.Advice) []string {
	var fields []string
	if a.WSMinFrame > 0 {
		fields = append(fields, fmt.Sprintf("min_frame=%d", a.WSMinFrame), fmt.Sprintf("max_frame=%d", a.WSMaxFrame))
	}
	if a.WSMaxJitterMs > 0 {
		fields = append(fields, fmt.Sprintf("jitter_ms=%d", a.WSMaxJitterMs))
	}
	if a.MaxPadding > 0 {
		fields = append(fields, fmt.Sprintf("padding=%d", a.MaxPadding))
	}
	if a.KeepaliveMin > 0 {
		fields = append(fields, fmt.Sprintf("keepalive=%s-%s", a.KeepaliveMin, a.KeepaliveMax))
	}
	keyed, bare := fields, fields
	if a.Transport != "" {
		keyed = append([]string{"transport=" + a.Transport}, fields...)
		bare = append([]string{a.Transport}, fields...)
	}
	return []string{strings.Join(keyed, " "), strings.Join(bare, ",\t")}
}

// FuzzParseTransportAdvice reads arbitrary TRANSPORT_ADVICE values - the
// setting, and since F19 the file an operator edits on a live server:
//   - blank is no advice, and anything else is either an error or an advice
//     that names something;
//   - an accepted advice is inside the bounds the parser documents: a
//     transport the client can be sent to, a frame band given as a pair with
//     min <= max in 1..65535, jitter up to 60 s, padding up to 4096, and a
//     keepalive range of whole seconds in 1s..1h with the top not below the
//     bottom;
//   - written back in either syntax it parses to the same advice;
//   - validateAdvice refuses it exactly when it names a transport the server
//     does not listen on.
func FuzzParseTransportAdvice(f *testing.F) {
	for _, s := range []string{
		"ws",
		"transport=ws min_frame=512 max_frame=2048 jitter_ms=5 padding=128 keepalive=10s-20s",
		"transport=ws min_frame=1 max_frame=65535 jitter_ms=60000 padding=4096 keepalive=1s-3600s",
		"obfs,padding=1,\tkeepalive=1m0s-1h0m0s",
		"ws obfs",
		"transport=ws transport=obfs",
		"min_frame=10 max_frame=5",
		"min_frame=10",
		"keepalive=1500ms-2s",
		"keepalive=20s-10s",
		"jitter_ms=-1",
		"frames=1",
		" , ",
		"",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		a, err := ParseTransportAdvice(raw)
		again, err2 := ParseTransportAdvice(raw)
		if (err == nil) != (err2 == nil) || (a == nil) != (again == nil) || (a != nil && *a != *again) {
			t.Fatalf("%q parsed twice differently", raw)
		}
		if strings.TrimSpace(raw) == "" {
			if a != nil || err != nil {
				t.Fatalf("blank %q gave %+v, %v", raw, a, err)
			}
			return
		}
		if err != nil {
			if a != nil {
				t.Fatalf("a refusal returned %+v", a)
			}
			return
		}
		if a == nil || *a == (obfs.Advice{}) {
			t.Fatalf("%q was accepted as no advice", raw)
		}

		switch a.Transport {
		case "", TransportObfs, TransportWS:
		default:
			t.Fatalf("accepted transport %q", a.Transport)
		}
		if (a.WSMinFrame > 0) != (a.WSMaxFrame > 0) || a.WSMinFrame < 0 || a.WSMinFrame > a.WSMaxFrame || a.WSMaxFrame > 65535 {
			t.Fatalf("accepted a frame band %d-%d", a.WSMinFrame, a.WSMaxFrame)
		}
		if a.WSMaxJitterMs < 0 || a.WSMaxJitterMs > 60_000 || a.MaxPadding < 0 || a.MaxPadding > 4096 {
			t.Fatalf("accepted jitter %d and padding %d", a.WSMaxJitterMs, a.MaxPadding)
		}
		lo, hi := a.KeepaliveMin, a.KeepaliveMax
		if (lo > 0) != (hi > 0) || lo%time.Second != 0 || hi%time.Second != 0 || lo > hi || hi > time.Hour ||
			(lo > 0 && lo < time.Second) {
			t.Fatalf("accepted keepalive %s-%s", lo, hi)
		}

		for _, s := range adviceSpellings(*a) {
			back, err := ParseTransportAdvice(s)
			if err != nil || back == nil || *back != *a {
				t.Fatalf("%q parsed as %+v, written back as %q it parses as %+v (err=%v)", raw, *a, s, back, err)
			}
		}

		both := Config{TransportAdvice: raw, ObfsEnabled: true, WSEnabled: true}
		if err := validateAdvice(both); err != nil {
			t.Fatalf("a server with every listener refused %q: %v", raw, err)
		}
		if err := validateAdvice(Config{TransportAdvice: raw}); (err == nil) != (a.Transport == "") {
			t.Fatalf("a server without listeners, advice to %q: err=%v", a.Transport, err)
		}
	})
}

// referenceVersion is sanitizeVersion written the other way round: the
// allowed bytes are all ASCII, so a version is its allowed bytes in order,
// cut to 32.
func referenceVersion(v string) string {
	var out []byte
	for i := 0; i < len(v) && len(out) < maxVersionLength; i++ {
		c := v[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".-_+", c) >= 0 {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return versionUnknown
	}
	return string(out)
}

// FuzzVersionLabels feeds one server a sequence of client-chosen versions
// (split on NUL) and holds the fence on the client_version label to what
// docs/design/observability-policy.md records:
//   - every label is 1 to 32 characters of the build-identifier alphabet;
//   - a label is the sanitized version, or "other" once 32 builds are named;
//   - at most 32 distinct names, plus "unknown" and "other", are ever
//     emitted, and a build keeps the label it was first given.
func FuzzVersionLabels(f *testing.F) {
	var many []string
	for i := range maxVersionLabels + 8 {
		many = append(many, fmt.Sprintf("v1.%d.0", i))
	}
	f.Add([]byte(strings.Join(many, "\x00") + "\x00v1.3.0\x00other\x00unknown\x00"))
	f.Add([]byte("v2.2.0\x00v2.2.0+dirty\x00<script>\x00\xff\xfe\x00версия"))
	f.Add([]byte(strings.Repeat("v", 100)))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, stream []byte) {
		var v versionLabels
		first := map[string]string{}
		named := map[string]struct{}{}
		for _, version := range strings.Split(string(stream), "\x00") {
			label := v.label(version)
			want := referenceVersion(version)
			if got := sanitizeVersion(version); got != want {
				t.Fatalf("sanitizeVersion(%q) = %q, want %q", version, got, want)
			}
			if label != want && label != versionOther {
				t.Fatalf("%q was labelled %q, want %q or %q", version, label, want, versionOther)
			}
			if len(label) == 0 || len(label) > maxVersionLength || referenceVersion(label) != label {
				t.Fatalf("the label %q is outside the alphabet or the length", label)
			}
			if prev, ok := first[want]; ok && prev != label {
				t.Fatalf("build %q was labelled %q and then %q", want, prev, label)
			}
			first[want] = label
			if label != versionOther && label != versionUnknown {
				named[label] = struct{}{}
			}
			if len(named) > maxVersionLabels {
				t.Fatalf("%d builds are named, the fence is %d", len(named), maxVersionLabels)
			}
		}
	})
}
