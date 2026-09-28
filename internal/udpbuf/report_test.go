package udpbuf

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestTheReportNamesTheCeilingToRaise(t *testing.T) {
	for _, tc := range []struct {
		got  Got
		err  error
		want string
	}{
		{Got{Bytes: 2 * Want, Full: true, Limit: 4 << 20}, nil, `level=INFO msg="UDP receive buffer" bytes=4194304`},
		{Got{Bytes: 425984, Limit: 212992}, nil, `level=WARN msg="UDP receive buffer below what answer bursts need, set net.core.rmem_max=2097152 on the host" bytes=425984 rmem_max=212992`},
		{Got{}, errors.New("no socket"), `level=WARN msg="UDP receive buffer unknown" error="no socket"`},
	} {
		var out bytes.Buffer
		report(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{
			ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				}
				return a
			},
		})), tc.got, tc.err)
		if line := strings.TrimSpace(out.String()); line != tc.want {
			t.Errorf("logged\n\t%s\nwant\n\t%s", line, tc.want)
		}
	}
}
