package main

import (
	"bytes"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// linesOf returns the log lines with the message msg.
func linesOf(logs, msg string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `msg="`+msg+`"`) {
			out = append(out, line)
		}
	}
	return out
}

func wantFields(t *testing.T, line string, fields ...string) {
	t.Helper()
	for _, f := range fields {
		if !strings.Contains(" "+line+" ", " "+f+" ") {
			t.Errorf("no %s in %s", f, line)
		}
	}
}

func TestAQuietDirectionIsNamedOnlyAgainstABusyOne(t *testing.T) {
	for _, c := range []struct {
		name string
		t    assocTotals
		want string
	}{
		{"both ways", assocTotals{sent: 500, received: 5000}, ""},
		{"one in a hundred", assocTotals{sent: 50, received: 5000}, ""},
		{"upstream stopped", assocTotals{sent: 3, received: 5000}, "sent"},
		{"downstream stopped", assocTotals{sent: 5000}, "received"},
		{"a lookup", assocTotals{sent: 1}, ""},
		{"below the floor", assocTotals{received: quietFloor - 1}, ""},
		{"at the floor", assocTotals{received: quietFloor}, "sent"},
	} {
		if got := c.t.quiet(); got != c.want {
			t.Errorf("%s: quiet() = %q, want %q", c.name, got, c.want)
		}
	}
}

// A live association writes its totals once a period and nothing for a
// period that carried nothing, so a client killed in the middle of a match
// leaves what the match carried in its log (docs/plan/draft.md, Ч-9).
func TestALongAssociationReportsWhatItCarried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		logs := captureLogs(t)
		var stats assocStats
		r := startAssocReport(&stats, time.Now(), func() []any { return []any{"native_sent", 7} })

		time.Sleep(udpReportEvery + time.Second)
		if got := linesOf(logs.String(), "UDP Tunnel running"); len(got) != 0 {
			t.Fatalf("an association that carried nothing reported: %q", got)
		}

		for i := 0; i < 500; i++ {
			stats.addSent(40)
			stats.addReceived(100)
		}
		time.Sleep(udpReportEvery)
		got := linesOf(logs.String(), "UDP Tunnel running")
		if len(got) != 1 {
			t.Fatalf("%d lines after a period with traffic, want 1: %q", len(got), got)
		}
		wantFields(t, got[0], "level=INFO", "age=2m0s", "sent=500", "sent_bytes=20000",
			"received=500", "received_bytes=50000", "native_sent=7")
		if strings.Contains(got[0], "quiet=") {
			t.Errorf("a period with traffic both ways named a quiet direction: %s", got[0])
		}

		time.Sleep(udpReportEvery)
		if got := linesOf(logs.String(), "UDP Tunnel running"); len(got) != 1 {
			t.Fatalf("a period that carried nothing reported: %q", got[1:])
		}

		// The upstream stops after good periods. Over the whole association
		// it still sent half of what it got, so only the period shows it.
		for i := 0; i < 500; i++ {
			stats.addReceived(100)
		}
		time.Sleep(udpReportEvery)
		got = linesOf(logs.String(), "UDP Tunnel running")
		if len(got) != 2 {
			t.Fatalf("%d lines, want 2: %q", len(got), got)
		}
		wantFields(t, got[1], "age=4m0s", "sent=500", "received=1000", "quiet=sent")

		stats.addSent(1)
		r.stop()
		time.Sleep(2 * udpReportEvery)
		if got := linesOf(logs.String(), "UDP Tunnel running"); len(got) != 2 {
			t.Fatalf("a stopped report wrote %q", got[2:])
		}
	})
}

// udpAssociationUp is udpTunnelUp for a test that also needs the
// application's connection and the end of the handler.
func udpAssociationUp(t *testing.T) (control net.Conn, app *net.UDPConn, tunnel net.Conn, done chan struct{}) {
	t.Helper()
	control, tunnel, done = startUDPAssociate(t)
	if _, err := tunnel.Write(udpTunnelReply); err != nil {
		t.Fatalf("answering the 0x83 command: %v", err)
	}
	reply := readAppReply(t, control)
	if reply[1] != 0x00 {
		t.Fatalf("the client refused a tunnel the server accepted: reply % x", reply)
	}
	app, err := net.DialUDP("udp", nil, boundUDPPort(t, reply))
	if err != nil {
		t.Fatalf("dialing the client's UDP port: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return control, app, tunnel, done
}

func waitHandler(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the association did not end")
	}
}

// An association is meant to end by its application. One the tunnel ended
// is a warning: the client of the full tunnel logs at warn, and a match that
// lost its association said nothing there (docs/plan/draft.md, Ч-4).
func TestAnAssociationTheTunnelEndedIsAWarning(t *testing.T) {
	logs := captureLogs(t)
	_, app, tunnel, done := udpAssociationUp(t)

	question, answer := datagram("question"), datagram("the answer")
	if _, err := app.Write(question); err != nil {
		t.Fatalf("sending a datagram: %v", err)
	}
	readFrame(t, tunnel, len(question))
	if _, err := tunnel.Write(tunnelFrame(answer)); err != nil {
		t.Fatalf("answering: %v", err)
	}
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := app.Read(make([]byte, 2048)); err != nil {
		t.Fatalf("the answer never reached the application: %v", err)
	}
	_ = tunnel.Close()
	waitHandler(t, done)

	got := linesOf(logs.String(), "UDP Tunnel closed")
	if len(got) != 1 {
		t.Fatalf("%d closing lines, want 1: %q", len(got), got)
	}
	wantFields(t, got[0], "level=WARN", "closed_by=tunnel", "sent=1", "received=1",
		"sent_bytes="+strconv.Itoa(len(question)), "received_bytes="+strconv.Itoa(len(answer)))
}

func TestAnAssociationItsApplicationEndedIsNotAWarning(t *testing.T) {
	logs := captureLogs(t)
	control, app, tunnel, done := udpAssociationUp(t)

	question := datagram("question")
	if _, err := app.Write(question); err != nil {
		t.Fatalf("sending a datagram: %v", err)
	}
	readFrame(t, tunnel, len(question))
	_ = control.Close()
	waitHandler(t, done)

	got := linesOf(logs.String(), "UDP Tunnel closed")
	if len(got) != 1 {
		t.Fatalf("%d closing lines, want 1: %q", len(got), got)
	}
	wantFields(t, got[0], "level=INFO", "closed_by=application", "sent=1", "received=0")
}

// An application that stopped sending while the answers kept coming is a
// warning however it ended: that was the association re-created in the
// middle of a match, 2.4 KB up against 12 MB down.
func TestAnAssociationWithAQuietDirectionIsAWarning(t *testing.T) {
	logs := captureLogs(t)
	control, app, tunnel, done := udpAssociationUp(t)

	question := datagram("question")
	if _, err := app.Write(question); err != nil {
		t.Fatalf("sending a datagram: %v", err)
	}
	readFrame(t, tunnel, len(question))
	const answers = 3 * quietFloor
	for i := 0; i < answers; i++ {
		if _, err := tunnel.Write(tunnelFrame(datagram("state"))); err != nil {
			t.Fatalf("answering: %v", err)
		}
	}
	buf := make([]byte, 2048)
	for i := 0; i < answers; i++ {
		_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := app.Read(buf); err != nil {
			t.Fatalf("answer %d never reached the application: %v", i, err)
		}
	}
	_ = control.Close()
	waitHandler(t, done)

	got := linesOf(logs.String(), "UDP Tunnel closed")
	if len(got) != 1 {
		t.Fatalf("%d closing lines, want 1: %q", len(got), got)
	}
	wantFields(t, got[0], "level=WARN", "closed_by=application", "sent=1", "quiet=sent")
}

// The client logs JSON, where a bare time.Duration is a count of nanoseconds:
// the first closing lines of rc3 said "age":6000000000.
func TestTheAgeOfAnAssociationReadsAsADuration(t *testing.T) {
	var buf bytes.Buffer
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	logAssocClosed(assocEnd{by: endApplication}, time.Now().Add(-90*time.Second), assocTotals{}, nil)
	if !strings.Contains(buf.String(), `"age":"1m30s"`) {
		t.Errorf("no age as a duration in %s", buf.String())
	}
}
