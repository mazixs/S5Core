package logging

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// JournalBuffer is how much the journal holds before it writes: one write(2)
// per 64 KiB, or per FlushInterval when the traffic is lighter.
const JournalBuffer = 64 << 10

// FlushInterval bounds how long a line waits in the buffer.
const FlushInterval = time.Second

// Journal is the session journal: one JSON line per event, written into a
// buffer under a mutex by the goroutine the event happened on. There is no
// writer goroutine and no channel - on one core a channel lost most of a burst
// (docs/research/logging.md, 2.2) - and a line costs a copy into the buffer.
//
// A failed write never reaches the caller. The lines it did not finish are
// counted as dropped, and the next line is preceded by a log_gap marker saying
// how many were lost, so a gap in seq always has its explanation in the file.
// A write that stopped inside a line leaves that piece on a line of its own:
// the marker starts on a new line, so every line after it parses.
type Journal struct {
	file io.WriteCloser
	boot string

	mu  sync.Mutex
	buf []byte
	// ends and levels describe the lines in buf: where each one ends and its
	// index in JournalLevels.
	ends   []int
	levels []uint8
	seq    uint64
	gap    uint64 // dropped since the last line that made it into buf
	// torn is set when the file ends inside a line a failed write left.
	torn   bool
	closed bool
	line   Line

	lines   [2]atomic.Uint64
	dropped atomic.Uint64

	stop chan struct{}
	done chan struct{}
}

// NewJournal starts a journal over w and its flush ticker. boot names this
// process in the marker lines; empty draws one.
func NewJournal(w io.WriteCloser, boot string) *Journal {
	if boot == "" {
		boot = NewBoot()
	}
	j := &Journal{
		file:   w,
		boot:   boot,
		buf:    make([]byte, 0, JournalBuffer+4096),
		ends:   make([]int, 0, 512),
		levels: make([]uint8, 0, 512),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go j.flushLoop()
	return j
}

// NewBoot is 8 hex digits from crypto/rand: the epoch of one process.
func NewBoot() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Boot is the epoch this journal writes under.
func (j *Journal) Boot() string { return j.boot }

// JournalLevels names the levels a journal line takes, in the order Lines
// counts them.
func JournalLevels() []string { return []string{"info", "warn"} }

// Lines counts the lines of one level that reached the file, Dropped the
// lines that were lost.
func (j *Journal) Lines(level int) uint64 { return j.lines[level].Load() }
func (j *Journal) Dropped() uint64        { return j.dropped.Load() }

// Every journal of the process together, for s5core_log_lines_total and
// s5core_log_dropped_total: a metric is per process, and a scrape sees zeroes
// before the first journal opens.
var (
	journalLines   [2]atomic.Uint64
	journalDropped atomic.Uint64
)

// JournalLines and JournalDropped are the process-wide counts.
func JournalLines(level int) uint64 { return journalLines[level].Load() }
func JournalDropped() uint64        { return journalDropped.Load() }

func journalLevel(level string) int {
	if level == "WARN" {
		return 1
	}
	return 0
}

// Line is one journal line being built. Its methods append a field each; the
// keys are the caller's constants and are written as they are.
type Line struct{ b []byte }

func (l *Line) key(k string) {
	l.b = append(l.b, ',', '"')
	l.b = append(l.b, k...)
	l.b = append(l.b, '"', ':')
}

// Str appends a string field.
func (l *Line) Str(k, v string) {
	l.key(k)
	l.b = AppendJSONString(l.b, v)
}

// Int appends an integer field.
func (l *Line) Int(k string, v int64) {
	l.key(k)
	l.b = strconv.AppendInt(l.b, v, 10)
}

// Uint appends an unsigned integer field.
func (l *Line) Uint(k string, v uint64) {
	l.key(k)
	l.b = strconv.AppendUint(l.b, v, 10)
}

// Bool appends a boolean field.
func (l *Line) Bool(k string, v bool) {
	l.key(k)
	l.b = strconv.AppendBool(l.b, v)
}

// Prefix appends a network as a string field.
func (l *Line) Prefix(k string, p netip.Prefix) {
	l.key(k)
	l.b = append(l.b, '"')
	l.b = p.AppendTo(l.b)
	l.b = append(l.b, '"')
}

// Ms appends a duration in whole milliseconds.
func (l *Line) Ms(k string, d time.Duration) { l.Int(k, d.Milliseconds()) }

// Write appends one line for event. fill adds its fields; it runs under the
// journal's mutex and must not call back into the journal.
func (j *Journal) Write(level, event string, fill func(*Line)) {
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		j.dropped.Add(1)
		journalDropped.Add(1)
		return
	}
	if j.torn && len(j.buf) == 0 {
		j.buf = append(j.buf, '\n')
	}
	if j.gap > 0 {
		n := j.gap
		j.gap = 0
		j.appendLine(now, "WARN", "log_gap", func(l *Line) { l.Uint("dropped", n) })
	}
	j.appendLine(now, level, event, fill)
	if len(j.buf) >= JournalBuffer {
		j.flushLocked()
	}
}

func (j *Journal) appendLine(now time.Time, level, event string, fill func(*Line)) {
	j.seq++
	b := append(j.buf, `{"time":"`...)
	b = now.UTC().AppendFormat(b, "2006-01-02T15:04:05.000Z07:00")
	b = append(b, `","level":"`...)
	b = append(b, level...)
	b = append(b, `","msg":"`...)
	b = append(b, event...)
	b = append(b, `","event":"`...)
	b = append(b, event...)
	b = append(b, `","seq":`...)
	b = strconv.AppendUint(b, j.seq, 10)
	j.line.b = b
	if fill != nil {
		fill(&j.line)
	}
	j.buf = append(j.line.b, '}', '\n')
	j.line.b = nil
	j.ends = append(j.ends, len(j.buf))
	j.levels = append(j.levels, uint8(journalLevel(level)))
}

// Flush writes what the buffer holds.
func (j *Journal) Flush() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.flushLocked()
}

func (j *Journal) flushLocked() {
	if len(j.buf) == 0 {
		return
	}
	n, _ := j.file.Write(j.buf)
	n = min(max(n, 0), len(j.buf))
	if n > 0 {
		j.torn = j.buf[n-1] != '\n'
	}
	var written [2]uint64
	var lost uint64
	for i, end := range j.ends {
		if end <= n {
			written[j.levels[i]]++
		} else {
			lost++
		}
	}
	for i, w := range written {
		j.lines[i].Add(w)
		journalLines[i].Add(w)
	}
	j.dropped.Add(lost)
	journalDropped.Add(lost)
	j.gap += lost
	j.buf = j.buf[:0]
	j.ends = j.ends[:0]
	j.levels = j.levels[:0]
}

func (j *Journal) flushLoop() {
	defer close(j.done)
	t := time.NewTicker(FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-j.stop:
			return
		case <-t.C:
			j.Flush()
		}
	}
}

// Close flushes, stops the ticker and closes the file. Lines written after it
// are counted as dropped.
func (j *Journal) Close() error {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return nil
	}
	j.flushLocked()
	if j.torn {
		// The next process appends to this file and starts on a new line.
		if n, _ := j.file.Write([]byte{'\n'}); n == 1 {
			j.torn = false
		}
	}
	j.closed = true
	j.mu.Unlock()
	close(j.stop)
	<-j.done
	return j.file.Close()
}

// AppendJSONString appends s as a JSON string. Control characters are
// escaped and invalid UTF-8 becomes U+FFFD, so no value can break the line
// or the line after it.
func AppendJSONString(b []byte, s string) []byte {
	const hexDigits = "0123456789abcdef"
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' && c != 0x7f {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 || r == ' ' || r == ' ' {
			b = append(b, s[start:i]...)
			if r == utf8.RuneError {
				b = append(b, `�`...)
			} else {
				b = append(b, `\u202`...)
				b = append(b, hexDigits[r&0xf])
			}
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// LastEvent reads the event of the last complete line of a journal file, for
// the prev_unclean check at start. Empty when the file is empty or missing.
func LastEvent(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	const tail = 8 << 10
	off := info.Size() - tail
	if off < 0 {
		off = 0
	}
	buf := make([]byte, info.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return ""
	}
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	const key = `"event":"`
	i := bytes.Index(buf, []byte(key))
	if i < 0 {
		return ""
	}
	rest := buf[i+len(key):]
	if k := bytes.IndexByte(rest, '"'); k >= 0 {
		return string(rest[:k])
	}
	return ""
}
