package diagnostics

import (
	"cmp"
	"encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/privatefs"
)

const (
	// diskBudget is the most the diagnostics directory may hold.
	diskBudget = 256 << 20
	// freeDiskReserve is what the recorder leaves free on the volume.
	freeDiskReserve = 256 << 20
	// incidentFileMax is the most one events or trace file may take.
	incidentFileMax = 64 << 20
	// incidentReserve is the room an incident needs to start.
	incidentReserve = 1 << 20
	// diskCheckEvery is how many ticks pass between two checks of the room.
	diskCheckEvery = 20
)

// errNoRoom means the budget is spent and no automatic incident is left to
// make room.
var errNoRoom = errors.New("no room for diagnostics left in the directory or on the volume")

// readDir lists the directory; a test stands in entries that are gone by
// the time they are looked at.
var readDir = os.ReadDir

// room is what the recorder may still write: the budget less what the
// directory holds, and no more than leaves freeDiskReserve on the volume.
// The events file being written counts by what was written to it: Windows
// tells the size of an open file late. A file removed since the directory
// was read counts for nothing. A subdirectory is not the recorder's: it is
// neither entered nor counted.
func (r *recorder) room() (int64, error) {
	entries, err := readDir(r.dir)
	if err != nil {
		return 0, err
	}
	var used int64
	writing := ""
	if p := r.pending; p != nil {
		writing, used = filepath.Base(p.f.Name()), p.written
	}
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink != 0 {
			return 0, errors.New("a symbolic link in the diagnostics directory")
		}
		if e.IsDir() || e.Name() == writing {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		used += info.Size()
	}
	free, err := freeDisk(r.dir)
	if err != nil {
		return 0, err
	}
	return max(0, min(r.budget-used, int64(free)-freeDiskReserve)), nil
}

// makeRoom returns the room once it is at least need, removing the oldest
// group of files rotation may take as long as it is not.
func (r *recorder) makeRoom(need int64) (int64, error) {
	for {
		room, err := r.room()
		if err != nil || room >= need {
			return room, err
		}
		freed, removed := r.removeOldest()
		if !freed {
			return room, errNoRoom
		}
		if removed {
			r.health.rotated++
		}
	}
}

// savedIncident is what rotation reads of a manifest.
type savedIncident struct {
	Trigger struct {
		Source                 string    `json:"source"`
		UTC                    time.Time `json:"utc"`
		PriorAutomaticIncident string    `json:"prior_automatic_incident"`
	} `json:"trigger"`
}

// removeOldest removes the files of the oldest incident rotation may take:
// an automatic one, by its trigger, or one left without a manifest - a
// partial file after a kill, a trace whose incident has no manifest - by the
// last time one of its files was written. It leaves the incident being
// written, the trace being written, the manual incidents and the automatic
// ones they took over, and an incident whose manifest cannot be read.
//
// freed says the directory holds less than it did, removed that this call
// removed something: a file someone else removed first frees its room all
// the same, and one that cannot be removed sends rotation to the next.
func (r *recorder) removeOldest() (freed, removed bool) {
	entries, err := readDir(r.dir)
	if err != nil {
		return false, false
	}
	type group struct {
		files    []string
		written  time.Time // the latest of its files
		manifest *savedIncident
		unread   bool // a manifest there that could not be read
	}
	groups := map[string]*group{}
	for _, e := range entries {
		id := incidentOf(e.Name())
		if id == "" || e.IsDir() {
			continue
		}
		g := groups[id]
		if g == nil {
			g = &group{}
			groups[id] = g
		}
		g.files = append(g.files, e.Name())
		if info, err := e.Info(); err == nil && info.ModTime().After(g.written) {
			g.written = info.ModTime()
		}
		if e.Name() != id+manifestSuffix {
			continue
		}
		var m savedIncident
		switch err := readManifest(filepath.Join(r.dir, e.Name()), &m); {
		case err == nil:
			g.manifest = &m
		case !errors.Is(err, fs.ErrNotExist):
			g.unread = true
		}
	}
	kept := map[string]bool{}
	if p := r.pending; p != nil {
		kept[p.id], kept[p.prior] = true, true
	}
	if r.tracing.Load() {
		kept[r.traceID] = true
	}
	for id, g := range groups {
		if g.manifest != nil && g.manifest.Trigger.Source != sourceAutomatic {
			kept[id], kept[g.manifest.Trigger.PriorAutomaticIncident] = true, true
		}
	}
	type candidate struct {
		id string
		at time.Time
	}
	var candidates []candidate
	for id, g := range groups {
		switch {
		case kept[id] || g.unread:
		case g.manifest != nil:
			candidates = append(candidates, candidate{id, g.manifest.Trigger.UTC})
		default:
			candidates = append(candidates, candidate{id, g.written})
		}
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		return cmp.Or(a.at.Compare(b.at), strings.Compare(a.id, b.id))
	})
	for _, c := range candidates {
		for _, name := range groups[c.id].files {
			switch err := os.Remove(filepath.Join(r.dir, name)); {
			case err == nil:
				freed, removed = true, true
			case errors.Is(err, fs.ErrNotExist):
				freed = true
			}
		}
		if freed {
			return freed, removed
		}
	}
	return false, false
}

// incidentOf is the incident a file of the directory belongs to: the UUID
// its name starts with.
func incidentOf(name string) string {
	id, _, _ := strings.Cut(name, ".")
	if _, err := uuid.Parse(id); err != nil {
		return ""
	}
	return id
}

func readManifest(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.UnmarshalRead(io.LimitReader(f, 1<<20), v)
}

// writeFile writes data to name in the directory, through a private
// temporary file renamed into place once it is on disk.
func (r *recorder) writeFile(name string, data []byte) error {
	f, err := privatefs.CreateTemp(r.dir, name+".*.partial")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return r.commit(f, name, err)
}

// commit syncs and closes f and renames it to name, unless err already says
// it failed: then the partial file stays until rotation needs its room.
func (r *recorder) commit(f *os.File, name string, err error) error {
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(r.dir, name))
}

// quotaWriter refuses to write past its quota.
type quotaWriter struct {
	w    io.Writer
	left int64
}

var errQuota = errors.New("the file reached its share of the diagnostics budget")

func (q *quotaWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > q.left {
		return 0, errQuota
	}
	n, err := q.w.Write(p)
	q.left -= int64(n)
	return n, err
}
