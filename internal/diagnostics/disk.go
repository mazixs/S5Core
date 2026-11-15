package diagnostics

import (
	"encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// room is what the recorder may still write: the budget less what the
// directory holds, and no more than leaves freeDiskReserve on the volume.
// The events file being written counts by what was written to it: Windows
// tells the size of an open file late.
func (r *recorder) room() (int64, error) {
	var used int64
	writing := ""
	if p := r.pending; p != nil {
		writing, used = p.f.Name(), p.written
	}
	err := filepath.WalkDir(r.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return errors.New("a symbolic link in the diagnostics directory")
		}
		if !d.IsDir() && path != writing {
			info, err := d.Info()
			if err != nil {
				return err
			}
			used += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	free, err := freeDisk(r.dir)
	if err != nil {
		return 0, err
	}
	return max(0, min(r.budget-used, int64(free)-freeDiskReserve)), nil
}

// makeRoom returns the room once it is at least need, removing the oldest
// automatic incident as long as it is not. A manual incident is never
// removed, nor the one being written.
func (r *recorder) makeRoom(need int64) (int64, error) {
	for {
		room, err := r.room()
		if err != nil || room >= need {
			return room, err
		}
		if !r.removeOldestAutomatic() {
			return room, errNoRoom
		}
		r.health.rotated++
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

func (r *recorder) removeOldestAutomatic() bool {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return false
	}
	kept := map[string]bool{}
	if p := r.pending; p != nil {
		kept[p.id], kept[p.prior] = true, true
	}
	type candidate struct {
		id string
		at time.Time
	}
	var automatic []candidate
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), manifestSuffix)
		if !ok {
			continue
		}
		var m savedIncident
		if err := readManifest(filepath.Join(r.dir, e.Name()), &m); err != nil {
			continue
		}
		if m.Trigger.Source == sourceAutomatic {
			automatic = append(automatic, candidate{id, m.Trigger.UTC})
		} else {
			kept[id], kept[m.Trigger.PriorAutomaticIncident] = true, true
		}
	}
	oldest := candidate{}
	for _, c := range automatic {
		if !kept[c.id] && (oldest.id == "" || c.at.Before(oldest.at)) {
			oldest = c
		}
	}
	if oldest.id == "" {
		return false
	}
	removed := false
	for _, e := range entries {
		if incidentOf(e.Name()) == oldest.id && os.Remove(filepath.Join(r.dir, e.Name())) == nil {
			removed = true
		}
	}
	return removed
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
// it failed: then the partial file stays for whoever looks.
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
