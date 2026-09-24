package userstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
)

func fuzzStore() *Store { return NewStore(slog.New(slog.NewTextHandler(io.Discard, nil))) }

func fuzzSameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// fuzzSameAccount compares accounts field by field, times by instant: the
// writer may spell an offset differently from the file it read.
func fuzzSameAccount(a, b UserAccount) bool {
	return a.ID == b.ID && a.Username == b.Username && a.Password == b.Password &&
		a.PasswordHash == b.PasswordHash && a.TunnelKey == b.TunnelKey && a.Role == b.Role &&
		a.Comment == b.Comment && fuzzSameTime(a.ValidFrom, b.ValidFrom) && fuzzSameTime(a.ValidUntil, b.ValidUntil) &&
		a.TrafficLimitBytes == b.TrafficLimitBytes && a.TrafficUsedBytes == b.TrafficUsedBytes && a.Enabled == b.Enabled
}

func fuzzUsersFile(tb testing.TB, users ...UserAccount) []byte {
	data, err := json.Marshal(UsersFile{Users: users})
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

// FuzzLoadUsersFile loads arbitrary bytes as the users file (USERS_FILE) and
// checks what a load promises:
//   - it succeeds exactly when the JSON parses and validateUsers passes it:
//     non-empty, unique names and ids, a known role, a hash that can be
//     checked (F15);
//   - every account is loaded as written, except that one without a tunnel
//     key is given a decodable 32-byte key and a hash is respelled into the
//     standard alphabet;
//   - the file is rewritten only when something was migrated, and what was
//     written loads back to the same accounts and keys without another
//     rewrite;
//   - Reload accepts the same files, leaves the file alone and agrees with
//     Load on every account;
//   - a tunnel member always has the key its account stores.
func FuzzLoadUsersFile(f *testing.F) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	tag := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	hash := "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + tag
	legacy := "$argon2id$v=19$m=64,t=1,p=1$" + base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0xfe, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6}) +
		"$" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfe}, 16))
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, TunnelKeySize))
	until := time.Date(2027, 1, 2, 3, 4, 5, 6, time.FixedZone("", 3*3600))

	f.Add(fuzzUsersFile(f,
		UserAccount{ID: "1", Username: "alice", PasswordHash: hash, TunnelKey: key, Role: "admin", Enabled: true, ValidUntil: &until, TrafficLimitBytes: 1 << 30},
		UserAccount{ID: "2", Username: "bob", Password: "plain", Enabled: true},
		UserAccount{ID: "3", Username: "carol", PasswordHash: legacy, Role: "operator", TrafficUsedBytes: 5},
	))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "dave", TunnelKey: "not base64", Enabled: true}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "erin", TunnelKey: base64.StdEncoding.EncodeToString([]byte("short")), Enabled: true}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "a"}, UserAccount{ID: "1", Username: "b"}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "a"}, UserAccount{ID: "2", Username: "a"}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "a", Role: "root"}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "1", Username: "a", PasswordHash: "$argon2id$v=19$m=-1,t=3,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA"}))
	f.Add(fuzzUsersFile(f, UserAccount{ID: "", Username: "a"}))
	f.Add([]byte(`{"users":[{"id":"1","username":"z","valid_from":"2026-01-01T00:00:00+00:00","enabled":true}]}`))
	f.Add([]byte(`{"users":null}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "users.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var uf UsersFile
		wantOK := json.Unmarshal(data, &uf) == nil && validateUsers(uf.Users) == nil

		s := fuzzStore()
		err := s.LoadFromFile(path)
		if (err == nil) != wantOK {
			t.Fatalf("LoadFromFile err=%v, the parser and validateUsers say ok=%v", err, wantOK)
		}
		reloaded := fuzzStore()
		reloadPath := filepath.Join(dir, "reload.json")
		if err := os.WriteFile(reloadPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if rerr := reloaded.Reload(reloadPath); (rerr == nil) != wantOK {
			t.Fatalf("Reload err=%v, LoadFromFile err=%v", rerr, err)
		}
		if after, _ := os.ReadFile(reloadPath); !bytes.Equal(after, data) {
			t.Fatalf("Reload rewrote the file")
		}
		if err != nil {
			return
		}

		if s.UserCount() != len(uf.Users) || reloaded.UserCount() != len(uf.Users) {
			t.Fatalf("%d accounts in the file, %d loaded and %d reloaded", len(uf.Users), s.UserCount(), reloaded.UserCount())
		}
		rewrite := false
		for _, u := range uf.Users {
			got, ok := s.Lookup(u.Username)
			if !ok {
				t.Fatalf("account %q is not in the store", u.Username)
			}
			want := u
			if std, changed := passwordhash.Standardise(u.PasswordHash); changed {
				want.PasswordHash = std
				rewrite = true
			}
			if u.TunnelKey == "" {
				if _, err := DecodeTunnelKey(got.TunnelKey); err != nil {
					t.Fatalf("account %q was given the key %q: %v", u.Username, got.TunnelKey, err)
				}
				want.TunnelKey = got.TunnelKey
				rewrite = true
			}
			if !fuzzSameAccount(got, want) {
				t.Fatalf("account loaded as %+v, want %+v", got, want)
			}
			again, _ := reloaded.Lookup(u.Username)
			again.TunnelKey = got.TunnelKey
			if !fuzzSameAccount(again, got) {
				t.Fatalf("Reload read %+v, Load %+v", again, got)
			}
		}

		written, _ := os.ReadFile(path)
		if !rewrite {
			if !bytes.Equal(written, data) {
				t.Fatalf("nothing was migrated and the file was rewritten")
			}
		} else {
			second := fuzzStore()
			if err := second.LoadFromFile(path); err != nil {
				t.Fatalf("the migrated file does not load: %v\n%s", err, written)
			}
			for _, u := range uf.Users {
				a, _ := s.Lookup(u.Username)
				b, ok := second.Lookup(u.Username)
				if !ok || !fuzzSameAccount(a, b) {
					t.Fatalf("account %q came back from the migrated file as %+v, want %+v", u.Username, b, a)
				}
			}
			if final, _ := os.ReadFile(path); !bytes.Equal(final, written) {
				t.Fatalf("a second load of the migrated file rewrote it again")
			}
		}

		for _, m := range s.TunnelMembers() {
			acc, _ := s.Lookup(m.Username)
			k, err := DecodeTunnelKey(acc.TunnelKey)
			if err != nil || !bytes.Equal(k, m.Key) {
				t.Fatalf("member %q has a key its account does not store", m.Username)
			}
		}
	})
}

// FuzzDecodeTunnelKey: an accepted key is 32 bytes, and it is the key its
// standard encoding decodes to - so the key the migration writes is the key
// the server resolves. Anything else is an error, never a shorter key.
func FuzzDecodeTunnelKey(f *testing.F) {
	f.Add(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, TunnelKeySize)))
	f.Add(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, TunnelKeySize)))
	f.Add(base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, TunnelKeySize)))
	f.Add(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, TunnelKeySize-1)))
	f.Add(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, TunnelKeySize+1)))
	f.Add("AAAA\nAAAA")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		key, err := DecodeTunnelKey(s)
		if err != nil {
			if key != nil {
				t.Fatalf("a refusal returned %x", key)
			}
			return
		}
		if len(key) != TunnelKeySize {
			t.Fatalf("accepted a %d-byte key", len(key))
		}
		back, err := DecodeTunnelKey(base64.StdEncoding.EncodeToString(key))
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("the re-encoded key %x decoded to %x, err=%v", key, back, err)
		}
	})
}
