package s5server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mazixs/S5Core/internal/userstore"
)

func TestFutureMemberActivatesAndExpiresWithoutReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		from, until := time.Now().Add(5*time.Second), time.Now().Add(10*time.Second)
		file := userstore.UsersFile{Users: []userstore.UserAccount{{ID: "future-id", Username: "future",
			Enabled: true, TunnelKey: base64.StdEncoding.EncodeToString(randomMemberKey(t)), ValidFrom: &from, ValidUntil: &until}}}
		data, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "users.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		s, err := NewServer(Config{Port: "0", RequireAuth: true, UsersFile: path})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { s.maintainMembers(ctx); close(done) }()
		synctest.Wait()
		if s.members.Len() != 0 {
			t.Fatal("future key resolved before valid_from")
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if s.members.Len() != 1 {
			t.Fatal("future key did not activate without reload")
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if s.members.Len() != 0 {
			t.Fatal("expired key stayed in the directory")
		}
		cancel()
		<-done
	})
}

func TestMovingAValidityDateEarlierWakesTheMemberTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		from := time.Now().Add(time.Hour)
		file := userstore.UsersFile{Users: []userstore.UserAccount{{ID: "future-id", Username: "future", Enabled: true, TunnelKey: base64.StdEncoding.EncodeToString(randomMemberKey(t)), ValidFrom: &from}}}
		path := filepath.Join(t.TempDir(), "users.json")
		write := func() {
			data, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		write()
		s, err := NewServer(Config{Port: "0", RequireAuth: true, UsersFile: path})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() { s.maintainMembers(ctx); close(done) }()
		synctest.Wait()
		from = time.Now().Add(2 * time.Second)
		write()
		if err = s.ReloadUsers(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if s.members.Len() != 1 {
			t.Fatal("earlier validity date left the old one-hour timer running")
		}
		cancel()
		<-done
	})
}
