package userstore

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/mazixs/S5Core/internal/identity"
)

func loadedCounterStore(t *testing.T) (*Store, string) {
	t.Helper()
	store := NewStore(nil)
	path := createTestFile(t, []UserAccount{{ID: "a", Username: "alice", Password: "p", Enabled: true, TrafficUsedBytes: 100}})
	if err := store.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	return store, path
}

func editAccountFile(t *testing.T, path string, edit func(*UsersFile)) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file UsersFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	edit(&file)
	data, err = json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRepeatedReloadAndSaveNeverLoseOrRepeatTraffic(t *testing.T) {
	store, path := loadedCounterStore(t)
	store.AddTraffic("alice", 50)
	for i := range 3 {
		if err := store.Reload(path); err != nil {
			t.Fatal(err)
		}
		account, _ := store.Lookup("alice")
		if account.TrafficUsedBytes != 150 {
			t.Fatalf("reload %d: used=%d", i, account.TrafficUsedBytes)
		}
	}
	if err := store.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Reload(path); err != nil {
			t.Fatal(err)
		}
		account, _ := store.Lookup("alice")
		if account.TrafficUsedBytes != 150 {
			t.Fatalf("saved counter counted again: %d", account.TrafficUsedBytes)
		}
	}
}

func TestFailedFinalSaveAndReloadRetainSpentQuota(t *testing.T) {
	store, path := loadedCounterStore(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store.AddTraffic("alice", 50)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.StopPeriodicFlush(); err == nil {
		t.Fatal("failed save was hidden")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	editAccountFile(t, path, func(file *UsersFile) { file.Users[0].TrafficLimitBytes = 120 })
	for range 2 {
		if err := store.Reload(path); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Lookup("alice")
		if got.TrafficUsedBytes != 150 || store.SessionStatus("alice") != SessionQuotaExceeded {
			t.Fatalf("failed save/reload lost spend: %+v", got.Policy())
		}
	}
}

func TestSavingDoesNotOverwriteAnOperatorsFileEdit(t *testing.T) {
	store, path := loadedCounterStore(t)
	store.AddTraffic("alice", 50)
	external := editAccountFile(t, path, func(file *UsersFile) { file.Users[0].Enabled = false })
	if err := store.SaveToFile(path); err == nil {
		t.Fatal("save silently overwrote an external edit")
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, external) {
		t.Fatal("failed save changed the operator's bytes")
	}
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	account, _ := store.Lookup("alice")
	if account.Enabled || account.TrafficUsedBytes != 150 {
		t.Fatalf("reload lost edit or spend: %+v", account.Policy())
	}
	if err := store.SaveToFile(path); err != nil {
		t.Fatalf("accepted edit could not be saved: %v", err)
	}
}

func TestReloadRetainsUnsavedSDKCreationRemovalAndRole(t *testing.T) {
	store, path := loadedCounterStore(t)
	if err := store.AddUser("removed", "p"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveUser("removed"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRole("alice", identity.RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := store.AddUser("added", "p"); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Lookup("removed"); ok {
		t.Error("removed SDK account came back")
	}
	if _, ok := store.Lookup("added"); !ok {
		t.Error("new SDK account disappeared")
	}
	if store.Role("alice") != identity.RoleOperator {
		t.Error("unsaved SDK role was reverted")
	}
}

func TestConflictingRoleEditsLeaveMemoryAndFileIntact(t *testing.T) {
	store, path := loadedCounterStore(t)
	if err := store.SetRole("alice", identity.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	external := editAccountFile(t, path, func(file *UsersFile) { file.Users[0].Role = "operator" })
	if err := store.Reload(path); err == nil {
		t.Fatal("conflicting role changes silently merged")
	}
	if store.Role("alice") != identity.RoleAdmin {
		t.Fatal("failed reload changed memory")
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, external) {
		t.Fatal("failed reload changed the file")
	}
}

func TestRenamingAnAccountPreservesItsLiveCounterByID(t *testing.T) {
	store, path := loadedCounterStore(t)
	counter := store.TrafficCounterFor("alice")
	counter.Add(50)
	editAccountFile(t, path, func(file *UsersFile) { file.Users[0].Username = "renamed" })
	if err := store.Reload(path); err != nil {
		t.Fatal(err)
	}
	counter.Add(10)
	account, ok := store.Lookup("renamed")
	if !ok || account.TrafficUsedBytes != 160 || counter != store.TrafficCounterFor("renamed") {
		t.Fatal("rename lost the live counter")
	}
}
