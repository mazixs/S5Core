package userstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testTime(s string) *time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return &t
}

func TestUserAccount_IsExpired(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		until   *time.Time
		expired bool
	}{
		{"nil until", nil, false},
		{"future until", testTime("2027-01-01T00:00:00Z"), false},
		{"past until", testTime("2026-01-01T00:00:00Z"), true},
		{"exact until", &now, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := UserAccount{ValidUntil: tt.until}
			if got := u.IsExpired(now); got != tt.expired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expired)
			}
		})
	}
}

func TestUserAccount_IsNotYetActive(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		from      *time.Time
		notActive bool
	}{
		{"nil from", nil, false},
		{"past from", testTime("2026-01-01T00:00:00Z"), false},
		{"future from", testTime("2026-06-01T00:00:00Z"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := UserAccount{ValidFrom: tt.from}
			if got := u.IsNotYetActive(now); got != tt.notActive {
				t.Errorf("IsNotYetActive() = %v, want %v", got, tt.notActive)
			}
		})
	}
}

func TestUserAccount_IsTrafficExceeded(t *testing.T) {
	tests := []struct {
		name     string
		limit    int64
		used     int64
		exceeded bool
	}{
		{"no limit", 0, 1000, false},
		{"under limit", 1000, 500, false},
		{"at limit", 1000, 1000, true},
		{"over limit", 1000, 1500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := UserAccount{TrafficLimitBytes: tt.limit, TrafficUsedBytes: tt.used}
			if got := u.IsTrafficExceeded(); got != tt.exceeded {
				t.Errorf("IsTrafficExceeded() = %v, want %v", got, tt.exceeded)
			}
		})
	}
}

func createTestFile(t *testing.T, users []UserAccount) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	data, err := json.MarshalIndent(UsersFile{Users: users}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testUsers() []UserAccount {
	return []UserAccount{
		{
			ID:                "u-001",
			Username:          "alice",
			Password:          "pass1",
			Comment:           "test user",
			ValidFrom:         testTime("2026-01-01T00:00:00Z"),
			ValidUntil:        testTime("2027-01-01T00:00:00Z"),
			TrafficLimitBytes: 1024 * 1024, // 1MB
			Enabled:           true,
		},
		{
			ID:       "u-002",
			Username: "bob",
			Password: "pass2",
			Enabled:  true,
		},
		{
			ID:       "u-003",
			Username: "disabled",
			Password: "pass3",
			Enabled:  false,
		},
		{
			ID:         "u-004",
			Username:   "expired",
			Password:   "pass4",
			ValidUntil: testTime("2020-01-01T00:00:00Z"),
			Enabled:    true,
		},
	}
}

func TestStore_LoadFromFile(t *testing.T) {
	path := createTestFile(t, testUsers())
	s := NewStore(nil)

	if err := s.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if s.UserCount() != 4 {
		t.Errorf("UserCount = %d, want 4", s.UserCount())
	}

	acc, ok := s.Lookup("alice")
	if !ok {
		t.Fatal("alice not found")
	}
	if acc.ID != "u-001" {
		t.Errorf("alice.ID = %q, want u-001", acc.ID)
	}
	if acc.Comment != "test user" {
		t.Errorf("alice.Comment = %q, want 'test user'", acc.Comment)
	}
}

func TestStore_LoadFromFile_DuplicateUsername(t *testing.T) {
	users := []UserAccount{
		{ID: "1", Username: "dup", Password: "p", Enabled: true},
		{ID: "2", Username: "dup", Password: "p", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)

	err := s.LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for duplicate username")
	}
}

func TestStore_LoadFromFile_DuplicateID(t *testing.T) {
	users := []UserAccount{
		{ID: "same", Username: "u1", Password: "p", Enabled: true},
		{ID: "same", Username: "u2", Password: "p", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)

	err := s.LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for duplicate id")
	}
}

func TestStore_IsValid(t *testing.T) {
	path := createTestFile(t, testUsers())
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		user  string
		pass  string
		valid bool
	}{
		{"correct credentials", "alice", "pass1", true},
		{"wrong password", "alice", "wrong", false},
		{"unknown user", "unknown", "pass", false},
		{"disabled user", "disabled", "pass3", false},
		{"expired user", "expired", "pass4", false},
		{"no TTL user", "bob", "pass2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.IsValid(tt.user, tt.pass); got != tt.valid {
				t.Errorf("IsValid(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.valid)
			}
		})
	}
}

func TestStore_IsValid_TrafficExceeded(t *testing.T) {
	users := []UserAccount{
		{
			ID:                "u-001",
			Username:          "alice",
			Password:          "pass",
			TrafficLimitBytes: 100,
			TrafficUsedBytes:  50,
			Enabled:           true,
		},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	// Under limit
	if !s.IsValid("alice", "pass") {
		t.Error("should be valid under traffic limit")
	}

	// Add traffic to exceed
	s.AddTraffic("alice", 60)

	if s.IsValid("alice", "pass") {
		t.Error("should be invalid when traffic exceeded")
	}
}

func TestStore_AddTraffic_Concurrent(t *testing.T) {
	users := []UserAccount{
		{ID: "u-001", Username: "alice", Password: "pass", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	const goroutines = 100
	const perGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				s.AddTraffic("alice", 1)
			}
		}()
	}
	wg.Wait()

	acc, _ := s.Lookup("alice")
	expected := int64(goroutines * perGoroutine)
	if acc.TrafficUsedBytes != expected {
		t.Errorf("TrafficUsedBytes = %d, want %d", acc.TrafficUsedBytes, expected)
	}
}

func TestStore_SaveAndReload(t *testing.T) {
	users := []UserAccount{
		{ID: "u-001", Username: "alice", Password: "pass", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	// Add some traffic
	s.AddTraffic("alice", 42)

	// Save
	if err := s.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	// Reload into fresh store
	s2 := NewStore(nil)
	if err := s2.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	acc, _ := s2.Lookup("alice")
	if acc.TrafficUsedBytes != 42 {
		t.Errorf("TrafficUsedBytes after reload = %d, want 42", acc.TrafficUsedBytes)
	}
}

func TestStore_Reload_MergesTraffic(t *testing.T) {
	users := []UserAccount{
		{ID: "u-001", Username: "alice", Password: "pass", TrafficUsedBytes: 100, Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	// Runtime traffic
	s.AddTraffic("alice", 50)

	// Reload same file (simulates admin editing the file)
	if err := s.Reload(path); err != nil {
		t.Fatal(err)
	}

	acc, _ := s.Lookup("alice")
	// Should be original 100 + runtime delta 50 = 150
	if acc.TrafficUsedBytes != 150 {
		t.Errorf("TrafficUsedBytes after reload = %d, want 150", acc.TrafficUsedBytes)
	}
}

func TestCredentialAdapter(t *testing.T) {
	users := []UserAccount{
		{ID: "u-001", Username: "alice", Password: "pass", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	adapter := NewCredentialAdapter(s)

	if !adapter.Valid("alice", "pass") {
		t.Error("adapter.Valid should return true for valid creds")
	}
	if adapter.Valid("alice", "wrong") {
		t.Error("adapter.Valid should return false for wrong password")
	}
	if adapter.Valid("unknown", "pass") {
		t.Error("adapter.Valid should return false for unknown user")
	}
}

func TestStore_FlushTraffic(t *testing.T) {
	users := []UserAccount{
		{ID: "u-001", Username: "alice", Password: "pass", Enabled: true},
	}
	path := createTestFile(t, users)
	s := NewStore(nil)
	if err := s.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}

	s.AddTraffic("alice", 100)

	// Before flush, the account's TrafficUsedBytes should be 0 (delta is separate)
	s.mu.RLock()
	entry := s.users["alice"]
	beforeFlush := entry.account.TrafficUsedBytes
	s.mu.RUnlock()

	if beforeFlush != 0 {
		t.Errorf("before flush TrafficUsedBytes = %d, want 0", beforeFlush)
	}

	s.FlushTraffic()

	s.mu.RLock()
	afterFlush := s.users["alice"].account.TrafficUsedBytes
	delta := s.users["alice"].trafficDelta.Load()
	s.mu.RUnlock()

	if afterFlush != 100 {
		t.Errorf("after flush TrafficUsedBytes = %d, want 100", afterFlush)
	}
	if delta != 0 {
		t.Errorf("after flush trafficDelta = %d, want 0", delta)
	}
}
