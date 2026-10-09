package userstore

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrFileChanged prevents a flush from overwriting an operator's edits.
var ErrFileChanged = errors.New("userstore: account file changed; reload required")

// ErrEditConflict means SDK and file edits changed the same metadata
// differently. Reload is transactional: neither side is overwritten.
var ErrEditConflict = errors.New("userstore: conflicting account edits")

func accountsByID(accounts []UserAccount) map[string]UserAccount {
	result := make(map[string]UserAccount, len(accounts))
	for _, account := range accounts {
		result[account.ID] = account.clone()
	}
	return result
}

func sameMetadata(a, b UserAccount) bool {
	a.TrafficUsedBytes, b.TrafficUsedBytes = 0, 0
	return reflect.DeepEqual(a, b)
}

// mergeMetadata performs a three-way merge of cold-path account fields. The
// persisted baseline distinguishes an operator edit from an unsaved SDK edit.
// All fields participate except spend, which has its own monotonic merge.
func mergeMetadata(base, memory, disk UserAccount) (UserAccount, error) {
	merged := disk.clone()
	b, m, d, result := reflect.ValueOf(base), reflect.ValueOf(memory), reflect.ValueOf(disk), reflect.ValueOf(&merged).Elem()
	for i := range b.NumField() {
		field := b.Type().Field(i).Name
		if field == "TrafficUsedBytes" || reflect.DeepEqual(m.Field(i).Interface(), b.Field(i).Interface()) {
			continue
		}
		if !reflect.DeepEqual(d.Field(i).Interface(), b.Field(i).Interface()) && !reflect.DeepEqual(d.Field(i).Interface(), m.Field(i).Interface()) {
			return UserAccount{}, fmt.Errorf("%w: field %s", ErrEditConflict, field)
		}
		result.Field(i).Set(m.Field(i))
	}
	merged.TrafficUsedBytes = max(memory.TrafficUsedBytes, disk.TrafficUsedBytes)
	return merged.clone(), nil
}

func (s *Store) mergeReloadLocked(disk []UserAccount) ([]UserAccount, map[string]*userEntry, map[string]int64, error) {
	fromDisk := accountsByID(disk)
	memory := make(map[string]UserAccount, len(s.users))
	entries := make(map[string]*userEntry, len(s.users))
	deltas := make(map[string]int64, len(s.users))
	ids := make(map[string]struct{}, len(fromDisk)+len(s.users))
	for id := range fromDisk {
		ids[id] = struct{}{}
	}
	for id := range s.diskAccounts {
		ids[id] = struct{}{}
	}
	for _, entry := range s.users {
		account := entry.account.clone()
		delta := entry.trafficDelta.Load()
		account.TrafficUsedBytes += delta
		memory[account.ID], entries[account.ID], deltas[account.ID] = account, entry, delta
		ids[account.ID] = struct{}{}
	}
	merged := make([]UserAccount, 0, len(ids))
	for id := range ids {
		base, hadBase := s.diskAccounts[id]
		mem, hasMem := memory[id]
		file, hasFile := fromDisk[id]
		switch {
		case hasMem && hasFile && hadBase:
			account, err := mergeMetadata(base, mem, file)
			if err != nil {
				return nil, nil, nil, err
			}
			merged = append(merged, account)
		case hasMem && hasFile:
			if !sameMetadata(mem, file) {
				return nil, nil, nil, ErrEditConflict
			}
			file.TrafficUsedBytes = max(mem.TrafficUsedBytes, file.TrafficUsedBytes)
			merged = append(merged, file)
		case hasMem && !hasFile && !hadBase:
			merged = append(merged, mem)
		case !hasMem && hasFile && !hadBase:
			merged = append(merged, file)
		case hasMem && !hasFile:
			// Revocation wins over an in-flight password migration or other
			// unsaved metadata. A removed account must not be resurrected.
		case !hasMem && hasFile:
			// An account removed by the SDK stays removed on an old file.
		}
	}
	return merged, entries, deltas, nil
}
