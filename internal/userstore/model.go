package userstore

import "time"

// UserAccount represents a single proxy user with authentication,
// validity period, and traffic accounting.
type UserAccount struct {
	ID                string     `json:"id"`
	Username          string     `json:"username"`
	Password          string     `json:"password"`
	Comment           string     `json:"comment,omitempty"`
	ValidFrom         *time.Time `json:"valid_from,omitempty"`
	ValidUntil        *time.Time `json:"valid_until,omitempty"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes,omitempty"`
	TrafficUsedBytes  int64      `json:"traffic_used_bytes,omitempty"`
	Enabled           bool       `json:"enabled"`
}

// UsersFile is the root structure of the users JSON file.
type UsersFile struct {
	Users []UserAccount `json:"users"`
}

// IsExpired checks if the account has passed its validity period.
func (u *UserAccount) IsExpired(now time.Time) bool {
	if u.ValidUntil != nil && now.After(*u.ValidUntil) {
		return true
	}
	return false
}

// IsNotYetActive checks if the account is not yet within its validity period.
func (u *UserAccount) IsNotYetActive(now time.Time) bool {
	if u.ValidFrom != nil && now.Before(*u.ValidFrom) {
		return true
	}
	return false
}

// IsTrafficExceeded checks if the user has exceeded their traffic limit.
func (u *UserAccount) IsTrafficExceeded() bool {
	if u.TrafficLimitBytes > 0 && u.TrafficUsedBytes >= u.TrafficLimitBytes {
		return true
	}
	return false
}
