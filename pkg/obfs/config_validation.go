package obfs

import "fmt"

// ValidateMTU accepts the default (zero) or the format's framing bounds.
func ValidateMTU(mtu int) error {
	if mtu != 0 && (mtu < MinMTU || mtu > MaxMTU) {
		return fmt.Errorf("OBFS_MTU must be 0 or between %d and %d", MinMTU, MaxMTU)
	}
	return nil
}
