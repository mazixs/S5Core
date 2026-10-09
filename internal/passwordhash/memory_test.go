package passwordhash

import (
	"encoding/base64"
	"testing"
)

func TestMemoryCostUsesTheValidatedPHCParameters(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	hash := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	valid := "$argon2id$v=19$m=131072,t=1,p=1$" + salt + "$" + hash
	if cost, err := MemoryCost(valid); err != nil || cost != 128<<20 {
		t.Fatalf("cost=%d error=%v", cost, err)
	}
	for _, bad := range []string{"", "$argon2id$v=19$m=131072,t=1,p=1$" + salt + "$!!!"} {
		if _, err := MemoryCost(bad); err == nil {
			t.Fatal("malformed PHC admitted to memory accounting")
		}
	}
}
