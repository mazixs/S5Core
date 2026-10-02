package main

import "testing"

func TestTheProcAddressesAreReadInHostOrder(t *testing.T) {
	for in, want := range map[string]string{
		"0100007F:1F90":                         "127.0.0.1:8080",
		"00000000000000000000000001000000:0035": "[::1]:53",
		"0000000000000000FFFF00000100007F:0044": "127.0.0.1:68",
	} {
		if got := procAddr(in); got != want {
			t.Errorf("procAddr(%s) = %s, want %s", in, got, want)
		}
	}
}
