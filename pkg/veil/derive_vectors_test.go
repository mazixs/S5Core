package veil

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"
)

// Known-answer vectors for Derive and DeriveDatagram. They pin the bytes on
// the wire, so a refactoring of the derivation that changes a label, the order
// of Expand or the cipher choice fails here rather than between two builds.
var (
	vectorPSK    = []byte("0123456789abcdef0123456789abcdef")
	vectorSecret = []byte("a shared salt, thirty-two bytes!")
	vectorNonce  = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	vectorText   = []byte("veil vector")
)

func vectorSeal(aead cipher.AEAD) string {
	return hex.EncodeToString(aead.Seal(nil, vectorNonce, vectorText, nil))
}

// direction is what one direction ("client" or "server" in the labels)
// derives: the stream AEAD and length mask, the datagram AEAD and tag key.
type direction struct {
	seal, mask, udpSeal, udpTag string
}

var derivationVectors = []struct {
	name           string
	ctx            Context
	client, server direction
}{
	{
		name: "default",
		ctx:  Context{},
		client: direction{
			seal:    "e2f87beadf70bb84d315425f481422e252277b28d869a900ef632b",
			mask:    "42e12d0920b15f4b",
			udpSeal: "9e82f8181f122e492c53b6ff66bb3a27c0163752a7cee04bef8586",
			udpTag:  "22e93cf860736ce3e6dd656789e71ae300acf8980b56cb684f9efec4d49a376b",
		},
		server: direction{
			seal:    "8ddb2490da337bac884aa585ca29e65b55db1509ca4e5cee035dd4",
			mask:    "ad23f8274b4b0d10",
			udpSeal: "65249a9f901362a896bee898c05e9948a716afcb60ce34b19f3ca2",
			udpTag:  "97812585ebc01a34396bcd0180a01dd45d9621e49cd6d3e5163e2c40b5d28bf4",
		},
	},
	{
		name: "chacha v2 node",
		ctx:  Context{Version: "v2", Cipher: CipherChaCha, NodeID: "ams-1"},
		client: direction{
			seal:    "e36b632fe6e90258c0d7992d676b3b104420234b5af7c45f9fb801",
			mask:    "f837cb4ce31390cc",
			udpSeal: "72a73e3f2fae0dab22a88c6ebcb6a5dc61710e3b84e73c3951d6b1",
			udpTag:  "d1f7745f095a0b5f39a0d13ac744f85b5f346145610616027bdfa0746e59f7d0",
		},
		server: direction{
			seal:    "01a7324b3ceac15141e6973eacc61fca32bdea81b65d1497086c6e",
			mask:    "a43ae09787687571",
			udpSeal: "c7d173dbb2d4fbd0968cabcb8e75e075e2959558e60c8afd67228b",
			udpTag:  "b42a3a55854e530c3f62597c996a1eaa71d0549eb069088e1c29cb60fce952cd",
		},
	},
}

func TestTheDerivedKeysMatchTheRecordedVectors(t *testing.T) {
	for _, v := range derivationVectors {
		for _, role := range []Role{RoleClient, RoleServer} {
			send, recv := v.client, v.server
			if role == RoleServer {
				send, recv = recv, send
			}
			s := derive(t, vectorPSK, vectorSecret, v.ctx, role)
			d, err := DeriveDatagram(vectorPSK, vectorSecret, v.ctx, role)
			if err != nil {
				t.Fatalf("%s role %d: DeriveDatagram: %v", v.name, role, err)
			}
			for _, c := range []struct{ what, got, want string }{
				{"stream send seal", vectorSeal(s.Send.Data), send.seal},
				{"stream recv seal", vectorSeal(s.Recv.Data), recv.seal},
				{"stream send mask", hex.EncodeToString(mask(s.Send)), send.mask},
				{"stream recv mask", hex.EncodeToString(mask(s.Recv)), recv.mask},
				{"datagram send seal", vectorSeal(d.Send), send.udpSeal},
				{"datagram recv seal", vectorSeal(d.Recv), recv.udpSeal},
				{"datagram send tag", hex.EncodeToString(d.SendTag[:]), send.udpTag},
				{"datagram recv tag", hex.EncodeToString(d.RecvTag[:]), recv.udpTag},
			} {
				if c.got != c.want {
					t.Errorf("%s role %d %s = %s, recorded %s", v.name, role, c.what, c.got, c.want)
				}
			}
		}
	}
}

// DeriveDatagram shares its checks with Derive, so a key material the stream
// refuses is refused for datagrams too, and with the same words.
func TestDeriveDatagramRefusesWhatDeriveRefuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		psk    []byte
		secret []byte
		ctx    Context
		role   Role
	}{
		{"short PSK", bytes.Repeat([]byte("k"), 31), vectorSecret, Context{}, RoleClient},
		{"long PSK", bytes.Repeat([]byte("k"), 33), vectorSecret, Context{}, RoleClient},
		{"empty secret", vectorPSK, nil, Context{}, RoleClient},
		{"no role", vectorPSK, vectorSecret, Context{}, RoleUnset},
		{"unknown role", vectorPSK, vectorSecret, Context{}, Role(7)},
		{"unknown cipher", vectorPSK, vectorSecret, Context{Cipher: "rot13"}, RoleServer},
	} {
		_, streamErr := Derive(c.psk, c.secret, c.ctx, c.role)
		_, datagramErr := DeriveDatagram(c.psk, c.secret, c.ctx, c.role)
		if streamErr == nil || datagramErr == nil {
			t.Errorf("%s: Derive error %v, DeriveDatagram error %v; both must refuse", c.name, streamErr, datagramErr)
			continue
		}
		if streamErr.Error() != datagramErr.Error() {
			t.Errorf("%s: DeriveDatagram says %q, Derive says %q", c.name, datagramErr, streamErr)
		}
		if !strings.HasPrefix(datagramErr.Error(), "veil: ") {
			t.Errorf("%s: %q does not name the package", c.name, datagramErr)
		}
	}
}
