package obfs

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
	"github.com/mazixs/S5Core/pkg/veil"
)

// Plan task Ф5-5 wants a client on a router without AES instructions to take
// ChaCha20-Poly1305 by itself, and a server to accept it without being told.
// pkg/veil proves the pieces; these tests prove the property reaches the
// wire - that a tunnel really carries traffic under either cipher, that the
// server needs no configuration to accept both, and that an observer cannot
// tell which was taken.

// acceptingServer is the scheme a server runs: its own identity under every
// cipher, in the order pkg/veil prefers them.
func acceptingServer(nodeID string) *veil.Clocked {
	accepts := make([]veil.Context, 0, len(veil.Ciphers()))
	for _, c := range veil.Ciphers() {
		accepts = append(accepts, veil.Context{Cipher: c, NodeID: nodeID})
	}
	return &veil.Clocked{Context: accepts[0], Accepts: accepts}
}

func TestAServerAcceptsEitherCipherWithoutBeingTold(t *testing.T) {
	for _, c := range veil.Ciphers() {
		t.Run(string(c), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			psk := bytes.Repeat([]byte("k"), 32)
			client, err := NewClientConn(clientConn, Config{
				PSK:        psk,
				MaxPadding: 64,
				Scheme:     &veil.Clocked{Context: veil.Context{Cipher: c}},
			})
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			// The server is configured once, for both ciphers, and is never
			// told which one this client picked.
			server, err := NewServerConn(serverConn, Config{
				PSK:        psk,
				MaxPadding: 64,
				Scheme:     acceptingServer(""),
			})
			if err != nil {
				t.Fatalf("server: %v", err)
			}

			msg := []byte("a router without AES instructions says hello")
			go func() {
				if _, writeErr := client.Write(msg); writeErr != nil {
					t.Errorf("write: %v", writeErr)
				}
			}()

			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 128)
			n, err := server.Read(buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(buf[:n], msg) {
				t.Fatalf("read %q, want %q", buf[:n], msg)
			}

			// And back, because the two directions have separate keys and a
			// cipher that only works one way is a cipher that does not work.
			reply := []byte("the server answers under the same cipher")
			go func() {
				if _, writeErr := server.Write(reply); writeErr != nil {
					t.Errorf("reply: %v", writeErr)
				}
			}()
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err = client.Read(buf)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if !bytes.Equal(buf[:n], reply) {
				t.Fatalf("read back %q, want %q", buf[:n], reply)
			}
		})
	}
}

// The cipher is a property of the client's processor, and a processor is not
// something a censor is entitled to learn. Two clients that differ only in
// cipher must put the same shape on the wire.
func TestTheCipherChoiceIsInvisibleOnTheWire(t *testing.T) {
	const samples = 200
	psk := bytes.Repeat([]byte("k"), 32)
	payload := []byte("the same message under two different ciphers")

	byCipher := make(map[veil.Cipher][][]byte, len(veil.Ciphers()))
	for _, c := range veil.Ciphers() {
		corpus := make([][]byte, 0, samples)
		for range samples {
			clientConn, serverConn := net.Pipe()

			client, err := NewClientConn(clientConn, Config{
				PSK:        psk,
				MaxPadding: 256,
				Scheme:     &veil.Clocked{Context: veil.Context{Cipher: c}},
			})
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			go func() {
				_, _ = client.Write(payload)
				_ = client.Close()
			}()

			// Everything the client sends before it stops: prologue, first
			// frame and whatever padding went with them.
			_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var wire bytes.Buffer
			buf := make([]byte, 4096)
			for {
				n, err := serverConn.Read(buf)
				wire.Write(buf[:n])
				if err != nil {
					break
				}
			}
			_ = serverConn.Close()

			if wire.Len() == 0 {
				t.Fatal("the client sent nothing")
			}
			// Past the opening: the encoded prologue is printable by
			// design and varies in length by design, so pooling it with
			// the frames would measure the encoding, not the cipher. What
			// the cipher could leak is in the frames.
			corpus = append(corpus, bytes.Clone(wire.Bytes()[len(client.(*conn).wirePrologue):]))
		}
		byCipher[c] = corpus
	}

	// Padding still varies the length under either cipher - otherwise the
	// corpus below would be measuring nothing.
	for _, c := range veil.Ciphers() {
		if lengths := stealth.Lengths(byCipher[c]); lengths.Distinct < 2 {
			t.Errorf("cipher %q: %d samples produced %d distinct lengths, padding is not working",
				c, len(byCipher[c]), lengths.Distinct)
		}
	}

	// And no byte position gives the cipher away either. The frames are
	// checked across both corpora pooled together, aligned on where the
	// opening ended: if one cipher marked a byte, the pool shows it.
	pooled := make([][]byte, 0, samples*len(veil.Ciphers()))
	for _, c := range veil.Ciphers() {
		for _, sample := range byCipher[c] {
			pooled = append(pooled, sample[:veil.SaltSize])
		}
	}
	for _, f := range stealth.PositionalUniformity(pooled, veil.SaltSize) {
		t.Errorf("the first bytes carry the cipher choice at offset %d: %s", f.Offset, f)
	}
}

// The length check the test above cannot make while padding is random: with
// padding off, the same payload must produce the same number of bytes under
// either cipher, down to the byte. That is the property - identical key,
// nonce and tag sizes - that lets the choice be free.
func TestBothCiphersPutTheSameNumberOfBytesOnTheWire(t *testing.T) {
	psk := bytes.Repeat([]byte("k"), 32)
	payload := []byte("the same message under two different ciphers")

	sizes := make(map[veil.Cipher]int, len(veil.Ciphers()))
	for _, c := range veil.Ciphers() {
		clientConn, serverConn := net.Pipe()

		client, err := NewClientConn(clientConn, Config{
			PSK:        psk,
			MaxPadding: 0,
			Scheme:     &veil.Clocked{Context: veil.Context{Cipher: c}},
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		go func() {
			_, _ = client.Write(payload)
			_ = client.Close()
		}()

		_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n := 0
		buf := make([]byte, 4096)
		for {
			read, err := serverConn.Read(buf)
			n += read
			if err != nil {
				break
			}
		}
		_ = serverConn.Close()
		// The opening does not count: its length comes from the session
		// secret and differs between two connections under one cipher as
		// much as between two ciphers. What must match is the frames.
		sizes[c] = n - len(client.(*conn).wirePrologue)
	}

	first := veil.Ciphers()[0]
	for _, c := range veil.Ciphers()[1:] {
		if sizes[c] != sizes[first] {
			t.Errorf("cipher %q sends %d bytes where %q sends %d: the choice is visible by size",
				c, sizes[c], first, sizes[first])
		}
	}
	if sizes[first] == 0 {
		t.Fatal("the client sent nothing")
	}
}

// A server that has not been told about a cipher must refuse it the way it
// refuses a wrong key - the client is simply not talking its format.
func TestACipherTheServerDoesNotAcceptFailsLikeAWrongKey(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	psk := bytes.Repeat([]byte("k"), 32)
	client, err := NewClientConn(clientConn, Config{
		PSK:    psk,
		Scheme: &veil.Clocked{Context: veil.Context{Cipher: veil.CipherChaCha}},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	// Accepts only AES, which is what a build from before this task does.
	server, err := NewServerConn(serverConn, Config{
		PSK:    psk,
		Scheme: &veil.Clocked{Context: veil.Context{Cipher: veil.CipherAES}},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("hello"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := server.Read(make([]byte, 64)); err == nil {
		t.Fatal("a server read a frame under a cipher it does not accept")
	}
}
