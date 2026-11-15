package ws

import "testing"

// gorilla's DefaultDialer honors HTTP_PROXY and HTTPS_PROXY; this dialer must
// connect to the target itself, so none of its variants may set a proxy selector.
func TestStandaloneDialerDoesNotSelectEnvironmentHTTPProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://unused.invalid:1")
	t.Setenv("HTTPS_PROXY", "http://unused.invalid:1")
	for _, test := range []struct {
		name   string
		ownTLS bool
	}{
		{name: "gorilla_tls"},
		{name: "owned_tls", ownTLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer, _, _, err := newGorillaDialer(DialOpts{URL: "wss://fixture.invalid/ws"}, test.ownTLS)
			if err != nil {
				t.Fatal(err)
			}
			if dialer.Proxy != nil {
				t.Fatal("standalone dialer started consulting an HTTP proxy selector")
			}
		})
	}
}
