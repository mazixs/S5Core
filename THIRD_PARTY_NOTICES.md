# Third-party origins and notices

S5Core is maintained and developed in this repository. Its current transports,
session lifecycle, account management, observability and SDK extend well beyond
the original proxy implementation. That development does not mean all inherited
code has disappeared.

This file records inherited source components. It is not a complete license
inventory of the external dependencies listed in `go.mod`.

## armon/go-socks5

[Upstream](https://github.com/armon/go-socks5) is the source of the modified
SOCKS5 implementation in [`internal/socks5`](internal/socks5/).
It was already present in the first code-bearing commit, `b0c0898`; commit
`d701bc0` switched the server from the external module to this internal package.

Retained examples include `CredentialStore` and `StaticCredentials.Valid` in
[`credentials.go`](internal/socks5/credentials.go), and the `PermitCommand`
structure and dispatch in [`ruleset.go`](internal/socks5/ruleset.go), extended
with the project's UDP tunnel command. The fork also retains and modifies the
original server, authentication and request-handling interfaces.

The original MIT notice, Copyright (c) 2014 Armon Dadgar, is preserved in
[`internal/socks5/LICENSE`](internal/socks5/LICENSE). See the
[component history and extensions](internal/socks5/README.md).

## serjs/socks5-server

[Upstream](https://github.com/serjs/socks5-server) is the historical starting
point for the standalone proxy configuration and destination-filtering layer.
It is a separate project from `armon/go-socks5`, which it also uses.

The original `PROXY_*`, `REQUIRE_AUTH`, `ALLOWED_IPS` and `ALLOWED_DEST_FQDN`
configuration is recognizable in [`cmd/s5core/main.go`](cmd/s5core/main.go).
`PermitDestAddrPattern` and `PermitDestAddrPatternRuleSet` survive, with a
substantially revised implementation, in
[`internal/s5core/ruleset.go`](internal/s5core/ruleset.go).

This is an attribution of origin, not a claim that the current S5Core
architecture or most of its functionality comes from that small server.
The upstream MIT notice is reproduced below from its
[LICENSE](https://github.com/serjs/socks5-server/blob/master/LICENSE).

```text
MIT License

Copyright (c) 2025 Sergey Bogatyrets

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
