# cDesk SOCKS5 gateway / go-socks5

This fork adds a small authenticated TCP CONNECT service for a LAN gateway that can reach RustDesk hbbs, hbbr and HTTPS API endpoints.
See [Windows x64 setup](docs/windows-quickstart.md) and [configuration example](config.example.json).
Version 0.2.0 adds an opt-in [OSS protocol adapter behind the same SOCKS5 interface](docs/rustdesk-oss-bridge.md): set `oss_hbbs_port` on an approved target to bridge RustDesk registration to OSS UDP, while retaining TCP relay and API tunnels. See [OSS configuration](config.oss.example.json). It uses the client's legacy plaintext signalling compatibility path and does not implement a signed server key exchange. Without this adapter, the official client's TCP registration is incompatible with OSS hbbs; see [upstream issue #13010](https://github.com/rustdesk/rustdesk/issues/13010).
Build with `./scripts/build-windows.ps1`; place `config.json` beside the executable and run `cdesk-socks5-windows-amd64.exe` without arguments. NSSM can manage it as a Windows service.
The library module path is retained for upstream compatibility. The service is based on upstream v0.1.3.

The upstream library documentation follows.

[![GoDoc](https://godoc.org/github.com/things-go/go-socks5?status.svg)](https://godoc.org/github.com/things-go/go-socks5)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/things-go/go-socks5?tab=doc)
![Action Status](https://github.com/things-go/go-socks5/workflows/Go/badge.svg)
[![codecov](https://codecov.io/gh/things-go/go-socks5/branch/master/graph/badge.svg)](https://codecov.io/gh/things-go/go-socks5)
[![Go Report Card](https://goreportcard.com/badge/github.com/things-go/go-socks5)](https://goreportcard.com/report/github.com/things-go/go-socks5)
[![License](https://img.shields.io/github/license/things-go/go-socks5)](https://github.com/things-go/go-socks5/raw/master/LICENSE)
[![Tag](https://img.shields.io/github/v/tag/things-go/go-socks5)](https://github.com/things-go/go-socks5/tags)

Provides the `socks5` package that implements a [SOCKS5](http://en.wikipedia.org/wiki/SOCKS).
SOCKS (Secure Sockets) is used to route traffic between a client and server through
an intermediate proxy layer. This can be used to bypass firewalls or NATs.

### Feature


The package has the following features:
- Support socks5 server
- Support TCP/UDP and IPv4/IPv6
- Unit tests
- "No Auth" mode
- User/Password authentication optional user addr limit
- Support for the CONNECT command
- Support for the ASSOCIATE command
- Rules to do granular filtering of commands
- Custom DNS resolution
- Custom goroutine pool
- buffer pool design and optional custom buffer pool
- Custom logger

### TODO

The package still needs the following:
- Support for the BIND command

### Installation

Use go get.
```bash
    go get github.com/things-go/go-socks5
```

Then import the socks5 server package into your own code.

```bash
    import "github.com/things-go/go-socks5"
```

### Example

Below is a simple example of usage, more see [example](https://github.com/things-go/go-socks5/tree/master/_example)

[embedmd]:# (_example/main.go go)
```go
package main

import (
	"log"
	"os"

	"github.com/things-go/go-socks5"
)

func main() {
	// Create a SOCKS5 server
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", ":8000"); err != nil {
		panic(err)
	}
}
```

### Reference
- [rfc1928](https://www.ietf.org/rfc/rfc1928.txt) 
- original armon's [go-sock5](https://github.com/armon/go-socks5) library

## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.

