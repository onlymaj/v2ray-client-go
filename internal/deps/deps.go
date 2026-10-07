// Package deps pins the allowed third-party modules in go.mod until real
// code imports them. Delete once every module is imported elsewhere.
package deps

import (
	_ "github.com/refraction-networking/utls"
	_ "golang.org/x/crypto/chacha20poly1305"
	_ "golang.org/x/crypto/hkdf"
	_ "golang.org/x/crypto/scrypt"
	_ "golang.org/x/crypto/x509roots/fallback"
	_ "golang.org/x/net/http2"
)
