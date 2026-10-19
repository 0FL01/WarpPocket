// Package trust supplies a versioned, embedded Mozilla CA bundle. No adjacent
// file, Python installation or platform certificate-store bootstrap is needed.
package trust

import (
	"crypto/x509"
	_ "embed"
	"errors"
)

//go:embed roots.pem
var roots []byte

//go:embed NOTICE.txt
var Notice string

func Pool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(roots) {
		return nil, errors.New("embedded CA bundle is invalid")
	}
	return pool, nil
}
