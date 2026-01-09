/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"slices"
	"strings"
	"time"
)

// CertPool is a set of certificates.
type CertPool struct {
	certificates []*x509.Certificate

	filterExpired bool
}

type Option func(*CertPool)

func WithFilteredExpiredCerts(filterExpired bool) Option {
	return func(cp *CertPool) {
		cp.filterExpired = filterExpired
	}
}

// NewCertPool returns a new, empty CertPool.
// Optionally, it can filter out expired certificates.
func NewCertPool(options ...Option) *CertPool {
	certPool := &CertPool{}

	for _, option := range options {
		option(certPool)
	}

	return certPool
}

func (cp *CertPool) addCert(now time.Time, cert *x509.Certificate) {
	if cp.filterExpired && now.After(cert.NotAfter) {
		return
	}

	i, found := slices.BinarySearchFunc(cp.certificates, cert, func(a, b *x509.Certificate) int {
		return bytes.Compare(a.Raw, b.Raw)
	})
	if found {
		return
	}
	cp.certificates = slices.Insert(cp.certificates, i, cert)
}

func (cp *CertPool) AddCertificatesFromPEM(parser *CertParser, pemData []byte) error {
	return parser.parseCertificatePEM(pemData, func(cert *x509.Certificate) bool {
		cp.addCert(time.Now(), cert)
		return true
	})
}

func (cp *CertPool) PEM() []byte {
	if cp == nil || len(cp.certificates) == 0 {
		return nil
	}

	buffer := bytes.Buffer{}

	for _, cert := range cp.certificates {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil
		}
	}

	return buffer.Bytes()
}

func (cp *CertPool) Certificates() []*x509.Certificate {
	return cp.certificates
}

func (cp *CertPool) HashString() string {
	return HashString(CertificatesHash(cp.certificates...))
}

func HashString(hash [sha256.Size]byte) string {
	return strings.TrimRight(base32.HexEncoding.EncodeToString(hash[:]), "=")
}

func CertificatesHash(certs ...*x509.Certificate) [sha256.Size]byte {
	hash := sha256.New()
	for _, cert := range certs {
		_, _ = hash.Write(cert.Raw)
	}
	var certsHash [sha256.Size]byte
	_ = hash.Sum(certsHash[:0])
	return certsHash
}
