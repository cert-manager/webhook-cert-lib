/*
Copyright 2022 The cert-manager Authors.

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
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// CertPool is a set of certificates.
type CertPool struct {
	certificates map[[sha256.Size]byte]*x509.Certificate

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
	certPool := &CertPool{
		certificates: make(map[[sha256.Size]byte]*x509.Certificate),
	}

	for _, option := range options {
		option(certPool)
	}

	return certPool
}

func (cp *CertPool) addCert(now time.Time, cert *x509.Certificate) error {
	if cert == nil || len(cert.Raw) == 0 {
		return fmt.Errorf("adding nil Certificate to CertPool")
	}
	if cp.filterExpired && now.After(cert.NotAfter) {
		return nil
	}

	hash := sha256.Sum256(cert.Raw)
	cp.certificates[hash] = cert
	return nil
}

func (cp *CertPool) AddCertificatesFromPEM(pemData []byte) error {
	now := time.Now()
	return parseCertificatePEM(pemData, func(cert *x509.Certificate) (bool, error) {
		if err := cp.addCert(now, cert); err != nil {
			return false, err
		}
		return true, nil
	})
}

func (cp *CertPool) AddCertificate(cert *x509.Certificate) error {
	return cp.addCert(time.Now(), cert)
}

func (cp *CertPool) PEM() []byte {
	if cp == nil || len(cp.certificates) == 0 {
		return nil
	}

	buffer := bytes.Buffer{}

	for _, cert := range cp.certificates {
		if err := pem.Encode(&buffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return nil
		}
	}

	return buffer.Bytes()
}

func (cp *CertPool) Certificates() []*x509.Certificate {
	hashes := maps.Keys(cp.certificates)

	sortedHashes := slices.SortedFunc(hashes, func(i, j [sha256.Size]byte) int {
		return bytes.Compare(i[:], j[:])
	})

	orderedCertificates := make([]*x509.Certificate, 0, len(cp.certificates))
	for _, hash := range sortedHashes {
		orderedCertificates = append(orderedCertificates, cp.certificates[hash])
	}
	return orderedCertificates
}

func (cp *CertPool) HashString() string {
	return HashString(CertificatesHash(cp.Certificates()...))
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
