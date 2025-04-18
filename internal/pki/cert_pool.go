/*
Copyright The cert-manager Authors.

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
	"encoding/pem"
	"fmt"
	"slices"
	"time"
)

// CertPool is a set of certificates.
type CertPool struct {
	certificates map[[32]byte]*x509.Certificate

	filterExpired bool
}

type Option func(*CertPool)

func WithFilteredExpiredCerts(filterExpired bool) Option {
	return func(cp *CertPool) {
		cp.filterExpired = filterExpired
	}
}

// NewCertPool returns a new, empty CertPool.
// It will deduplicate certificates based on their SHA256 hash.
// Optionally, it can filter out expired certificates.
func NewCertPool(options ...Option) *CertPool {
	certPool := &CertPool{
		certificates: make(map[[32]byte]*x509.Certificate),
	}

	for _, option := range options {
		option(certPool)
	}

	return certPool
}

func (cp *CertPool) AddCert(cert *x509.Certificate) bool {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}
	if cp.filterExpired && time.Now().After(cert.NotAfter) {
		return false
	}

	hash := sha256.Sum256(cert.Raw)
	cp.certificates[hash] = cert
	return true
}

// AddCertsFromPEM strictly validates a given input PEM bundle to confirm it contains
// only valid CERTIFICATE PEM blocks. If successful, returns the validated PEM blocks with any
// comments or extra data stripped.
//
// This validation is broadly similar to the standard library function
// crypto/x509.CertPool.AppendCertsFromPEM - that is, we decode each PEM block at a time and parse
// it as a certificate.
//
// The difference here is that we want to ensure that the bundle _only_ contains certificates, and
// not just skip over things which aren't certificates.
//
// If, for example, someone accidentally used a combined cert + private key as an input to a trust
// bundle, we wouldn't want to then distribute the private key in the target.
//
// In addition, the standard library AppendCertsFromPEM also silently skips PEM blocks with
// non-empty Headers. We error on such PEM blocks, for the same reason as above; headers could
// contain (accidental) private information. They're also non-standard according to
// https://www.rfc-editor.org/rfc/rfc7468
//
// Additionally, if the input PEM bundle contains no non-expired certificates, an error is returned.
// TODO: Reconsider what should happen if the input only contains expired certificates.
func (cp *CertPool) AddCertsFromPEM(pemData []byte) error {
	if pemData == nil {
		return fmt.Errorf("certificate data can't be nil")
	}

	ok := false
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", block.Type)
		}

		if len(block.Headers) != 0 {
			return fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("failed appending a certificate: certificate is nil")
		}

		if cp.AddCert(certificate) {
			ok = true // at least one non-expired certificate was found in the input
		}
	}

	if !ok {
		return fmt.Errorf("no non-expired certificates found in input bundle")
	}

	return nil
}

// Get certificates quantity in the certificates pool
func (cp *CertPool) Size() int {
	return len(cp.certificates)
}

func (cp *CertPool) PEM() string {
	if cp == nil || len(cp.certificates) == 0 {
		return ""
	}

	buffer := bytes.Buffer{}

	for _, cert := range cp.Certificates() {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return ""
		}
	}

	return string(bytes.TrimSpace(buffer.Bytes()))
}

func (cp *CertPool) PEMSplit() []string {
	if cp == nil || len(cp.certificates) == 0 {
		return nil
	}

	pems := make([]string, 0, len(cp.certificates))
	for _, cert := range cp.Certificates() {
		pems = append(pems, string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))))
	}

	return pems
}

// Get the list of all x509 Certificates in the certificates pool
func (cp *CertPool) Certificates() []*x509.Certificate {
	hashes := make([][32]byte, 0, len(cp.certificates))
	for hash := range cp.certificates {
		hashes = append(hashes, hash)
	}

	slices.SortFunc(hashes, func(i, j [32]byte) int {
		return bytes.Compare(i[:], j[:])
	})

	orderedCertificates := make([]*x509.Certificate, 0, len(cp.certificates))
	for _, hash := range hashes {
		orderedCertificates = append(orderedCertificates, cp.certificates[hash])
	}

	return orderedCertificates
}
