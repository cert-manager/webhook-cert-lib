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

package authority

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
)

type CertInfo struct {
	Hash       string    `json:"hash"`
	ValidUntil time.Time `json:"validUntil"`
}

func (c *CertInfo) String() string {
	return c.Hash + " (valid until " + c.ValidUntil.Format(time.RFC3339) + ")"
}

func certInfo(cert *x509.Certificate) CertInfo {
	return CertInfo{
		Hash:       pki.HashString(pki.CertificatesHash(cert)),
		ValidUntil: cert.NotAfter,
	}
}

func certInfoFromPEM(certPEM []byte) any {
	if len(certPEM) == 0 {
		return "<empty>"
	}

	cert, err := pki.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate PEM: %w", err)
	}

	return certInfo(cert)
}

func certsInfoFromPEM(certsPEM []byte) any {
	if len(certsPEM) == 0 {
		return "<empty>"
	}

	certPool := pki.NewCertPool()
	if err := certPool.AddCertificatesFromPEM(certsPEM); err != nil {
		return fmt.Errorf("failed to parse certificates PEM: %w", err)
	}

	certs := certPool.Certificates()

	certsInfo := make([]CertInfo, 0, len(certs))
	for _, cert := range certs {
		certsInfo = append(certsInfo, CertInfo{
			Hash:       pki.HashString(pki.CertificatesHash(cert)),
			ValidUntil: cert.NotAfter,
		})
	}

	return certsInfo
}
