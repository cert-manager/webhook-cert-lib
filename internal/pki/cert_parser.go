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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
)

type CertParser struct {
	parsedCerts []parsedCert
}

func NewCertParser() *CertParser {
	return &CertParser{}
}

type parsedCert struct {
	certBytes   []byte
	certificate *x509.Certificate
	err         error
}

func (cp *CertParser) parseCertificateDER(certBytes []byte) (*x509.Certificate, error) {
	i, found := slices.BinarySearchFunc(cp.parsedCerts, certBytes, func(a parsedCert, b []byte) int {
		return bytes.Compare(a.certBytes, b)
	})
	if found {
		parsedCert := cp.parsedCerts[i]
		return parsedCert.certificate, parsedCert.err
	}

	certificate, err := x509.ParseCertificate(certBytes)
	cp.parsedCerts = slices.Insert(cp.parsedCerts, i, parsedCert{
		certBytes:   certBytes,
		certificate: certificate,
		err:         err,
	})
	return certificate, err
}

// parseCertificatePEM strictly validates a given input PEM bundle to confirm it contains
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
func (cp *CertParser) parseCertificatePEM(pemData []byte, addCert func(*x509.Certificate) bool) error {
	if pemData == nil {
		return fmt.Errorf("certificate data can't be nil")
	}

	readAllPEM := false
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)

		if block == nil {
			readAllPEM = true
			break
		}

		if block.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", block.Type)
		}

		if len(block.Headers) != 0 {
			return fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		certificate, err := cp.parseCertificateDER(block.Bytes)
		if err != nil {
			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("failed appending a certificate: certificate is nil")
		}

		if !addCert(certificate) {
			break
		}
	}

	if len(pemData) > 0 {
		if !readAllPEM {
			return fmt.Errorf("extra PEM data found after processing PEM blocks")
		} else {
			return fmt.Errorf("extra non-PEM data found after processing PEM blocks")
		}
	}

	return nil
}
