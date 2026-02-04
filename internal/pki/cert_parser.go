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
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// parseCertificatePEM strictly validates a given input PEM bundle to confirm it contains
// only valid CERTIFICATE PEM blocks. If successful, returns nil and invokes addCert for
// each parsed certificate. Any comments or extra non-whitespace data cause an error.
//
// Parameters:
//   - pemData: the PEM-encoded input to validate. Must not be nil.
//   - addCert: callback invoked for each successfully parsed *x509.Certificate.
//     If the callback returns false and there remains unread non-whitespace input,
//     the function returns an error about extra data; if no extra data remains, the
//     function returns nil.
func parseCertificatePEM(pemData []byte, addCert func(*x509.Certificate) (bool, error)) error {
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

		// Only CERTIFICATE blocks are allowed
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found %q", block.Type)
		}

		// We error on PEM blocks with non-empty Headers. Such PEM block headers could
		// contain (accidental) private information. They're also non-standard according to
		// https://www.rfc-editor.org/rfc/rfc7468
		if len(block.Headers) != 0 {
			return fmt.Errorf("invalid PEM block in bundle: PEM headers are not permitted")
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid PEM block in bundle: failed to parse certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("invalid PEM block in bundle: parsed certificate is nil")
		}

		if cont, err := addCert(certificate); err != nil {
			return err
		} else if !cont {
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
