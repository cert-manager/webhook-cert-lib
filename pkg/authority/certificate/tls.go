/*
Copyright 2025 The cert-manager Authors.

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

package certificate

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
)

func GenerateLeaf(
	leafDNSNames []string,
	leafDuration time.Duration,
	caCert *x509.Certificate, caPk crypto.PrivateKey,
) (*x509.Certificate, crypto.Signer, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		DNSNames: leafDNSNames,

		// Validity
		NotBefore: now,
		NotAfter:  now.Add(leafDuration),

		// Basic constraints
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Key usages
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Cap the validity such that it does not extend the validity of the CA
	if template.NotAfter.After(caCert.NotAfter) {
		template.NotAfter = caCert.NotAfter
	}

	// Sign certificate using CA
	_, cert, err := pki.SignCertificate(template, caCert, pk.Public(), caPk)
	return cert, pk, err
}

func GenerateCA(
	caDuration time.Duration,
) (*x509.Certificate, crypto.Signer, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "cert-manager-dynamic-ca",
		},

		// Validity
		NotBefore: now,
		NotAfter:  now.Add(caDuration),

		// Basic constraints
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,

		// Key usages
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// self sign the root CA
	_, cert, err := pki.SignCertificate(template, template, pk.Public(), pk)
	return cert, pk, err
}

func RenewAfter(cert *x509.Certificate) time.Duration {
	return time.Until(cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3))
}
