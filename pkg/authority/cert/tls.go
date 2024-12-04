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

package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func GenerateLeaf(
	leafDNSNames []string,
	leafDuration time.Duration,
	caCert *x509.Certificate, caPk crypto.PrivateKey,
) (*x509.Certificate, crypto.Signer, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: serialNumber,

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
	if cert.NotAfter.After(caCert.NotAfter) {
		cert.NotAfter = caCert.NotAfter
	}

	// Sign certificate using CA
	_, cert, err = pki.SignCertificate(cert, caCert, pk.Public(), caPk)
	return cert, pk, err
}

func GenerateCA(
	caDuration time.Duration,
) (*x509.Certificate, crypto.Signer, error) {
	pk, err := pki.GenerateECPrivateKey(384)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cert := &x509.Certificate{
		Version:      3,
		SerialNumber: serialNumber,

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
	_, cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
	return cert, pk, err
}

var (
	ErrCertNotAvailable = errors.New("no tls.Certificate available")
)

type CertificateHolder struct {
	certP atomic.Pointer[tls.Certificate]
}

func (h *CertificateHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.certP.Load()
	if cert == nil {
		return nil, ErrCertNotAvailable
	}
	return cert, nil
}

func (h *CertificateHolder) SetCertificate(cert *tls.Certificate) {
	h.certP.Store(cert)
}
