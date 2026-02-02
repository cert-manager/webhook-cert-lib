/*
Copyright 2020 The cert-manager Authors.

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func Test__caRequiresRegeneration(t *testing.T) {
	generateSecretData := func(mod func(*x509.Certificate)) map[string][]byte {
		// Generate a certificate and private key pair
		pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		assert.NoError(t, err)
		pkBytes, err := pki.EncodePrivateKey(pk)
		assert.NoError(t, err)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		assert.NoError(t, err)
		cert := &x509.Certificate{
			Version:               3,
			BasicConstraintsValid: true,
			SerialNumber:          serialNumber,
			PublicKeyAlgorithm:    x509.ECDSA,
			Subject: pkix.Name{
				CommonName: "cert-manager-webhook-ca",
			},
			IsCA:      true,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(5 * time.Minute),
			KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		}
		if mod != nil {
			mod(cert)
		}
		cert, err = pki.SignCertificate(cert, cert, pk.Public(), pk)
		assert.NoError(t, err)
		certBytes, err := pki.EncodeX509(cert)
		assert.NoError(t, err)

		return map[string][]byte{
			"tls.crt": certBytes,
			"ca.crt":  certBytes,
			"tls.key": pkBytes,
		}
	}

	tests := []struct {
		name         string
		secret       *corev1.Secret
		expect       bool
		expectReason string
	}{
		{
			name: "Missing data in CA secret (nil data)",
			secret: &corev1.Secret{
				Data: nil,
			},
			expect:       true,
			expectReason: "Missing data in CA secret.",
		},
		{
			name: "Missing data in CA secret (missing ca.crt)",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.key": []byte("private key"),
				},
			},
			expect:       true,
			expectReason: "Missing data in CA secret.",
		},
		{
			name: "Failed to parse data in CA secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt": []byte("cert"),
					"ca.crt":  []byte("cert"),
					"tls.key": []byte("secret"),
				},
			},
			expect:       true,
			expectReason: "Failed to parse data in CA secret.",
		},
		{
			name: "Stored certificate is not marked as a CA",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.IsCA = false
					},
				),
			},
			expect:       true,
			expectReason: "Stored certificate is not marked as a CA.",
		},
		{
			name: "Root CA certificate is JUST nearing expiry",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						lifetime := 10 * time.Hour
						cert.NotBefore = time.Now().Add(-6*lifetime/10 - 1*time.Minute)
						cert.NotAfter = cert.NotBefore.Add(lifetime)
					},
				),
			},
			expect:       true,
			expectReason: "CA certificate is nearing expiry.",
		},
		{
			name: "Root CA certificate is ALMOST nearing expiry",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						lifetime := 10 * time.Hour
						cert.NotBefore = time.Now().Add(-6*lifetime/10 + 1*time.Minute)
						cert.NotAfter = cert.NotBefore.Add(lifetime)
					},
				),
			},
			expect: false,
		},
		{
			name: "Root CA certificate is expired",
			secret: &corev1.Secret{
				Data: generateSecretData(
					func(cert *x509.Certificate) {
						cert.NotBefore = time.Now().Add(-1 * time.Hour)
						cert.NotAfter = time.Now().Add(-1 * time.Minute)
					},
				),
			},
			expect:       true,
			expectReason: "CA certificate is nearing expiry.",
		},
		{
			name: "Ok",
			secret: &corev1.Secret{
				Data: generateSecretData(nil),
			},
			expect:       false,
			expectReason: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			required, reason := caRequiresRegeneration(test.secret)
			if required != test.expect {
				t.Errorf("Expected %v, but got %v", test.expect, required)
			}
			if reason != test.expectReason {
				t.Errorf("Expected %q, but got %q", test.expectReason, reason)
			}
		})
	}
}
