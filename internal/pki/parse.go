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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificateFromPEM will decode a PEM encoded x509 Certificate.
func ParseCertificateFromPEM(parser *CertParser, certBytes []byte) (*x509.Certificate, error) {
	var returnedCert *x509.Certificate
	return returnedCert, parser.parseCertificatePEM(certBytes, func(cert *x509.Certificate) bool {
		returnedCert = cert
		return false // stop after first cert, will error if there are more
	})
}

func ParseCertificateFromDER(parser *CertParser, derBytes []byte) (*x509.Certificate, error) {
	return parser.parseCertificateDER(derBytes)
}

type publicKeyEqual interface {
	Equal(crypto.PublicKey) bool
}

// PublicKeysEqual compares two public keys for equivalence across supported types.
func PublicKeysEqual(a, b any) (bool, error) {
	if ak, ok := a.(publicKeyEqual); ok {
		return ak.Equal(b), nil
	}

	return false, fmt.Errorf("unsupported public key type %T", a)
}

// DecodePrivateKeyBytes will decode a PEM encoded private key into a crypto.Signer.
// It supports ECDSA and RSA private keys only. All other types will return err.
func DecodePrivateKeyBytes(keyBytes []byte) (crypto.Signer, error) {
	// decode the private key pem
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding private key PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: %s", err.Error())
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("error parsing pkcs#8 private key: invalid key type")
		}
		return signer, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing ecdsa private key: %s", err.Error())
		}

		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing rsa private key: %s", err.Error())
		}

		err = key.Validate()
		if err != nil {
			return nil, fmt.Errorf("rsa private key failed validation: %s", err.Error())
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unknown private key type: %s", block.Type)
	}
}
