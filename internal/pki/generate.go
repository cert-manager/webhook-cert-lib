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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// EncodePrivateKey will encode a given crypto.PrivateKey by first inspecting
// the type of key encoding and then inspecting the type of key provided.
// It only supports encoding RSA or ECDSA keys.
func EncodePrivateKey(pk crypto.PrivateKey) ([]byte, error) {
	switch k := pk.(type) {
	case *rsa.PrivateKey:
		return encodePKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return encodeECPrivateKey(k)
	case ed25519.PrivateKey:
		return encodePKCS8PrivateKey(k)
	default:
		return nil, fmt.Errorf("error encoding private key: unknown key type: %T", pk)
	}
}

// encodePKCS1PrivateKey will marshal a RSA private key into x509 PEM format.
func encodePKCS1PrivateKey(pk *rsa.PrivateKey) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(pk)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}

	return pem.EncodeToMemory(block)
}

// encodePKCS8PrivateKey will marshal a private key into x509 PEM format.
func encodePKCS8PrivateKey(pk any) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}

	return pem.EncodeToMemory(block), nil
}

// encodeECPrivateKey will marshal an ECDSA private key into x509 PEM format.
func encodeECPrivateKey(pk *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("error encoding private key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}

	return pem.EncodeToMemory(block), nil
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
