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

package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// SignCertificate returns a signed *x509.Certificate given a template
// *x509.Certificate crt and an issuer.
// publicKey is the public key of the signee, and signerKey is the private
// key of the signer.
// It returns a parsed *x509.Certificate on success.
func SignCertificate(certParser *CertParser, template *x509.Certificate, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey any) (*x509.Certificate, error) {
	typedSigner, ok := signerKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("didn't get an expected Signer in call to SignCertificate")
	}

	var pubKeyAlgo x509.PublicKeyAlgorithm
	var sigAlgoArg any

	// NB: can't rely on issuerCert.Public or issuercert.PublicKeyAlgorithm being set reliably;
	// but we know that signerKey.Public() will work!
	switch pubKey := typedSigner.Public().(type) {
	case *rsa.PublicKey:
		pubKeyAlgo = x509.RSA

		// Size is in bytes so multiply by 8 to get bits because they're more familiar
		// This is technically not portable but if you're using cert-manager on a platform
		// with bytes that don't have 8 bits, you've got bigger problems than this!
		sigAlgoArg = pubKey.Size() * 8

	case *ecdsa.PublicKey:
		pubKeyAlgo = x509.ECDSA
		sigAlgoArg = pubKey.Curve

	case ed25519.PublicKey:
		pubKeyAlgo = x509.Ed25519
		sigAlgoArg = nil // ignored by signatureAlgorithmFromPublicKey

	default:
		return nil, fmt.Errorf("unknown public key type on signing certificate: %T", issuerCert.PublicKey)
	}

	var err error
	template.SignatureAlgorithm, err = signatureAlgorithmFromPublicKey(pubKeyAlgo, sigAlgoArg)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerCert, publicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %w", err)
	}

	cert, err := DecodeCertificateFromDER(certParser, derBytes)
	if err != nil {
		return nil, fmt.Errorf("error decoding DER certificate bytes: %w", err)
	}

	return cert, nil
}

// EncodeCertificateAsPEM will encode a single *x509.Certificate into PEM format.
func EncodeCertificateAsPEM(cert *x509.Certificate) ([]byte, error) {
	caPem := bytes.NewBuffer([]byte{})
	err := pem.Encode(caPem, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}

	return caPem.Bytes(), nil
}

// signatureAlgorithmFromPublicKey takes a public key type and an argument specific to that public
// key, and returns an appropriate signature algorithm for that key.
// If alg is x509.RSA, arg must be an integer key size in bits
// If alg is x509.ECDSA, arg must be an elliptic.Curve
// If alg is x509.Ed25519, arg is ignored
// All other algorithms and args cause an error
// The signature algorithms returned by this function are to some degree a matter of preference. The
// choices here are motivated by what is common and what is required by bodies such as the US DoD.
func signatureAlgorithmFromPublicKey(alg x509.PublicKeyAlgorithm, arg any) (x509.SignatureAlgorithm, error) {
	var signatureAlgorithm x509.SignatureAlgorithm

	switch alg { //nolint:exhaustive // There is a default that appears to be not picked up by the linter
	case x509.RSA:
		size, ok := arg.(int)
		if !ok {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("expected to get an integer key size for RSA key but got %T", arg)
		}

		switch {
		case size >= 4096:
			signatureAlgorithm = x509.SHA512WithRSA

		case size >= 3072:
			signatureAlgorithm = x509.SHA384WithRSA

		case size >= 2048:
			signatureAlgorithm = x509.SHA256WithRSA

		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("invalid size %d for RSA key on signing certificate", size)
		}

	case x509.ECDSA:
		curve, ok := arg.(elliptic.Curve)
		if !ok {
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("expected to get an ECDSA curve for ECDSA key but got %T", arg)
		}

		switch curve {
		case elliptic.P521():
			signatureAlgorithm = x509.ECDSAWithSHA512

		case elliptic.P384():
			signatureAlgorithm = x509.ECDSAWithSHA384

		case elliptic.P256():
			signatureAlgorithm = x509.ECDSAWithSHA256

		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown / unsupported curve attached to ECDSA signing certificate")
		}

	case x509.Ed25519:
		signatureAlgorithm = x509.PureEd25519

	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("got unsupported public key type when trying to calculate signature algorithm")
	}

	return signatureAlgorithm, nil
}
