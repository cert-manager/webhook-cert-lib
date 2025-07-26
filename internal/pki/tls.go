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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
)

func ToTLSCertificate(cert *x509.Certificate, pk crypto.Signer) (tls.Certificate, error) {
	pkData, err := EncodePrivateKey(pk)
	if err != nil {
		return tls.Certificate{}, err
	}

	certData, err := EncodeX509(cert)
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tlsCert, nil
}

var (
	ErrCertNotAvailable = errors.New("no tls.Certificate available")
)

type TLSCertificateHolder struct {
	certP atomic.Pointer[tls.Certificate]
}

func (h *TLSCertificateHolder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.certP.Load()
	if cert == nil {
		return nil, ErrCertNotAvailable
	}
	return cert, nil
}

func (h *TLSCertificateHolder) SetCertificate(cert *tls.Certificate) {
	h.certP.Store(cert)
}
