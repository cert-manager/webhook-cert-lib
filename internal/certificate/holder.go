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
	"crypto/tls"
	"errors"
	"sync/atomic"
)

var (
	ErrCertNotAvailable = errors.New("no tls.Certificate available")
)

type Holder struct {
	certP atomic.Pointer[tls.Certificate]
}

func (h *Holder) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.certP.Load()
	if cert == nil {
		return nil, ErrCertNotAvailable
	}
	return cert, nil
}

func (h *Holder) SetCertificate(cert *tls.Certificate) {
	h.certP.Store(cert)
}
