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

package api

import corev1 "k8s.io/api/core/v1"

const (
	// DynamicAuthoritySecretLabel will - if set to "true" - make the dynamic
	// authority CA controller inject and maintain a dynamic CA.
	// The label must be added to Secret resource that want to denote that they
	// can be directly injected into injectables that have a
	// `inject-dynamic-ca-from-secret` label.
	// If an injectable references a Secret that does NOT have this annotation,
	// the dynamic ca-injector will refuse to inject the secret.
	DynamicAuthoritySecretLabel = "cert-manager.io/allow-dynamic-ca-injection" //#nosec G101 - This is not credentials
	// WantInjectFromSecretNamespaceLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret in
	// namespace.
	// Must be used in conjunction with WantInjectFromSecretNameLabel.
	WantInjectFromSecretNamespaceLabel = "cert-manager.io/inject-dynamic-ca-from-secret-namespace" //#nosec G101 - This is not credentials
	// WantInjectFromSecretNameLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret with name.
	// Must be used in conjunction with WantInjectFromSecretNamespaceLabel.
	WantInjectFromSecretNameLabel = "cert-manager.io/inject-dynamic-ca-from-secret-name" //#nosec G101 - This is not credentials

	// TLSPendingCertKey stores a pending (new) CA cert PEM while it is being
	// propagated to targets. It will be promoted to `tls_serving.crt` after
	// `Options.PropagationDelay` has elapsed since the rotation timestamp.
	TLSPendingCertKey = corev1.TLSCertKey

	// TLSPendingPrivateKeyKey stores the private key corresponding to the
	// pending cert in `TLSPendingCertKey`.
	TLSPendingPrivateKeyKey = corev1.TLSPrivateKeyKey

	TLSServingCertKey       = "tls_serving.crt"
	TLSServingPrivateKeyKey = "tls_serving.key"

	TLSAllTrustedCertsKey = "all_trusted_certs.crt"

	IssuingAuthorityIDAnnotation = "cert-manager.io/issuing-authority-id"

	// InjectedAtTimestampAnnotation marks the time the pending cert has been added
	// to all trust stores. It is used to decide when it can be promoted to serving.
	// It corresponds to the version specified in InjectedLastVersionAnnotation.
	InjectedAtTimestampAnnotation = "cert-manager.io/injected-at-timestamp"

	// InjectedLastVersionAnnotation marks the last version of the secret that
	// has been injected into all targets. It is updated at the same time as
	// InjectedAtTimestampAnnotation. It is the hash of the bundle that was
	// injected.
	InjectedLastVersionAnnotation = "cert-manager.io/injected-last-version"
)
