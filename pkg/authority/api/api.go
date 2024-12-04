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

package api

const (
	// DynamicAuthoritySecretLabel will - if set to "true" - make the dynamic
	// authority CA controller inject and maintain a dynamic CA.
	// The label must be added to Secret resource that want to denote that they
	// can be directly injected into injectables that have a
	// `inject-dynamic-ca-from-secret` label.
	// If an injectable references a Secret that does NOT have this annotation,
	// the dynamic ca-injector will refuse to inject the secret.
	DynamicAuthoritySecretLabel = "cert-manager.io/allow-dynamic-ca-injection"
	// WantInjectFromSecretNamespaceLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret in
	// namespace.
	// Must be used in conjunction with WantInjectFromSecretNameLabel.
	WantInjectFromSecretNamespaceLabel = "cert-manager.io/inject-dynamic-ca-from-secret-namespace"
	// WantInjectFromSecretNameLabel is the label that specifies that a
	// particular object wants injection of dynamic CAs from secret with name.
	// Must be used in conjunction with WantInjectFromSecretNamespaceLabel.
	WantInjectFromSecretNameLabel = "cert-manager.io/inject-dynamic-ca-from-secret-name"

	// TLSCABundleKey is used as a data key in Secret resources to store a CA
	// certificate bundle.
	TLSCABundleKey = "ca-bundle.crt"

	// RenewCertificateSecretAnnotation is an annotation that can be set to
	// an arbitrary value on a certificate secret to trigger a renewal of the
	// certificate managed in the secret.
	RenewCertificateSecretAnnotation = "renew.cert-manager.io/requestedAt"
	// RenewHandledCertificateSecretAnnotation is an annotation that will be set on a
	// certificate secret whenever a new certificate is renewed using the
	// RenewCertificateSecretAnnotation annotation.
	RenewHandledCertificateSecretAnnotation = "renew.cert-manager.io/lastRequestedAt"
)
