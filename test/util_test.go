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

package test

import (
	"errors"
	"fmt"

	. "github.com/onsi/gomega"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
)

func assertCASecret(secret *corev1.Secret) {
	Eventually(komega.Object(secret)).Should(And(
		HaveField("Labels", HaveKeyWithValue(api.DynamicAuthoritySecretLabel, "true")),
		HaveField("Type", Equal(corev1.SecretTypeTLS)),
		HaveField("Data", And(
			HaveKeyWithValue(corev1.TLSCertKey, Not(BeEmpty())),
			HaveKeyWithValue(corev1.TLSPrivateKeyKey, Not(BeEmpty())),
			HaveKeyWithValue(api.TLSCABundleKey, Not(BeEmpty())),
		)),
	))

	cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	Expect(err).ToNot(HaveOccurred())
	caBundle, err := pki.DecodeX509CertificateSetBytes(secret.Data[api.TLSCABundleKey])
	Expect(err).ToNot(HaveOccurred())

	Expect(secretPublicKeysDiffer(secret)).To(BeFalse())
	Expect(cert.Subject).To(Equal(cert.Issuer))
	Expect(caBundle).To(ContainElement(cert))
}

func NewValidatingWebhookConfigurationForTest(name string, caSecret types.NamespacedName) *admissionregistrationv1.ValidatingWebhookConfiguration {
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	vwc.Name = name
	vwc.Labels = map[string]string{
		api.WantInjectFromSecretNamespaceLabel: caSecret.Namespace,
		api.WantInjectFromSecretNameLabel:      caSecret.Name,
	}
	vwc.Webhooks = []admissionregistrationv1.ValidatingWebhook{
		newValidatingWebhookForTest("foo-webhook.cert-manager.io"),
		newValidatingWebhookForTest("bar-webhook.cert-manager.io"),
	}
	return vwc
}

func newValidatingWebhookForTest(name string) admissionregistrationv1.ValidatingWebhook {
	return admissionregistrationv1.ValidatingWebhook{
		Name:                    name,
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             ptr.To(admissionregistrationv1.SideEffectClassNone),
		ClientConfig: admissionregistrationv1.WebhookClientConfig{
			URL: ptr.To("https://" + name),
		},
	}
}

func secretPublicKeysDiffer(secret *corev1.Secret) (bool, error) {
	pk, err := pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true, fmt.Errorf("secret contains invalid private key data: %w", err)
	}
	x509Cert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid certificate: %w", err)
	}

	equal, err := pki.PublicKeysEqual(x509Cert.PublicKey, pk.Public())
	if err != nil {
		return true, fmt.Errorf("secret contains an invalid key-pair: %w", err)
	}
	if !equal {
		return true, errors.New("secret contains a private key that does not match the certificate")
	}

	return false, nil
}
