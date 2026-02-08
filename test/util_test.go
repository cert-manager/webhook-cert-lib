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

package test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func newValidatingWebhookConfigurationForTest(name string, caSecret types.NamespacedName) *admissionregistrationv1.ValidatingWebhookConfiguration {
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

type caTester struct {
	types.NamespacedName
	clientset *k8sfake.Clientset
}

// getPending returns true when the given TLS secret exists and has non-empty cert and key
// and carries the DynamicAuthoritySecretLabel label set to true. It also updates the provided
// secret pointer with latest Data and ResourceVersion for subsequent assertions.
func (ca *caTester) getPending(t *testing.T) *corev1.Secret {
	t.Helper()

	secret, err := ca.clientset.CoreV1().Secrets(ca.Namespace).Get(t.Context(), ca.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error: secret %s/%s not found yet: %v", ca.Namespace, ca.Name, err)
	}

	if secret.Labels[api.DynamicAuthoritySecretLabel] != "true" || secret.Type != corev1.SecretTypeTLS {
		t.Fatalf("error: secret present but not ready: labels=%v type=%s dataKeys=%v", secret.Labels, secret.Type, keysOf(secret.Data))
	}

	if len(secret.Data[api.TLSPendingCertKey]) == 0 {
		t.Fatalf("error: secret present but %q key missing or empty: dataKeys=%v", api.TLSPendingCertKey, keysOf(secret.Data))
	}
	if len(secret.Data[api.TLSPendingPrivateKeyKey]) == 0 {
		t.Fatalf("error: secret present but %q key missing or empty: dataKeys=%v", api.TLSPendingPrivateKeyKey, keysOf(secret.Data))
	}

	isValidCertPEM(t, secret.Data[api.TLSPendingCertKey], secret.Data[api.TLSPendingPrivateKeyKey])

	return secret.DeepCopy()
}

// getReady returns true when the given TLS secret exists and has non-empty cert and key
// and carries the DynamicAuthoritySecretLabel label set to true. It also updates the provided
// secret pointer with latest Data and ResourceVersion for subsequent assertions.
func (ca *caTester) getReady(t *testing.T) *corev1.Secret {
	t.Helper()

	secret, err := ca.clientset.CoreV1().Secrets(ca.Namespace).Get(t.Context(), ca.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error: secret %s/%s not found yet: %v", ca.Namespace, ca.Name, err)
	}

	if secret.Labels[api.DynamicAuthoritySecretLabel] != "true" || secret.Type != corev1.SecretTypeTLS {
		t.Fatalf("error: secret present but not ready: labels=%v type=%s dataKeys=%v", secret.Labels, secret.Type, keysOf(secret.Data))
	}

	if len(secret.Data[api.TLSServingCertKey]) == 0 {
		t.Fatalf("error: secret present but %q key missing or empty: dataKeys=%v", api.TLSServingCertKey, keysOf(secret.Data))
	}
	if len(secret.Data[api.TLSServingPrivateKeyKey]) == 0 {
		t.Fatalf("error: secret present but %q key missing or empty: dataKeys=%v", api.TLSServingPrivateKeyKey, keysOf(secret.Data))
	}

	isValidCertPEM(t, secret.Data[api.TLSServingCertKey], secret.Data[api.TLSServingPrivateKeyKey])

	return secret.DeepCopy()
}

func isValidCertPEM(t *testing.T, pemBytes []byte, keyBytes []byte) {
	t.Helper()

	cert, err := pki.DecodeCertificateFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("error: failed to parse cert PEM: %v", err)
	}

	privKey, err := pki.DecodePrivateKeyBytes(keyBytes)
	if err != nil {
		t.Fatalf("error: failed to parse private key PEM: %v", err)
	}

	ok, err := pki.PublicKeysEqual(cert.PublicKey, privKey.Public())
	if err != nil {
		t.Fatalf("error: failed to compare public keys: %v", err)
	}
	if !ok {
		t.Fatalf("error: cert public key does not match private key")
	}

	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		t.Fatalf("error: cert is not valid at current time %v: NotBefore=%v NotAfter=%v", time.Now(), cert.NotBefore, cert.NotAfter)
	}
}

// keysOf returns keys from map for logging.
func keysOf(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// createTLSSecretWithLabel creates a TLS Secret with the given cert/key and dynamic label.
func (ca *caTester) put(t *testing.T, secret *corev1.Secret) {
	t.Helper()

	secret = secret.DeepCopy()
	secret.Namespace = ca.Namespace
	secret.Name = ca.Name

	_, getErr := ca.clientset.CoreV1().Secrets(ca.Namespace).Get(t.Context(), ca.Name, metav1.GetOptions{})
	exists := getErr == nil

	if exists {
		if _, err := ca.clientset.CoreV1().Secrets(ca.Namespace).Update(t.Context(), secret, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("error: failed update secret %s/%s: %v", ca.Namespace, ca.Name, err)
		}
	} else {
		if _, err := ca.clientset.CoreV1().Secrets(ca.Namespace).Create(t.Context(), secret, metav1.CreateOptions{}); err != nil {
			t.Fatalf("error: failed create secret %s/%s: %v", ca.Namespace, ca.Name, err)
		}
	}

	synctest.Wait()
}

func (ca *caTester) delete(t *testing.T) {
	t.Helper()

	if err := ca.clientset.CoreV1().Secrets(ca.Namespace).Delete(t.Context(), ca.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("error: failed delete secret %s/%s: %v", ca.Namespace, ca.Name, err)
	}

	synctest.Wait()
}

// assertVWCInjectMatchesSecret asserts all webhooks in the VWC have CABundle equal to the secret cert.
func assertVWCInjectMatchesSecret(t *testing.T, clientset *k8sfake.Clientset, vwcName string, secretNN types.NamespacedName) {
	t.Helper()
	s, err := clientset.CoreV1().Secrets(secretNN.Namespace).Get(t.Context(), secretNN.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	got, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(t.Context(), vwcName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get vwc: %v", err)
	}
	if len(got.Webhooks) == 0 {
		t.Fatalf("no webhooks found in VWC %s", vwcName)
	}

	bundle := trustBundle(s)

	for i := range got.Webhooks {
		if string(bundle) != string(got.Webhooks[i].ClientConfig.CABundle) {
			t.Fatalf("webhook %d CABundle didn't match secret", i)
		}
	}
}

func trustBundle(cert *corev1.Secret) []byte {
	certPool := pki.NewCertPool()

	if cert != nil && cert.Data != nil {
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSServingCertKey])
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSPendingCertKey])
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSAllTrustedCertsKey])
	}

	return certPool.PEM()
}
