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

package authority

import (
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	admissionregistrationlisters "k8s.io/client-go/listers/admissionregistration/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cert-manager/webhook-cert-lib/internal/certificate"
	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
)

func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func stringsEqual(t *testing.T, expected, actual string) {
	t.Helper()

	if expected != actual {
		t.Fatalf("strings not equal:\nexpected: %q\nactual:   %q", expected, actual)
	}
}

func bytesNotEmpty(t *testing.T, notEmpty []byte) {
	t.Helper()

	if len(notEmpty) == 0 {
		t.Fatalf("expected byte slice to be not empty")
	}
}

// newSecretLister returns a SecretLister backed by a fresh indexer and a helper
// function to add Secrets to it.
func newSecretLister(t *testing.T) (corelisters.SecretLister, func(obj *corev1.Secret)) {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	add := func(obj *corev1.Secret) {
		requireNoError(t, indexer.Add(obj))
	}
	return corelisters.NewSecretLister(indexer), add
}

// newVWCLister returns a ValidatingWebhookConfigurationLister backed by a fresh indexer and a helper
// function to add VWCs to it.
func newVWCLister(t *testing.T) (admissionregistrationlisters.ValidatingWebhookConfigurationLister, func(obj *admissionregistrationv1.ValidatingWebhookConfiguration)) {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	add := func(obj *admissionregistrationv1.ValidatingWebhookConfiguration) {
		requireNoError(t, indexer.Add(obj))
	}
	return admissionregistrationlisters.NewValidatingWebhookConfigurationLister(indexer), add
}

func TestProcessReinjectUpdatesWebhookCABundle(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset()

	// Prepare listers
	secretLister, addSecret := newSecretLister(t)
	vwcLister, addVWC := newVWCLister(t)

	// CA secret with bundle: generate a real CA cert and key so checkCA() can parse it.
	caNS, caName := "ns", "ca"
	caCert, caKey, err := certificate.GenerateCA(24 * time.Hour)
	requireNoError(t, err)
	caCertPEM, err := pki.EncodeCertificateAsPEM(caCert)
	requireNoError(t, err)
	caKeyPEM, err := pki.EncodePrivateKey(caKey)
	requireNoError(t, err)
	caBundle := caCertPEM
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: caNS, Name: caName}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{api.TLSServingCertKey: caBundle, api.TLSServingPrivateKeyKey: caKeyPEM}}
	addSecret(sec)

	// Existing VWC in client with wrong CABundle, and present in lister
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "vwc1", Labels: map[string]string{
		api.WantInjectFromSecretNamespaceLabel: caNS,
		api.WantInjectFromSecretNameLabel:      caName,
	}}, Webhooks: []admissionregistrationv1.ValidatingWebhook{{
		Name:         "wh1",
		ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("old")},
	}, {
		Name:         "wh2",
		ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("old")},
	}}}
	_, err = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(t.Context(), vwc.DeepCopy(), metav1.CreateOptions{})
	requireNoError(t, err)
	addVWC(vwc)

	a := &Authority{
		Options: AuthorityOptions{
			AuthorityCertificate: AuthorityCertificateOptions{
				SecretNamespacedName: typesNN(caNS, caName),
			},
			PromotionDelay: 1 * time.Millisecond,
		},
		clientset:    cs,
		secretLister: secretLister,
		injectableListPatchers: map[schema.GroupVersionKind]injectable.ListPatcher{
			admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"): &injectable.ValidatingWebhookCaBundleInjectListPatcher{
				Client: cs,
				Lister: vwcLister,
			},
		},
		newQueue: func() workqueue.TypedRateLimitingInterface[queueKey] { return nil },
	}
	// Provide queue same as in production
	a.newQueue = newTypedQueue
	a.queue = a.newQueue()

	// Enqueue reinjection and process
	a.queue.Add(reconcileAllTargetsKey)
	_ = a.processNextWorkItem(t.Context()) // reconcile secret and enqueue targets
	_ = a.processNextWorkItem(t.Context()) // reconcile single target

	// Assert CABundle updated in cluster
	got, err := cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(t.Context(), vwc.Name, metav1.GetOptions{})
	requireNoError(t, err)

	if len(got.Webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(got.Webhooks))
	}
	for i := range got.Webhooks {
		stringsEqual(t, string(caBundle), string(got.Webhooks[i].ClientConfig.CABundle))
	}
}

// Ensure that when a pending cert exists but not all targets have been
// injected, reconcile does not promote it.
func TestPendingNotPromotedIfTargetsNotInjected(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset()
	secretLister, addSecret := newSecretLister(t)

	// seed secret with pending cert and different CABundle on VWC
	caCert, caPK, err := certificate.GenerateCA(40 * time.Hour)
	requireNoError(t, err)
	certPEM, err := pki.EncodeCertificateAsPEM(caCert)
	requireNoError(t, err)
	keyPEM, err := pki.EncodePrivateKey(caPK)
	requireNoError(t, err)
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ca"}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{
		api.TLSPendingCertKey:       certPEM,
		api.TLSPendingPrivateKeyKey: keyPEM,
	}}
	addSecret(sec)
	_, err = cs.CoreV1().Secrets("ns").Create(t.Context(), sec.DeepCopy(), metav1.CreateOptions{})
	requireNoError(t, err)

	// prepare a VWC lister with a webhook that does not have the pending bundle
	vwcLister, addVWC := newVWCLister(t)
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "vwc1"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:         "wh1",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{CABundle: []byte("other")},
		}},
	}
	addVWC(vwc)

	a := &Authority{
		Options: AuthorityOptions{
			AuthorityCertificate: AuthorityCertificateOptions{
				SecretNamespacedName: typesNN("ns", "ca"),
			},
		},
		clientset:    cs,
		secretLister: secretLister,
		injectableListPatchers: map[schema.GroupVersionKind]injectable.ListPatcher{
			admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"): &injectable.ValidatingWebhookCaBundleInjectListPatcher{
				Client: cs,
				Lister: vwcLister,
			},
		},
		newQueue: newTypedQueue,
	}
	a.queue = a.newQueue()

	a.queue.Add(reconcilePendingCAKey)
	_ = a.processNextWorkItem(t.Context())

	s, err := cs.CoreV1().Secrets("ns").Get(t.Context(), "ca", metav1.GetOptions{})
	requireNoError(t, err)
	// pending should still be present and not promoted
	stringsEqual(t, string(certPEM), string(s.Data[api.TLSPendingCertKey]))
	stringsEqual(t, string(keyPEM), string(s.Data[api.TLSPendingPrivateKeyKey]))
}

// If a Secret exists but is not type TLS, reconcile should still write
// pending fields (treat as unhealthy CA) so rotation proceeds.
//
// TODO: I believe the fake clientset does not enforce immutability of Secret.Type,
// so this test may not be fully valid.
func TestSecretWrongTypeCreatesPending(t *testing.T) {
	t.Parallel()

	cs := fake.NewClientset()
	secretLister, addSecret := newSecretLister(t)

	// create a non-TLS secret in lister and client
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ca"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{},
	}
	addSecret(sec)
	_, err := cs.CoreV1().Secrets("ns").Create(t.Context(), sec.DeepCopy(), metav1.CreateOptions{})
	requireNoError(t, err)

	// create a no-op VWC lister so reconcileCASecret doesn't nil-deref it
	vwcLister, _ := newVWCLister(t)

	a := &Authority{
		Options: AuthorityOptions{
			AuthorityCertificate: AuthorityCertificateOptions{
				SecretNamespacedName: typesNN("ns", "ca"),
			},
		},
		clientset:    cs,
		secretLister: secretLister,
		injectableListPatchers: map[schema.GroupVersionKind]injectable.ListPatcher{
			admissionregistrationv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"): &injectable.ValidatingWebhookCaBundleInjectListPatcher{
				Client: cs,
				Lister: vwcLister,
			},
		},
		newQueue: newTypedQueue,
	}
	a.queue = a.newQueue()

	a.queue.Add(reconcilePendingCAKey)
	_ = a.processNextWorkItem(t.Context())

	s, err := cs.CoreV1().Secrets("ns").Get(t.Context(), "ca", metav1.GetOptions{})
	requireNoError(t, err)
	// ensure pending fields were written
	bytesNotEmpty(t, s.Data[api.TLSPendingCertKey])
	bytesNotEmpty(t, s.Data[api.TLSPendingPrivateKeyKey])
}

// Minimal typed wrappers so we can use the same workqueue types as production code without
// importing generics directly in test code. This keeps the test decoupled from queue construction details.
func newTypedQueue() workqueue.TypedRateLimitingInterface[queueKey] {
	return workqueue.NewTypedRateLimitingQueueWithConfig(
		workqueue.DefaultTypedControllerRateLimiter[queueKey](),
		workqueue.TypedRateLimitingQueueConfig[queueKey]{Name: "authority-test"},
	)
}

// typesNN is a small helper to build a NamespacedName inline without importing the type in test code.
func typesNN(ns, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: ns, Name: name}
}
