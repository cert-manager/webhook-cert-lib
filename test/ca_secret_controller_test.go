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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CA Secret Controller", Ordered, func() {
	var (
		caSecret    *corev1.Secret
		caSecretRef types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "cert-ca-secret-controller"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecretRef = types.NamespacedName{
			Namespace: ns.Name,
			Name:      "ca-cert",
		}

		opts := authority.Options{
			CAOptions: authority.CAOptions{
				NamespacedName: caSecretRef,
				Duration:       7 * time.Hour,
			}}

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		controller := &authority.CASecretReconciler{
			Reconciler: authority.Reconciler{
				Patcher: k8sManager.GetClient(),
				Cache:   k8sManager.GetCache(),
				Options: opts,
			}}
		Expect(controller.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	BeforeEach(func() {
		caSecret = &corev1.Secret{}
		caSecret.Namespace = caSecretRef.Namespace
		caSecret.Name = caSecretRef.Name
	})

	It("should create Secret on startup", func() {
		assertCASecret(caSecret)

		By("checking for reconcile loops")
		resourceVersion := caSecret.ResourceVersion
		Consistently(komega.Object(caSecret)).Should(
			HaveField("ResourceVersion", Equal(resourceVersion)),
		)
	})

	It("should recreate Secret if it's deleted", func() {
		Expect(k8sClient.Delete(ctx, caSecret)).To(Succeed())
		assertCASecret(caSecret)
	})

	It("should issue certificate if Secret is modified", func() {
		caSecret.Type = corev1.SecretTypeTLS
		caSecret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("foo"),
			corev1.TLSPrivateKeyKey: []byte("bar"),
		}
		Expect(k8sClient.Update(ctx, caSecret)).To(Succeed())
		assertCASecret(caSecret)
	})

	It("should retain old CA if CA is rotated", func() {
		assertCASecret(caSecret)

		caBundleCerts, err := pki.DecodeX509CertificateSetBytes(caSecret.Data[api.TLSCABundleKey])
		Expect(err).ToNot(HaveOccurred())
		Expect(caBundleCerts).To(HaveLen(1))

		certBytes := caSecret.Data[corev1.TLSCertKey]

		Consistently(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Equal(certBytes))),
		)

		By("requesting a renewal")
		caSecret.Annotations = map[string]string{api.RenewCertificateSecretAnnotation: time.Now().String()}
		Expect(k8sClient.Update(ctx, caSecret)).To(Succeed())

		Eventually(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Not(Equal(certBytes)))),
		)
		assertCASecret(caSecret)

		certBytes = caSecret.Data[corev1.TLSCertKey]
		Consistently(komega.Object(caSecret)).Should(
			HaveField("Data", HaveKeyWithValue(corev1.TLSCertKey, Equal(certBytes))),
		)

		caBundleCerts, err = pki.DecodeX509CertificateSetBytes(caSecret.Data[api.TLSCABundleKey])
		Expect(err).ToNot(HaveOccurred())
		Expect(caBundleCerts).To(HaveLen(2))
	})
})
