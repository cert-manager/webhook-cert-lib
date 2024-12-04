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
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/leader_controllers/injectable"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	leadercontrollers "github.com/cert-manager/webhook-cert-lib/pkg/authority/leader_controllers"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var _ = Describe("Injectable Controller", Ordered, func() {
	var (
		caSecret    *corev1.Secret
		caSecretRef types.NamespacedName
	)

	BeforeAll(func() {
		ns := &corev1.Namespace{}
		ns.Name = "injectable-controller"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		caSecret = &corev1.Secret{}
		caSecret.Namespace = ns.Name
		caSecret.Name = "ca-cert"
		caSecret.Type = corev1.SecretTypeTLS
		caSecret.Labels = map[string]string{
			api.DynamicAuthoritySecretLabel: "true",
		}
		caSecret.Data = map[string][]byte{
			corev1.TLSCertKey:       []byte("CA cert injectable"),
			corev1.TLSPrivateKeyKey: []byte("CA cert key injectable"),
			api.TLSCABundleKey:      []byte("CA bundle injectable"),
		}
		Expect(k8sClient.Create(ctx, caSecret)).To(Succeed())
		caSecretRef = client.ObjectKeyFromObject(caSecret)

		k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme: scheme.Scheme,
			Metrics: metricsserver.Options{
				BindAddress: "0",
			},
		})
		Expect(err).ToNot(HaveOccurred())

		controller := &leadercontrollers.InjectableReconciler{
			Reconciler: leadercontrollers.Reconciler{
				Patcher: k8sManager.GetClient(),
				Cache:   k8sManager.GetCache(),
				Opts: leadercontrollers.CAOptions{
					Name:      caSecretRef.Name,
					Namespace: caSecretRef.Namespace,
				}},
			Injectable: &injectable.ValidatingWebhookCaBundleInject{},
		}
		Expect(controller.SetupWithManager(k8sManager)).To(Succeed())

		go func() {
			defer GinkgoRecover()
			err = k8sManager.Start(ctx)
			Expect(err).ToNot(HaveOccurred(), "failed to run manager")
		}()
	})

	Context("ValidatingWebhookConfiguration", func() {
		var vwc *admissionregistrationv1.ValidatingWebhookConfiguration

		It("should inject CA bundle", func() {
			vwc = NewValidatingWebhookConfigurationForTest("test-vwc", caSecretRef)
			Expect(k8sClient.Create(ctx, vwc)).To(Succeed())
		})

		It("should update CA bundle when bundle updated", func() {
			caSecret.Data[api.TLSCABundleKey] = []byte("updated CA bundle")
			Expect(k8sClient.Update(ctx, caSecret)).To(Succeed())
		})

		AfterEach(func() {
			Eventually(komega.Object(vwc)).Should(
				HaveField("Webhooks", HaveEach(
					HaveField("ClientConfig.CABundle", Equal(caSecret.Data[api.TLSCABundleKey])),
				)),
			)
		})
	})

})
