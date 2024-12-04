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

package leadercontrollers

import (
	"context"
	"crypto"
	"crypto/x509"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/cert"
	"github.com/go-logr/logr"
)

// CASecretReconciler reconciles a CA Secret object
type CASecretReconciler struct {
	Reconciler
	events chan event.TypedGenericEvent[*corev1.Secret]
}

// SetupWithManager sets up the controller with the Manager.
func (r *CASecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.events = make(chan event.TypedGenericEvent[*corev1.Secret], 1)
	r.events <- event.TypedGenericEvent[*corev1.Secret]{Object: &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.Opts.Name,
			Namespace: r.Opts.Namespace,
		},
	}}

	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_ca_secret").
		WatchesRawSource(r.caSecretSource(&handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		WatchesRawSource(source.Channel(r.events, &handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		Complete(r)
}

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, r.reconcileSecret(ctx, req)
}

func (r *CASecretReconciler) reconcileSecret(ctx context.Context, req ctrl.Request) error {
	secret := &corev1.Secret{}
	if err := r.Cache.Get(ctx, req.NamespacedName, secret); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}
		// Secret does not exist - let's create it
		secret.Namespace = req.Namespace
		secret.Name = req.Name
	}

	generate, caCert, caPk := r.needsGenerate(secret)

	if generate || secret.Annotations[api.RenewCertificateSecretAnnotation] != secret.Annotations[api.RenewHandledCertificateSecretAnnotation] {
		var err error
		caCert, caPk, err = cert.GenerateCA(r.Opts.Duration)
		if err != nil {
			return err
		}
	}

	certBytes, err := pki.EncodeX509(caCert)
	if err != nil {
		return err
	}
	pkBytes, err := pki.EncodePrivateKey(caPk)
	if err != nil {
		return err
	}

	caBundleBytes := addCertToCABundle(log.FromContext(ctx), secret.Data[api.TLSCABundleKey], caCert)

	ac := corev1ac.Secret(secret.Name, secret.Namespace).
		WithLabels(map[string]string{
			api.DynamicAuthoritySecretLabel: "true",
		}).
		WithType(corev1.SecretTypeTLS).
		WithData(map[string][]byte{
			corev1.TLSCertKey:       certBytes,
			corev1.TLSPrivateKeyKey: pkBytes,
			api.TLSCABundleKey:      caBundleBytes,
		})

	if v, ok := secret.Annotations[api.RenewCertificateSecretAnnotation]; ok {
		ac.WithAnnotations(map[string]string{
			api.RenewHandledCertificateSecretAnnotation: v,
		})
	}

	return r.Patcher.Patch(ctx, secret, newApplyPatch(ac), client.ForceOwnership, fieldOwner)
}

func addCertToCABundle(logger logr.Logger, caBundleBytes []byte, caCert *x509.Certificate) []byte {
	certPool := pki.NewCertPool(pki.WithFilteredExpiredCerts(true))

	if err := certPool.AddCertsFromPEM(caBundleBytes); err != nil {
		logger.Error(err, "failed to re-use existing CAs in new set of CAs")
	}
	// TODO: handle AddCert returning false? I expect this will never happen.
	certPool.AddCert(caCert)

	return []byte(certPool.PEM())
}

func (r *CASecretReconciler) needsGenerate(secret *corev1.Secret) (bool, *x509.Certificate, crypto.Signer) {
	caCert, err := pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return true, nil, nil
	}
	caPk, err := pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return true, nil, nil
	}

	equal, err := pki.PublicKeysEqual(caCert.PublicKey, caPk.Public())
	if !equal || err != nil {
		return true, nil, nil
	}

	// TODO: Trigger renew check due
	return false, caCert, caPk
}
