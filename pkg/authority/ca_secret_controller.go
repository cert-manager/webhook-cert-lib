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

package authority

import (
	"context"
	"crypto"
	"crypto/tls"
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

	"github.com/cert-manager/webhook-cert-lib/internal/certificate"
	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/internal/ssa"
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
			Namespace: r.CAOptions.Namespace,
			Name:      r.CAOptions.Name,
		},
	}}

	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_ca_secret").
		WatchesRawSource(r.caSecretSource(&handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		WatchesRawSource(source.Channel(r.events, &handler.TypedEnqueueRequestForObject[*corev1.Secret]{})).
		Complete(r)
}

func (r *CASecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	secret := &corev1.Secret{}
	if err := r.Cache.Get(ctx, req.NamespacedName, secret); err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Secret does not exist - let's create it by setting namespace/name
		secret.Namespace = req.Namespace
		secret.Name = req.Name
	}

	caCert, err := r.reconcileSecret(ctx, secret)
	return ctrl.Result{RequeueAfter: certificate.RenewAfter(caCert)}, err
}

func (r *CASecretReconciler) reconcileSecret(ctx context.Context, secret *corev1.Secret) (caCert *x509.Certificate, err error) {
	var caPk crypto.Signer

	if required, reason := caRequiresRegeneration(secret); required {
		log.FromContext(ctx).Info("Will regenerate CA", "reason", reason)

		caCert, caPk, err = certificate.GenerateCA(r.CAOptions.Duration)
		if err != nil {
			return caCert, err
		}
	} else {
		caCert, err = pki.DecodeX509CertificateBytes(secret.Data[corev1.TLSCertKey])
		if err != nil {
			return caCert, err
		}
		caPk, err = pki.DecodePrivateKeyBytes(secret.Data[corev1.TLSPrivateKeyKey])
		if err != nil {
			return caCert, err
		}
	}

	certBytes, err := pki.EncodeX509(caCert)
	if err != nil {
		return caCert, err
	}
	pkBytes, err := pki.EncodePrivateKey(caPk)
	if err != nil {
		return caCert, err
	}

	caBundleBytes := addCertToCABundle(ctx, secret.Data[api.TLSCABundleKey], caCert)

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

	return caCert, r.Patcher.Patch(ctx, secret, ssa.NewApplyPatch(ac), client.ForceOwnership, ssa.FieldOwner)
}

func addCertToCABundle(ctx context.Context, caBundleBytes []byte, caCert *x509.Certificate) []byte {
	certPool := pki.NewCertPool(pki.WithFilteredExpiredCerts(true))

	if err := certPool.AddCertsFromPEM(caBundleBytes); err != nil {
		log.FromContext(ctx).Error(err, "failed to re-use existing CAs in new set of CAs")
	}
	// TODO: handle AddCert returning false? I expect this will never happen.
	certPool.AddCert(caCert)

	return []byte(certPool.PEM())
}

// caRequiresRegeneration will check data in a Secret resource and return true
// if the CA needs to be regenerated for any reason.
func caRequiresRegeneration(s *corev1.Secret) (bool, string) {
	if s.Annotations[api.RenewCertificateSecretAnnotation] != s.Annotations[api.RenewHandledCertificateSecretAnnotation] {
		return true, "Forced renewal."
	}

	if s.Data == nil {
		return true, "Missing data in CA secret."
	}
	pkData := s.Data[corev1.TLSPrivateKeyKey]
	certData := s.Data[corev1.TLSCertKey]
	if len(pkData) == 0 || len(certData) == 0 {
		return true, "Missing data in CA secret."
	}
	cert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return true, "Failed to parse data in CA secret."
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true, "Internal error parsing x509 certificate."
	}
	if !x509Cert.IsCA {
		return true, "Stored certificate is not marked as a CA."
	}
	if certificate.RenewAfter(x509Cert) < 0 {
		return true, "CA certificate is nearing expiry."
	}

	return false, ""
}
