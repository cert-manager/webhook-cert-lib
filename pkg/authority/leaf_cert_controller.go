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

package authority

import (
	"context"
	"crypto/tls"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/cert"
)

// LeafCertReconciler reconciles the leaf/serving certificate
type LeafCertReconciler struct {
	Options           Options
	Cache             cache.Cache
	CertificateHolder *cert.CertificateHolder
}

// SetupWithManager sets up the controller with the Manager.
func (r *LeafCertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("cert_leaf").
		Watches(&corev1.Secret{}, &handler.TypedEnqueueRequestForObject[client.Object]{}).
		// Disable leader election since all replicas need a serving certificate
		WithOptions(controller.TypedOptions[ctrl.Request]{NeedLeaderElection: ptr.To(false)}).
		Complete(r)
}

func (r *LeafCertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, r.reconcileSecret(ctx, req)
}

func (r *LeafCertReconciler) reconcileSecret(ctx context.Context, req ctrl.Request) error {
	caSecret := &corev1.Secret{}
	if err := r.Cache.Get(ctx, req.NamespacedName, caSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	caCert, err := pki.DecodeX509CertificateBytes(caSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return err
	}
	caPk, err := pki.DecodePrivateKeyBytes(caSecret.Data[corev1.TLSPrivateKeyKey])
	if err != nil {
		return err
	}

	cert, pk, err := cert.GenerateLeaf(
		r.Options.LeafOptions.DNSNames,
		r.Options.LeafOptions.Duration,
		caCert, caPk,
	)
	if err != nil {
		return err
	}

	pkData, err := pki.EncodePrivateKey(pk)
	if err != nil {
		return err
	}

	certData, err := pki.EncodeX509(cert)
	if err != nil {
		return err
	}

	tlsCert, err := tls.X509KeyPair(certData, pkData)
	if err != nil {
		return err
	}

	r.CertificateHolder.SetCertificate(&tlsCert)
	return nil
}
