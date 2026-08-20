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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/internal/ssa"
)

// InjectableReconciler injects CA bundle into resources
type InjectableReconciler struct {
	Reconciler
	Injectable injectable.Injectable
}

// SetupWithManager sets up the controllers with the Manager.
func (r *InjectableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(strings.ToLower(r.Injectable.GroupVersionKind().Kind)).
		WatchesRawSource(
			source.Kind(
				r.Cache,
				injectable.NewUnstructured(r.Injectable),
				&handler.TypedEnqueueRequestForObject[*unstructured.Unstructured]{},
				predicate.NewTypedPredicateFuncs(func(obj *unstructured.Unstructured) bool {
					return obj.GetLabels()[api.WantInjectFromSecretNamespaceLabel] == r.CAOptions.Namespace &&
						obj.GetLabels()[api.WantInjectFromSecretNameLabel] == r.CAOptions.Name
				}),
			),
		).
		WatchesRawSource(
			r.caSecretSource(
				handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, _ *corev1.Secret) []reconcile.Request {
					objList := injectable.NewUnstructuredList(r.Injectable)
					if err := r.Cache.List(ctx, objList, client.MatchingLabels(map[string]string{
						api.WantInjectFromSecretNamespaceLabel: r.CAOptions.Namespace,
						api.WantInjectFromSecretNameLabel:      r.CAOptions.Name,
					})); err != nil {
						log.FromContext(ctx).Error(err, "when listing injectables")
						return nil
					}

					requests := make([]reconcile.Request, len(objList.Items))
					for i, obj := range objList.Items {
						req := reconcile.Request{}
						req.Namespace = obj.GetNamespace()
						req.Name = obj.GetName()
						requests[i] = req
					}
					return requests
				}),
			),
		).
		Complete(r)
}

func (r *InjectableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Cache.Get(ctx, r.CAOptions.NamespacedName, secret); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.reconcileInjectable(ctx, req, secret.Data[api.TLSCABundleKey])
}

func (r *InjectableReconciler) reconcileInjectable(ctx context.Context, req ctrl.Request, caBundle []byte) error {
	obj := injectable.NewUnstructured(r.Injectable)
	if err := r.Cache.Get(ctx, req.NamespacedName, obj); err != nil {
		return err
	}

	ac, err := r.Injectable.InjectCA(obj, caBundle)
	if err != nil {
		return err
	}

	if err := r.Patcher.Patch(ctx, obj, ssa.NewApplyPatch(ac), client.ForceOwnership, ssa.FieldOwner); err != nil {
		return err
	}

	return nil
}
