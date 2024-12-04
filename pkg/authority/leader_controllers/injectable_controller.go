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
	"strings"

	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/leader_controllers/injectable"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
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
				newUnstructured(r.Injectable),
				&handler.TypedEnqueueRequestForObject[*unstructured.Unstructured]{},
				predicate.NewTypedPredicateFuncs(func(obj *unstructured.Unstructured) bool {
					return obj.GetLabels()[api.WantInjectFromSecretNamespaceLabel] == r.Opts.Namespace &&
						obj.GetLabels()[api.WantInjectFromSecretNameLabel] == r.Opts.Name
				}),
			),
		).
		WatchesRawSource(
			r.caSecretSource(
				handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, _ *corev1.Secret) []reconcile.Request {
					objList := newUnstructuredList(r.Injectable)
					if err := r.Cache.List(ctx, objList, client.MatchingLabels(map[string]string{
						api.WantInjectFromSecretNamespaceLabel: r.Opts.Namespace,
						api.WantInjectFromSecretNameLabel:      r.Opts.Name,
					})); err != nil {
						log.FromContext(ctx).Error(err, "when listing injectables")
						return nil
					}

					requests := make([]reconcile.Request, len(objList.Items))
					for _, obj := range objList.Items {
						req := reconcile.Request{}
						req.Namespace = obj.GetNamespace()
						req.Name = obj.GetName()
						requests = append(requests, req)
					}
					return requests
				}),
			),
		).
		Complete(r)
}

func newUnstructured(injectable injectable.Injectable) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}

func newUnstructuredList(injectable injectable.Injectable) *unstructured.UnstructuredList {
	obj := &unstructured.UnstructuredList{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}

func (r *InjectableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Cache.Get(ctx, types.NamespacedName{Namespace: r.Opts.Namespace, Name: r.Opts.Name}, secret); err != nil {
		if errors.IsNotFound(err) {
			log.FromContext(ctx).V(1).Info("CA secret not yet found, requeueing request...")
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.reconcileInjectable(ctx, req, secret.Data[api.TLSCABundleKey])
}

func (r *InjectableReconciler) reconcileInjectable(ctx context.Context, req ctrl.Request, caBundle []byte) error {
	obj := newUnstructured(r.Injectable)
	if err := r.Cache.Get(ctx, req.NamespacedName, obj); err != nil {
		return err
	}

	ac, err := r.Injectable.InjectCA(obj, caBundle)
	if err != nil {
		return err
	}

	if err := r.Patcher.Patch(ctx, obj, newApplyPatch(ac), client.ForceOwnership, fieldOwner); err != nil {
		return err
	}

	return nil
}
