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
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type Reconciler struct {
	Patcher Patcher
	Cache   cache.Cache
	Opts    CAOptions
}

type Patcher interface {
	// Patch patches the given obj in the Kubernetes cluster. obj must be a
	// struct pointer so that obj can be updated with the content returned by the Server.
	Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error
}

type CAOptions struct {
	// The namespace used for certificate secrets.
	Namespace string

	// The name of the Secret used to store CA certificates.
	Name string

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	Duration time.Duration
}

func (r Reconciler) caSecretSource(handler handler.TypedEventHandler[*corev1.Secret, reconcile.Request]) source.SyncingSource {
	return source.Kind(
		r.Cache,
		&corev1.Secret{},
		handler,
		predicate.NewTypedPredicateFuncs[*corev1.Secret](func(obj *corev1.Secret) bool {
			return obj.Namespace == r.Opts.Namespace && obj.Name == r.Opts.Name
		}))
}
