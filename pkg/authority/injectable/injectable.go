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

package injectable

import (
	"context"
	"iter"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers/internalinterfaces"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type InjectableKind interface {
	GroupVersionKind() schema.GroupVersionKind
	ExampleObject() runtime.Object
	NewInformerAndListPatcher(
		client kubernetes.Interface,
		resyncPeriod time.Duration,
		indexers cache.Indexers,
		tweakListOptions internalinterfaces.TweakListOptionsFunc,
	) (cache.SharedIndexInformer, ListPatcher)
}

type IsUpToDate bool

const (
	UpToDate    IsUpToDate = true
	NeedsUpdate IsUpToDate = false
)

type ListPatcher interface {
	ListObjects(caBundle []byte) (iter.Seq2[types.NamespacedName, IsUpToDate], error)
	PatchObject(ctx context.Context, key types.NamespacedName, caBundle []byte, applyOptions metav1.ApplyOptions) (bool, error)
}
