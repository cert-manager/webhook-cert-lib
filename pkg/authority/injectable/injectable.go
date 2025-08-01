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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cert-manager/webhook-cert-lib/pkg/runtime"
)

type Injectable interface {
	GroupVersionKind() schema.GroupVersionKind
	InjectCA(obj *unstructured.Unstructured, caBundle []byte) (runtime.ApplyConfiguration, error)
}

func NewUnstructured(injectable Injectable) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}

func NewUnstructuredList(injectable Injectable) *unstructured.UnstructuredList {
	obj := &unstructured.UnstructuredList{}
	obj.SetGroupVersionKind(injectable.GroupVersionKind())
	return obj
}
