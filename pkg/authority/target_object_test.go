/*
Copyright 2026 The cert-manager Authors.

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
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func TestTargetObject_String(t *testing.T) {
	tests := []struct {
		name string
		obj  TargetObject
		str  string
	}{
		{
			name: "cluster-scoped-like",
			obj: TargetObject{
				GroupKind: schema.GroupKind{Group: "admissionregistration.k8s.io", Kind: "ValidatingWebhookConfiguration"},
				NamespacedName: types.NamespacedName{
					Name: "my-validating-webhook",
				},
			},
			str: `admissionregistration.k8s.io/ValidatingWebhookConfiguration/my-validating-webhook`,
		},
		{
			name: "namespaced",
			obj: TargetObject{
				GroupKind: schema.GroupKind{Group: "apps", Kind: "Deployment"},
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      "my-deployment",
				},
			},
			str: "apps/Deployment/default/my-deployment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.obj.String(); got != tc.str {
				t.Fatalf("String(): expected %s, got %s", tc.str, got)
			}

			// round-trip parse
			parsed, err := TargetObjectFromString(tc.str)
			if err != nil {
				t.Fatalf("TargetObjectFromString(%q) unexpected error: %v", tc.str, err)
			}
			if parsed != tc.obj {
				t.Fatalf("parsed mismatch: expected %+v, got %+v", tc.obj, parsed)
			}
		})
	}
}
