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
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type TargetObject struct {
	// The GroupKind of the target object.
	GroupKind schema.GroupKind

	// The NamespacedName of the target object.
	// Note: for cluster-scoped resources, the Namespace field should be empty.
	NamespacedName types.NamespacedName
}

func (to TargetObject) String() string {
	var builder strings.Builder
	_, _ = builder.WriteString(to.GroupKind.Group)
	_, _ = builder.WriteRune('/')
	_, _ = builder.WriteString(to.GroupKind.Kind)
	_, _ = builder.WriteRune('/')
	if to.NamespacedName.Namespace != "" {
		_, _ = builder.WriteString(to.NamespacedName.Namespace)
		_, _ = builder.WriteRune('/')
	}
	_, _ = builder.WriteString(to.NamespacedName.Name)
	return builder.String()
}

func TargetObjectFromString(s string) (TargetObject, error) {
	parts := strings.SplitN(s, "/", 5)
	if len(parts) < 3 || len(parts) > 4 {
		return TargetObject{}, fmt.Errorf("invalid target object string: %s", s)
	}

	var to TargetObject
	to.GroupKind = schema.GroupKind{Group: parts[0], Kind: parts[1]}
	if len(parts) == 4 {
		to.NamespacedName = types.NamespacedName{
			Namespace: parts[2],
			Name:      parts[3],
		}
	} else {
		to.NamespacedName = types.NamespacedName{
			Name: parts[2],
		}
	}
	return to, nil
}
