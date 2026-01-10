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

package autodetect

import (
	"k8s.io/apimachinery/pkg/types"
)

func DetectInClusterSettings() (InClusterSettings, error) {
	detectedNamespace, err := inClusterDetectNamespace()
	if err != nil {
		return InClusterSettings{}, err
	}

	return InClusterSettings{
		Namespace: detectedNamespace,
	}, nil
}

type InClusterSettings struct {
	Namespace string
}

func (setting InClusterSettings) SecretNamespacedName(secretName string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: setting.Namespace,
		Name:      secretName,
	}
}

func (setting InClusterSettings) ServiceDNSName(serviceName string) string {
	return serviceName + "." + setting.Namespace + ".svc"
}
