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
	"fmt"
	"os"
	"strings"
)

// based on https://github.com/kubernetes/client-go/blob/65de5216f10c2cb18014377e6cffdfcb03f849ce/tools/clientcmd/client_config.go#L646

const (
	saNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

func inClusterDetectNamespace() (string, error) {
	// Fall back to the namespace associated with the service account token, if available
	if data, err := os.ReadFile(saNamespaceFilePath); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns, nil
		}
	}

	return "", fmt.Errorf("file %q not found, we might not be running inside a cluster", saNamespaceFilePath)
}
