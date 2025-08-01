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
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
)

type Options struct {
	CAOptions   CAOptions
	LeafOptions LeafOptions

	Injectables []injectable.Injectable
}

type CAOptions struct {
	// The namespaced name of the Secret used to store CA certificates.
	types.NamespacedName

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than LeafDuration.
	Duration time.Duration
}

type LeafOptions struct {
	DNSNames []string

	// The amount of time leaf certificates signed by this authority will be
	// valid for.
	// This must be less than CADuration.
	Duration time.Duration
}
