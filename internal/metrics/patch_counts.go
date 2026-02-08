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

package metrics

import "sync/atomic"

type InternalMetrics struct {
	targetPatches atomic.Int64
	secretPatches atomic.Int64

	reconciliations atomic.Int64
}

// InternalMetricsReport is a snapshot of processed work item counts.
type InternalMetricsReport struct {
	TotalPatches  int64
	SecretPatches int64
	TargetPatches int64

	Reconciliations int64
}

// PatchCounts returns a snapshot of how many work items were processed.
func (a *InternalMetrics) PatchCounts() InternalMetricsReport {
	counts := InternalMetricsReport{
		SecretPatches:   a.secretPatches.Load(),
		TargetPatches:   a.targetPatches.Load(),
		Reconciliations: a.reconciliations.Load(),
	}
	counts.TotalPatches = counts.SecretPatches + counts.TargetPatches
	return counts
}

func (a *InternalMetrics) IncrementReconciliations() {
	a.reconciliations.Add(1)
}

func (a *InternalMetrics) IncrementTargetPatches() {
	a.targetPatches.Add(1)
}

func (a *InternalMetrics) IncrementSecretPatches() {
	a.secretPatches.Add(1)
}
