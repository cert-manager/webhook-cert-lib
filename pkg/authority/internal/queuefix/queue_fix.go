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

package queuefix

import (
	"time"

	"k8s.io/client-go/util/workqueue"
)

// FIX: queue that clears timed reconcile if .Add is called
//
// see https://github.com/kubernetes/kubernetes/issues/126027
type cleanQueue[T comparable] struct {
	workqueue.TypedRateLimitingInterface[T]
}

func FixQueue[T comparable](q workqueue.TypedRateLimitingInterface[T]) workqueue.TypedRateLimitingInterface[T] {
	return cleanQueue[T]{TypedRateLimitingInterface: q}
}

func (q cleanQueue[T]) AddAfter(item T, duration time.Duration) {
	duration = max(1*time.Millisecond, duration)
	q.TypedRateLimitingInterface.AddAfter(item, duration)
}

func (q cleanQueue[T]) Add(item T) {
	q.TypedRateLimitingInterface.AddAfter(item, 1*time.Millisecond)
}
