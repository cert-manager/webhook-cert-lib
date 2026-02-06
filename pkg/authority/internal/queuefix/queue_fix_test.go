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
	"testing"
	"testing/synctest"
	"time"

	"k8s.io/client-go/util/workqueue"
	testingclock "k8s.io/utils/clock/testing"
)

func Test_cleanqueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fakeClock := testingclock.NewFakeClock(time.Now())
		upstreamQueue := workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.DefaultTypedControllerRateLimiter[string](),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Clock: fakeClock,
			},
		)
		// if you use the upstream queue directly, this test fails
		q := cleanQueue[string]{TypedRateLimitingInterface: upstreamQueue}
		defer q.ShutDown()

		first := "foo"

		q.AddAfter(first, 0*time.Millisecond)
		q.AddAfter(first, 50*time.Millisecond)

		synctest.Wait()

		// step past the first block, we should receive now
		fakeClock.Step(10 * time.Millisecond)

		synctest.Wait()

		if q.Len() != 1 {
			t.Error("should have added")
		}
		item, _ := q.Get()
		q.Done(item)

		// step past the second add
		fakeClock.Step(50 * time.Millisecond)

		synctest.Wait()

		if q.Len() != 0 {
			t.Errorf("should not have added")
		}
	})
}
