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

package test

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/testing"
)

var (
	DefaultChanSize int = 100
)

func delayClientWatch(cs *k8sfake.Clientset, maxDelay time.Duration) {
	cs.PrependWatchReactor("*", func(action testing.Action) (handled bool, ret watch.Interface, err error) {
		var opts metav1.ListOptions
		if watchAction, ok := action.(testing.WatchActionImpl); ok {
			opts = watchAction.ListOptions
		}
		gvr := action.GetResource()
		ns := action.GetNamespace()
		watch, err := cs.Tracker().Watch(gvr, ns, opts)
		if err != nil {
			return false, nil, err
		}
		return true, delayedWatch(watch, maxDelay), nil
	})
}

func delayedWatch(watcher watch.Interface, maxDelay time.Duration) watch.Interface {
	dw := &delayedWatcher{
		watch:      watcher,
		eventQueue: make(chan eventWithTime, 10*DefaultChanSize),
		result:     make(chan watch.Event, DefaultChanSize),
		maxDelay:   maxDelay,
		stopped:    make(chan struct{}),
	}

	dw.run()

	return dw
}

type delayedWatcher struct {
	watch      watch.Interface
	eventQueue chan eventWithTime
	result     chan watch.Event
	maxDelay   time.Duration

	sync.Mutex
	stopped chan struct{}
}

type eventWithTime struct {
	event     watch.Event
	timestamp time.Time
}

var _ watch.Interface = &delayedWatcher{}

func randomDelay(maxDelay time.Duration) time.Duration {
	return time.Duration(float64(maxDelay) * rand.Float64()) // #nosec G404
}

func (f *delayedWatcher) run() {
	go func() {
		for event := range f.watch.ResultChan() {
			f.eventQueue <- eventWithTime{
				event:     event,
				timestamp: time.Now(),
			}
		}
		close(f.eventQueue)
	}()

	go func() {
		for event := range f.eventQueue {
			arrivalTime := event.timestamp.Add(randomDelay(f.maxDelay))
			select {
			case <-time.After(time.Until(arrivalTime)):
			case <-f.stopped:
				return
			}
			f.trigger(event.event)
		}
	}()
}

func (f *delayedWatcher) Stop() {
	f.Lock()
	defer f.Unlock()
	f.watch.Stop()

	select {
	case <-f.stopped:
		// already stopped
	default:
		close(f.result)
		close(f.stopped)
	}
}

func (f *delayedWatcher) ResultChan() <-chan watch.Event {
	f.Lock()
	defer f.Unlock()

	return f.result
}

func (f *delayedWatcher) trigger(event watch.Event) {
	f.Lock()
	defer f.Unlock()

	select {
	case <-f.stopped:
		return
	default:
	}

	select {
	case f.result <- event:
		return
	default:
		panic(fmt.Errorf("channel full"))
	}
}
