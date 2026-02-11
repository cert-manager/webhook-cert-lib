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

package informerfactory

import (
	"context"
	reflect "reflect"
	sync "sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	cache "k8s.io/client-go/tools/cache"
)

type informerFactory struct {
	lock sync.Mutex

	informers map[reflect.Type]cache.SharedIndexInformer
	// startedInformers is used for tracking which informers have been started.
	// This allows Start() to be called multiple times safely.
	startedInformers map[reflect.Type]bool
	// wg tracks how many goroutines were started.
	wg sync.WaitGroup
	// shuttingDown is true when Shutdown has been called. It may still be running
	// because it needs to wait for goroutines.
	shuttingDown bool
}

var _ Factory = &informerFactory{}

// NewInformerFactory constructs a new instance of a Factory with additional options.
func NewInformerFactory() Factory {
	factory := &informerFactory{
		informers:        make(map[reflect.Type]cache.SharedIndexInformer),
		startedInformers: make(map[reflect.Type]bool),
	}

	return factory
}

func (f *informerFactory) Start(ctx context.Context) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.shuttingDown {
		return
	}

	for informerType, informer := range f.informers {
		if f.startedInformers[informerType] {
			continue
		}

		f.wg.Go(func() {
			informer.RunWithContext(ctx)
		})
		f.startedInformers[informerType] = true
	}
}

func (f *informerFactory) Shutdown() {
	f.lock.Lock()
	f.shuttingDown = true
	f.lock.Unlock()

	// Will return immediately if there is nothing to wait for.
	f.wg.Wait()
}

func (f *informerFactory) WaitForCacheSync(ctx context.Context) bool {
	hasSyncedChecks := func() []cache.InformerSynced {
		f.lock.Lock()
		defer f.lock.Unlock()

		hasSyncedChecks := make([]cache.InformerSynced, 0, len(f.informers))
		for informerType, informer := range f.informers {
			if f.startedInformers[informerType] {
				hasSyncedChecks = append(hasSyncedChecks, informer.HasSynced)
			}
		}
		return hasSyncedChecks
	}()

	return waitForCacheSync(ctx, hasSyncedChecks...)
}

func waitForCacheSync(ctx context.Context, cacheSyncs ...cache.InformerSynced) bool {
	const syncedPollPeriod = 100 * time.Nanosecond

	if err := wait.PollUntilContextCancel(ctx, syncedPollPeriod, true, func(ctx context.Context) (bool, error) {
		for _, syncFunc := range cacheSyncs {
			if !syncFunc() {
				return false, nil
			}
		}
		return true, nil
	}); err != nil {
		return false
	}

	return true
}

// InformerFor returns the SharedIndexInformer for obj using an internal
// client.
func (f *informerFactory) InformerFor(obj runtime.Object, newFunc func() cache.SharedIndexInformer) cache.SharedIndexInformer {
	f.lock.Lock()
	defer f.lock.Unlock()

	informerType := reflect.TypeOf(obj)
	informer, exists := f.informers[informerType]
	if exists {
		return informer
	}

	informer = newFunc()
	f.informers[informerType] = informer

	return informer
}

type Factory interface {
	// Start initializes all requested informers. They are handled in goroutines
	// which run until the stop channel gets closed.
	// Warning: Start does not block. When run in a go-routine, it will race with a later WaitForCacheSync.
	Start(ctx context.Context)

	// Shutdown marks a factory as shutting down. At that point no new
	// informers can be started anymore and Start will return without
	// doing anything.
	//
	// In addition, Shutdown blocks until all goroutines have terminated. For that
	// to happen, the close channel(s) that they were started with must be closed,
	// either before Shutdown gets called or while it is waiting.
	//
	// Shutdown may be called multiple times, even concurrently. All such calls will
	// block until all goroutines have terminated.
	Shutdown()

	// WaitForCacheSync blocks until all started informers' caches were synced
	// or the stop channel gets closed.
	WaitForCacheSync(ctx context.Context) bool

	// InformerFor returns the SharedIndexInformer for obj using an internal
	// client.
	InformerFor(obj runtime.Object, newFunc func() cache.SharedIndexInformer) cache.SharedIndexInformer
}
