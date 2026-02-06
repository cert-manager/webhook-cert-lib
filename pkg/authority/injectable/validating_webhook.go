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

package injectable

import (
	"bytes"
	"context"
	"iter"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
	admissionregistrationinformers "k8s.io/client-go/informers/admissionregistration/v1"
	"k8s.io/client-go/informers/internalinterfaces"
	"k8s.io/client-go/kubernetes"
	admissionregistrationlisters "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/tools/cache"
)

type ValidatingWebhookCaBundleInject struct {
}

var _ InjectableKind = &ValidatingWebhookCaBundleInject{}

func (i ValidatingWebhookCaBundleInject) GroupVersionKind() schema.GroupVersionKind {
	return admissionregistrationv1.
		SchemeGroupVersion.
		WithKind("ValidatingWebhookConfiguration")
}

func (i *ValidatingWebhookCaBundleInject) ExampleObject() runtime.Object {
	return &admissionregistrationv1.
		ValidatingWebhookConfiguration{}
}

func (i *ValidatingWebhookCaBundleInject) NewInformerAndListPatcher(
	client kubernetes.Interface,
	resyncPeriod time.Duration,
	indexers cache.Indexers,
	tweakListOptions internalinterfaces.TweakListOptionsFunc,
) (cache.SharedIndexInformer, ListPatcher) {
	informer := admissionregistrationinformers.NewFilteredValidatingWebhookConfigurationInformer(
		client, resyncPeriod, indexers, tweakListOptions,
	)
	_ = informer.SetTransform(func(obj any) (any, error) {
		vwc := obj.(*admissionregistrationv1.ValidatingWebhookConfiguration)

		// Only retain the fields we care about for CABundle injection
		vwc.ObjectMeta = metav1.ObjectMeta{
			Name:            vwc.Name,
			Namespace:       vwc.Namespace,
			UID:             vwc.UID,
			ResourceVersion: vwc.ResourceVersion,
		}

		for index, webhook := range vwc.Webhooks {
			vwc.Webhooks[index] = admissionregistrationv1.ValidatingWebhook{
				Name: webhook.Name,
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					CABundle: webhook.ClientConfig.CABundle,
				},
			}
		}

		return vwc, nil
	})
	return informer, &ValidatingWebhookCaBundleInjectListPatcher{
		Client: client,
		Lister: admissionregistrationlisters.NewValidatingWebhookConfigurationLister(informer.GetIndexer()),
	}
}

type ValidatingWebhookCaBundleInjectListPatcher struct {
	Client kubernetes.Interface
	Lister admissionregistrationlisters.ValidatingWebhookConfigurationLister
}

var _ ListPatcher = &ValidatingWebhookCaBundleInjectListPatcher{}

func (i *ValidatingWebhookCaBundleInjectListPatcher) ListObjects(caBundle []byte) (iter.Seq2[types.NamespacedName, IsUpToDate], error) {
	vwcs, err := i.Lister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	return func(yield func(types.NamespacedName, IsUpToDate) bool) {
		for _, vwc := range vwcs {
			isUpToDate := true
			for i := range vwc.Webhooks {
				if !bytes.Equal(vwc.Webhooks[i].ClientConfig.CABundle, caBundle) {
					isUpToDate = false
					break
				}
			}

			if !yield(types.NamespacedName{Name: vwc.Name}, IsUpToDate(isUpToDate)) {
				return
			}
		}
	}, nil
}

func (i *ValidatingWebhookCaBundleInjectListPatcher) PatchObject(
	ctx context.Context, key types.NamespacedName, caBundle []byte,
	applyOptions metav1.ApplyOptions,
) (bool, error) {
	vwc, err := i.Lister.Get(key.Name)
	if err != nil {
		return false, err
	}

	// If the current object already contains the desired CABundle for all
	// webhooks, there's no need to call Apply.
	{
		needsPatch := false
		for idx := range vwc.Webhooks {
			if !bytes.Equal(vwc.Webhooks[idx].ClientConfig.CABundle, caBundle) {
				needsPatch = true
				break
			}
		}
		if !needsPatch {
			return false, nil
		}
	}

	ac := admissionregistrationv1ac.
		ValidatingWebhookConfiguration(vwc.Name)

	for _, w := range vwc.Webhooks {
		ac.WithWebhooks(
			admissionregistrationv1ac.ValidatingWebhook().
				WithName(w.Name).
				WithClientConfig(admissionregistrationv1ac.WebhookClientConfig().
					WithCABundle(caBundle...),
				),
		)
	}

	_, err = i.Client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Apply(ctx, ac, applyOptions)
	return true, err
}
