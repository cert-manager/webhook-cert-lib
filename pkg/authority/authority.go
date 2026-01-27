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
	"crypto/tls"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/webhook-cert-lib/internal/certificate"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
)

type Authority struct {
	Options Options

	certificateHolder *certificate.Holder
}

func (o *Authority) ServingCertificate() func(config *tls.Config) {
	if o.certificateHolder == nil {
		o.certificateHolder = &certificate.Holder{}
	}
	return func(config *tls.Config) {
		config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return o.certificateHolder.GetCertificate(info)
		}
	}
}

func (o *Authority) SetupWithManager(mgr ctrl.Manager) error {
	if o.certificateHolder == nil {
		return errors.New("ServingCertificate not invoked")
	}

	if o.Options.CAOptions.Duration == 0 {
		o.Options.CAOptions.Duration = 7 * 24 * time.Hour
	}
	if o.Options.LeafOptions.Duration == 0 {
		o.Options.LeafOptions.Duration = 1 * 24 * time.Hour
	}
	if len(o.Options.Injectables) == 0 {
		o.Options.Injectables = []injectable.Injectable{
			&injectable.ValidatingWebhookCaBundleInject{},
		}
	}

	cacheByObject := map[client.Object]cache.ByObject{
		&corev1.Secret{}: {
			Namespaces: map[string]cache.Config{
				o.Options.CAOptions.Namespace: {},
			},
			Field: fields.SelectorFromSet(fields.Set{
				"metadata.name":      o.Options.CAOptions.Name,
				"metadata.namespace": o.Options.CAOptions.Namespace,
			}),
			Label: labels.SelectorFromSet(labels.Set{
				api.DynamicAuthoritySecretLabel: "true",
			}),
		},
	}
	for _, i := range o.Options.Injectables {
		cacheByObject[injectable.NewUnstructured(i)] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{
				api.WantInjectFromSecretNameLabel:      o.Options.CAOptions.Name,
				api.WantInjectFromSecretNamespaceLabel: o.Options.CAOptions.Namespace,
			}),
		}
	}
	controllerCache, err := cache.New(mgr.GetConfig(), cache.Options{
		HTTPClient:                  mgr.GetHTTPClient(),
		Scheme:                      mgr.GetScheme(),
		Mapper:                      mgr.GetRESTMapper(),
		ReaderFailOnMissingInformer: true,
		ByObject:                    cacheByObject,
	})
	if err != nil {
		return err
	}
	if err := mgr.Add(controllerCache); err != nil {
		return err
	}

	// Uncached client, used for patching only.
	controllerClient, err := client.New(mgr.GetConfig(), client.Options{
		HTTPClient: mgr.GetHTTPClient(),
		Scheme:     mgr.GetScheme(),
		Mapper:     mgr.GetRESTMapper(),
	})
	if err != nil {
		return err
	}

	r := Reconciler{
		Patcher: controllerClient,
		Cache:   controllerCache,
		Options: o.Options,
	}
	controllers := []dynamicAuthorityController{
		&CASecretReconciler{Reconciler: r},
		&LeafCertReconciler{Reconciler: r, CertificateHolder: o.certificateHolder},
	}
	for _, i := range o.Options.Injectables {
		controllers = append(controllers, &InjectableReconciler{Reconciler: r, Injectable: i})
	}
	for _, c := range controllers {
		if err := c.SetupWithManager(mgr); err != nil {
			return err
		}
	}

	return nil
}

type dynamicAuthorityController interface {
	SetupWithManager(ctrl.Manager) error
}
