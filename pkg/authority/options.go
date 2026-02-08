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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/internal/autodetect"
)

func collisionAvoidanceDelay(isIssuer bool) time.Duration {
	if isIssuer {
		// the controller that issued the pending CA can instantly
		// reconcile the targets and promote the CA. We give it a leeway
		// of 3 seconds before letting other non-issuer controllers perform
		// the same work, to avoid sending too many requests to the apiserver.
		return 0
	}

	// non-issuers wait 3 seconds plus a random delay up to 3 seconds
	// to avoid collision when multiple controllers are running
	// and trying to reconcile the same targets at the same time.
	// this helps to spread out the load on the apiserver.
	// This should only happen when the issuer controller is down or
	// unable to perform the reconciliation.
	return wait.Jitter(time.Second*3, 1.0)
}

type AuthorityOptions struct {
	// AuthorityCertificate contains options for the CA certificate
	AuthorityCertificate AuthorityCertificateOptions

	// Targets contains options for the targets to inject the trusted
	// CA certificates into.
	Targets TargetsOptions

	// PromotionDelay is the amount of time to wait after all targets have
	// been reconciled before promoting the pending CA to be the serving CA.
	//
	// This delay is necessary to ensure that all webhook configurations
	// using the CA have had time to observe the new CA certificate before
	// it is promoted to be the serving CA.
	//
	// If this value is set too low, you might see a "certificate signed by unknown authority" error when using your webhook:
	//     error: failed to create configmap: Internal error occurred: failed calling
	//     webhook "example-webhook.k8s.io": failed to call webhook: Post "https://example-webhook-example-webhook.my-namespace.svc:443/validate?timeout=10s":
	//     tls: failed to verify certificate: x509: certificate signed by unknown authority
	//     (possibly because of "x509: ECDSA verification failure" while trying to verify
	//     candidate authority certificate "cert-manager-dynamic-ca")
	//
	// Defaults to 2s.
	PromotionDelay time.Duration

	// ServerCertificate contains options for the webhook server leaf certificate
	ServerCertificate ServerCertificateOptions
}

type AuthorityCertificateOptions struct {
	// The namespaced name of the Secret used to store CA certificates.
	SecretNamespacedName types.NamespacedName

	// The amount of time the root CA certificate will be valid for.
	// This must be greater than or equal to LeafDuration.
	// Defaults to 1 hour.
	Duration time.Duration
}

type TargetsOptions struct {
	// InjectableKinds is a list of injectable.InjectableKind implementations
	// that will be used to inject the CA certificate into target resources.
	//
	// Defaults to [ValidatingWebhookCaBundleInject].
	SupportedKinds []injectable.InjectableKind

	// Objects is a list of target objects to inject the CA certificate into.
	// All these targets need to exist and have been patched with the trust bundle
	// before the CA can be promoted to be the serving CA.
	Objects []TargetObject
}

type ServerCertificateOptions struct {
	// The DNS names to be included in the webhook server certificate.
	DNSNames []string

	// The amount of time server certificates signed by this authority will be
	// valid for.
	// This must be:
	//  - at least 60 seconds
	//  - at least 10 times the PromotionDelay
	//
	// Defaults to 1 hour.
	Duration time.Duration
}

func (opts *AuthorityOptions) ApplyDefaults() {
	if opts.AuthorityCertificate.Duration == 0 {
		opts.AuthorityCertificate.Duration = 1 * time.Hour
	}
	if opts.ServerCertificate.Duration == 0 {
		opts.ServerCertificate.Duration = 1 * time.Hour
	}
	if opts.PromotionDelay == 0 {
		opts.PromotionDelay = 2 * time.Second
	}
	if len(opts.Targets.SupportedKinds) == 0 {
		opts.Targets.SupportedKinds = []injectable.InjectableKind{
			&injectable.ValidatingWebhookCaBundleInject{},
		}
	}
}

func (opts *AuthorityOptions) Validate() error {
	if opts.AuthorityCertificate.Duration <= 0 {
		return fmt.Errorf("CA.Duration must be greater than zero")
	}
	if opts.ServerCertificate.Duration <= 0 {
		return fmt.Errorf("WebServer.Duration must be greater than zero")
	}
	if opts.PromotionDelay < 0 {
		return fmt.Errorf("PromotionDelay must be greater than or equal to zero")
	}
	if len(opts.Targets.Objects) == 0 {
		return fmt.Errorf("at least one target object must be specified in Targets.Objects")
	}

	supportedGroupKinds := make(map[schema.GroupKind]struct{})
	for _, kind := range opts.Targets.SupportedKinds {
		supportedGroupKinds[kind.GroupVersionKind().GroupKind()] = struct{}{}
	}
	for _, obj := range opts.Targets.Objects {
		if _, ok := supportedGroupKinds[obj.GroupKind]; !ok {
			return fmt.Errorf("target object %s has unsupported GroupKind %s", obj.String(), obj.GroupKind.String())
		}
	}

	// since the validity of the leaf certificate is capped by the CA certificate,
	// ensure that the CA duration is larger than the leaf duration
	if opts.AuthorityCertificate.Duration < opts.ServerCertificate.Duration {
		return fmt.Errorf("CA.Duration (%s) must be greater than WebServer.Duration (%s)", opts.AuthorityCertificate.Duration, opts.ServerCertificate.Duration)
	}

	// the CA certificate will be renewed between 6/10 and 7/10 of its lifetime, so
	// worst case we have left 3/10 of its lifetime to propagate the new CA to all targets
	// and promote it to serving before the CA certificate expires. For that reason,
	// we limit the promotion delay to be at most 1/10 of the CA certificate lifetime
	// to leave some time (2/10) to inject the trust bundle into all targets.
	//
	//      6/10                  7/10                  8/10                  9/10                  10/10
	// ------[==================X==]----------------------------X.....................X---------------|
	//                        New CA                         Injected              Promoted
	//
	//        <- trigger renewal ->                              <- promotion delay ->
	//                           <-   time to inject          ->    max 1/10 lifetime
	//                                new CA into all targets
	//
	if opts.AuthorityCertificate.Duration < 10*opts.PromotionDelay {
		return fmt.Errorf("CA.Duration (%s) must be greater than 10 * PromotionDelay (%s)", opts.AuthorityCertificate.Duration, 10*opts.PromotionDelay)
	}

	// ensure that the CA certificate is valid for at least 60 seconds. worst case,
	// this leaves us with a renewal window of 6 seconds (6/10 to 7/10) and 12 seconds
	// to inject the CA into all targets. With a promotion delay of maximum 6 seconds.
	if opts.AuthorityCertificate.Duration < 60*time.Second {
		return fmt.Errorf("CA.Duration (%s) must be greater than or equal to 60 seconds", opts.AuthorityCertificate.Duration)
	}

	return nil
}

var DetectInClusterSettings = autodetect.DetectInClusterSettings
