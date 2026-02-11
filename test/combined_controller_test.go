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
	"context"
	"crypto/tls"
	"fmt"
	"reflect"
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	internalmetrics "github.com/cert-manager/webhook-cert-lib/internal/metrics"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

type runOptions struct {
	ca        *caTester
	clientset *k8sfake.Clientset
	auth      *authority.Authority
	opts      authority.AuthorityOptions
}

func TestControllers(t *testing.T) {
	t.Parallel()

	const (
		nrAuthorityControllers = 50
		caDuration             = 7 * time.Hour
		serverCertDuration     = 1 * time.Hour
		promotionDelay         = 5 * time.Second
		maxStartupDelay        = 5 * time.Second
		maxWatchDelay          = 5 * time.Second

		// wait long enough to have observed the first serving certificate issuance
		minServingCertWait = maxStartupDelay + promotionDelay + 10*maxWatchDelay + 10*time.Millisecond
	)

	type controllerCase struct {
		name          string
		expReconciles int64
		run           func(t *testing.T, run runOptions)
	}

	cases := []controllerCase{
		{
			name:          "creates CA secret on startup",
			expReconciles: 21,
			run: func(t *testing.T, run runOptions) {
				_ = run.ca.getPending(t)
			},
		},
		{
			name:          "keeps resourceVersion stable",
			expReconciles: 21,
			run: func(t *testing.T, run runOptions) {
				s1 := run.ca.getReady(t)
				time.Sleep(minServingCertWait)
				s2 := run.ca.getReady(t)

				require.Equal(t, s1.ResourceVersion, s2.ResourceVersion)
			},
		},
		{
			name:          "recreates CA secret after delete",
			expReconciles: 43,
			run: func(t *testing.T, run runOptions) {
				run.ca.delete(t)
				time.Sleep(minServingCertWait)
				_ = run.ca.getReady(t)
			},
		},
		{
			name:          "repairs modified CA secret",
			expReconciles: 49,
			run: func(t *testing.T, run runOptions) {
				caSecret := run.ca.getReady(t)
				caSecret.Type = corev1.SecretTypeTLS
				caSecret.Data = map[string][]byte{api.TLSServingCertKey: []byte("foo"), api.TLSServingPrivateKeyKey: []byte("bar")}

				run.ca.put(t, caSecret)
				time.Sleep(minServingCertWait)
				_ = run.ca.getReady(t)
			},
		},
		{
			name:          "renews CA and rolls old keys",
			expReconciles: 49,
			run: func(t *testing.T, run runOptions) {
				s1 := run.ca.getReady(t)
				time.Sleep(6 * time.Hour)
				s2 := run.ca.getReady(t)

				require.NotEqual(t, string(s1.Data[api.TLSServingCertKey]), string(s2.Data[api.TLSServingCertKey]))
				require.NotEqual(t, string(s1.Data[api.TLSServingPrivateKeyKey]), string(s2.Data[api.TLSServingPrivateKeyKey]))
			},
		},
		{
			name:          "produces a serving certificate",
			expReconciles: 23,
			run: func(t *testing.T, run runOptions) {
				sc := &tls.Config{} // #nosec G402 -- for testing only
				run.auth.ServingCertificate(sc)
				cert, err := sc.GetCertificate(nil)
				require.NoError(t, err)
				require.NotNil(t, cert)
				require.Greater(t, len(cert.Certificate), 0)
			},
		},
		{
			name:          "injects CA bundle into ValidatingWebhookConfigurations",
			expReconciles: 45,
			run: func(t *testing.T, run runOptions) {
				vwcs := []string{}
				for i := range 10 {
					name := fmt.Sprintf("vwc-%d", i)
					vwcs = append(vwcs, name)
				}

				for _, name := range vwcs {
					vwc := newValidatingWebhookConfigurationForTest(name, run.opts.AuthorityCertificate.SecretNamespacedName)
					_, err := run.clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(t.Context(), vwc, metav1.CreateOptions{})
					require.NoError(t, err)
				}

				time.Sleep(minServingCertWait)

				synctest.Wait()
				for _, name := range vwcs {
					assertVWCInjectMatchesSecret(t, run.clientset, name, run.opts.AuthorityCertificate.SecretNamespacedName)
				}

				secret := run.ca.getReady(t)
				secret.Data[api.TLSServingCertKey] = []byte("updated CA bundle")
				run.ca.put(t, secret)

				synctest.Wait()
				for _, name := range vwcs {
					assertVWCInjectMatchesSecret(t, run.clientset, name, run.opts.AuthorityCertificate.SecretNamespacedName)
				}
			},
		},
		{
			name:          "waits for promotion delay before rotating leaf",
			expReconciles: 23,
			run: func(t *testing.T, run runOptions) {
				// Capture current serving certificate
				sc := &tls.Config{} // #nosec G402 -- for testing only
				run.auth.ServingCertificate(sc)
				first, err := sc.GetCertificate(nil)
				require.NoError(t, err)

				secret := run.ca.getReady(t)
				delete(secret.Data, api.TLSPendingPrivateKeyKey)
				secret.Data[api.TLSServingCertKey] = append(secret.Data[api.TLSServingCertKey], []byte("-mutated")...)
				run.ca.put(t, secret)

				// Immediately after reinjection, leaf should still be the same (PropagationDelay not elapsed)
				immediate, err := sc.GetCertificate(nil)
				require.NoError(t, err)
				require.Equal(t, first.Leaf.Raw, immediate.Leaf.Raw)

				// After promotion delay, leaf should rotate
				time.Sleep(minServingCertWait)
				rotated, err := sc.GetCertificate(nil)
				require.NoError(t, err)
				require.NotEqual(t, first.Leaf.Raw, rotated.Leaf.Raw)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				cs := k8sfake.NewClientset()
				delayClientWatch(cs, maxWatchDelay)

				const testTarget = "test-webhook-configuration"

				opts := authority.AuthorityOptions{
					AuthorityCertificate: authority.AuthorityCertificateOptions{
						SecretNamespacedName: types.NamespacedName{
							Namespace: "cert-ca-secret-controller",
							Name:      "ca-cert",
						},
						Duration: caDuration,
					},
					Targets: authority.TargetsOptions{
						Objects: []authority.TargetObject{
							{
								GroupKind: (injectable.ValidatingWebhookCaBundleInject{}).
									GroupVersionKind().
									GroupKind(),
								NamespacedName: types.NamespacedName{
									Name: testTarget,
								},
							},
						},
					},
					PromotionDelay: promotionDelay,
					ServerCertificate: authority.ServerCertificateOptions{
						Duration: serverCertDuration,
					},
				}

				_, err := cs.CoreV1().Namespaces().Create(
					t.Context(),
					&corev1.Namespace{
						ObjectMeta: metav1.ObjectMeta{
							Name: opts.AuthorityCertificate.SecretNamespacedName.Namespace,
						},
					},
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				_, err = cs.AdmissionregistrationV1().ValidatingWebhookConfigurations().Create(
					t.Context(),
					newValidatingWebhookConfigurationForTest(testTarget, opts.AuthorityCertificate.SecretNamespacedName),
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				synctest.Wait()

				var auths []*authority.Authority
				for range nrAuthorityControllers {
					auth, err := authority.NewAuthorityForClient(cs, opts)
					require.NoError(t, err)
					auths = append(auths, auth)
				}

				run := runOptions{
					ca: &caTester{
						NamespacedName: opts.AuthorityCertificate.SecretNamespacedName,
						clientset:      cs,
					},
					clientset: cs,
					auth:      auths[0], // use first replica for GetCertificate and metrics
					opts:      opts,
				}

				ctx, cancel := context.WithCancel(t.Context())
				group, gctx := errgroup.WithContext(ctx)
				for i, auth := range auths {
					group.Go(func() error {
						time.Sleep(randomDelay(maxStartupDelay))
						authCtx := logr.NewContext(
							gctx,
							testr.
								NewWithOptions(t, testr.Options{
									LogTimestamp: true,
								}).
								WithName(fmt.Sprintf("authority-controller-%d", i)),
						)
						return auth.Start(authCtx)
					})
				}
				defer func() {
					cancel()
					err := group.Wait()
					assert.NoError(t, err)
				}()

				time.Sleep(minServingCertWait)
				synctest.Wait()

				before := getMetricsReport(t, run.auth)
				if tc.run != nil {
					tc.run(t, run)
				}
				after := getMetricsReport(t, run.auth)

				nrPatches := after.TotalPatches - before.TotalPatches
				require.LessOrEqual(t, nrPatches, int64(30), "reconcile delta too high: %d", nrPatches)
			})
		})
	}
}

// HACK: use reflection to access unexported metrics field
func getMetricsReport(t *testing.T, auth *authority.Authority) internalmetrics.InternalMetricsReport {
	t.Helper()

	v := reflect.ValueOf(auth).Elem()
	metricsvalue := v.FieldByName("metrics")
	metricsvalue = reflect.NewAt(metricsvalue.Type(), unsafe.Pointer(metricsvalue.UnsafeAddr())).Elem()
	metrics := metricsvalue.Addr().Interface().(*internalmetrics.InternalMetrics)
	return metrics.PatchCounts()
}
