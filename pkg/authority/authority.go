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
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	applyconfigurationscorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/cert-manager/webhook-cert-lib/internal/certificate"
	internalmetrics "github.com/cert-manager/webhook-cert-lib/internal/metrics"
	"github.com/cert-manager/webhook-cert-lib/internal/pki"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/api"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/informerfactory"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/internal/queuefix"
)

// Authority wires together CA renewal, injection, and serving without controller-runtime.
type Authority struct {
	Options AuthorityOptions

	// id used to identify this Authority instance in logs and field managers
	// is used to reduce conflicts when multiple Authorities manage the same Secret
	// only the authority with the ID matching the one that issued the pending CA
	// is allowed to inject it into targets and promote it to serving CA during the
	// first 5 seconds after issuing the pending CA.
	authorityID string

	// Merged Manager fields (manager owns and serves the current leaf certificate)
	leafDNSNames []string
	leafDuration time.Duration
	leaf         atomic.Pointer[tlsCertWithExpiry]

	// clients
	clientset kubernetes.Interface

	// informers
	factory                informerfactory.Factory
	secretLister           corelisters.SecretLister
	injectableListPatchers map[schema.GroupVersionKind]injectable.ListPatcher

	// workqueue for handling reinjection tasks
	newQueue func() workqueue.TypedRateLimitingInterface[queueKey]
	queue    workqueue.TypedRateLimitingInterface[queueKey]

	// reconcile metrics
	metrics internalmetrics.InternalMetrics
}

type tlsCertWithExpiry struct {
	cert          tls.Certificate
	renewalPeriod certificate.TriggerWindow
	validUntil    time.Time
	ca            []byte
}

type queueKey struct {
	reconcileType string

	// for target reconciliation (don't use this field for other reconcile types)
	gvk schema.GroupVersionKind
	key types.NamespacedName
}

var reconcilePendingCAKey = queueKey{reconcileType: "reconcile-pending-ca"}
var reconcileServingCAPromotionKey = queueKey{reconcileType: "reconcile-serving-ca-promotion"}
var reconcileLeafCertificateKey = queueKey{reconcileType: "reconcile-leaf-certificate"}
var reconcileAllTargetsKey = queueKey{reconcileType: "reconcile-all-targets"}
var reconcileSecretTargetAnnotationKey = queueKey{reconcileType: "reconcile-secret-target-annotation"}

func reconcileSingleTargetKey(gvk schema.GroupVersionKind, key types.NamespacedName) queueKey {
	return queueKey{reconcileType: "reconcile-single-target", gvk: gvk, key: key}
}

var ErrCertNotAvailable = errors.New("leaf certificate not available")

// GetCertificate is a tls.Config.GetCertificate hook that returns the current leaf certificate.
func (a *Authority) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := a.leaf.Load()
	if cert == nil {
		return nil, ErrCertNotAvailable
	}
	return &cert.cert, nil
}

// NewAuthorityForConfig creates and prepares the Authority; call Start to run it.
func NewAuthorityForConfig(cfg *rest.Config, options AuthorityOptions) (*Authority, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewAuthorityForClient(cs, options)
}

// NewAuthorityForClient creates an Authority using a provided kubernetes clientset; call Start to run it.
func NewAuthorityForClient(cs kubernetes.Interface, options AuthorityOptions) (*Authority, error) {
	options.ApplyDefaults()
	if err := options.Validate(); err != nil {
		return nil, err
	}

	factory := informerfactory.NewInformerFactory()
	a := &Authority{
		Options:     options,
		authorityID: rand.String(10),
		clientset:   cs,
		factory:     factory,
		newQueue: func() workqueue.TypedRateLimitingInterface[queueKey] {
			return queuefix.FixQueue(
				workqueue.NewTypedRateLimitingQueueWithConfig(
					workqueue.DefaultTypedControllerRateLimiter[queueKey](),
					workqueue.TypedRateLimitingQueueConfig[queueKey]{
						Name: "authority",
					},
				),
			)
		},
		injectableListPatchers: make(map[schema.GroupVersionKind]injectable.ListPatcher, len(options.Targets.SupportedKinds)),
		leafDNSNames:           options.ServerCertificate.DNSNames,
		leafDuration:           options.ServerCertificate.Duration,
	}

	// Secret informer for CA Secret
	secretInf := factory.InformerFor(&corev1.Secret{}, func() cache.SharedIndexInformer {
		return coreinformers.NewFilteredSecretInformer(
			cs,
			options.AuthorityCertificate.SecretNamespacedName.Namespace,
			0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(lo *metav1.ListOptions) {
				// Namespace is already provided to the informer constructor; only match by name here.
				lo.FieldSelector = fields.Set{
					"metadata.name": options.AuthorityCertificate.SecretNamespacedName.Name,
				}.String()
			},
		)
	})
	if _, err := secretInf.AddEventHandlerWithOptions(cache.ResourceEventHandlerDetailedFuncs{
		AddFunc: func(obj any, isInInitialList bool) {
			a.onCASecretChange(extractNamespacedName(obj))
		},
		UpdateFunc: func(_, newObj any) {
			a.onCASecretChange(extractNamespacedName(newObj))
		},
		DeleteFunc: func(obj any) {
			a.onCASecretChange(extractNamespacedName(obj))
		},
	}, cache.HandlerOptions{}); err != nil {
		return nil, err
	}
	a.secretLister = corelisters.NewSecretLister(secretInf.GetIndexer())

	// VWC informer for injectable updates
	for _, inj := range options.Targets.SupportedKinds {
		gvk := inj.GroupVersionKind()

		informer, listPatcher := inj.NewInformerAndListPatcher(
			cs, 0,
			cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
			func(lo *metav1.ListOptions) {
				lo.LabelSelector = labels.Set{
					api.WantInjectFromSecretNameLabel:      a.Options.AuthorityCertificate.SecretNamespacedName.Name,
					api.WantInjectFromSecretNamespaceLabel: a.Options.AuthorityCertificate.SecretNamespacedName.Namespace,
				}.String()
			},
		)

		// add informer to factory
		_ = factory.InformerFor(inj.ExampleObject(), func() cache.SharedIndexInformer {
			return informer
		})
		if _, err := informer.AddEventHandlerWithOptions(cache.ResourceEventHandlerDetailedFuncs{
			AddFunc: func(obj any, isInInitialList bool) {
				a.onInjectableChange(gvk, extractNamespacedName(obj))
			},
			UpdateFunc: func(oldObj, newObj any) {
				a.onInjectableChange(gvk, extractNamespacedName(newObj))
			},
		}, cache.HandlerOptions{}); err != nil {
			return nil, err
		}

		a.injectableListPatchers[gvk] = listPatcher
	}

	return a, nil
}

func extractNamespacedName(rawObj any) types.NamespacedName {
	objName, err := cache.DeletionHandlingObjectToName(rawObj)
	if err != nil {
		panic(fmt.Sprintf("PROGRAMMER ERROR: could not extract namespaced name from object: %v", err))
	}

	return objName.AsNamespacedName()
}

// ServingCertificate returns a mutator that wires GetCertificate to the Authority's manager.
func (a *Authority) ServingCertificate(config *tls.Config) {
	config.GetCertificate = a.GetCertificate
}

// Start runs informers and controllers until the context is cancelled.
func (a *Authority) Start(ctx context.Context) error {
	klog.FromContext(ctx).Info(
		"Starting webhook certificate authority",
		"ca_secret", a.Options.AuthorityCertificate.SecretNamespacedName,
		"ca_duration", a.Options.AuthorityCertificate.Duration,
	)

	a.queue = a.newQueue()

	a.factory.Start(ctx)
	a.factory.WaitForCacheSync(ctx)

	// force the ca to be created if it does not exist yet
	a.queue.Add(reconcilePendingCAKey)

	// Start worker to process the queue
	var wg sync.WaitGroup

	const workerCount = 5
	for range workerCount {
		wg.Go(func() {
			wait.UntilWithContext(ctx, func(ctx context.Context) {
				for a.processNextWorkItem(ctx) {
				}
			}, time.Second)
		})
	}

	<-ctx.Done()
	a.factory.Shutdown()
	a.queue.ShutDown()
	wg.Wait()
	return nil
}

func (a *Authority) isIssuer() bool {
	secret, err := a.secretLister.Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).Get(a.Options.AuthorityCertificate.SecretNamespacedName.Name)
	if err != nil {
		return false
	}

	issuerID, ok := secret.Annotations[api.IssuingAuthorityIDAnnotation]
	return ok && issuerID == a.authorityID
}

func (a *Authority) onCASecretChange(namespacedName types.NamespacedName) {
	if namespacedName.Namespace != a.Options.AuthorityCertificate.SecretNamespacedName.Namespace ||
		namespacedName.Name != a.Options.AuthorityCertificate.SecretNamespacedName.Name {
		return
	}

	a.queue.Add(reconcileLeafCertificateKey)
	a.queue.Add(reconcilePendingCAKey)
	isIssuer := a.isIssuer()
	a.queue.AddAfter(reconcileAllTargetsKey, collisionAvoidanceDelay(isIssuer))         // enqueue, but let issuer go first
	a.queue.AddAfter(reconcileServingCAPromotionKey, collisionAvoidanceDelay(isIssuer)) // enqueue, but let issuer go first
}

func (a *Authority) onInjectableChange(gvk schema.GroupVersionKind, key types.NamespacedName) {
	// When targets change, enqueue reinjection based on current CA secret
	isIssuer := a.isIssuer()
	a.queue.AddAfter(reconcileSingleTargetKey(gvk, key), collisionAvoidanceDelay(isIssuer)) // enqueue, but let issuer go first
	a.queue.AddAfter(reconcileSecretTargetAnnotationKey, collisionAvoidanceDelay(isIssuer)) // enqueue, but let issuer go first
}

func (a *Authority) processNextWorkItem(ctx context.Context) bool {
	item, shutdown := a.queue.Get()
	if shutdown {
		return false
	}
	defer a.queue.Done(item)

	a.metrics.IncrementReconciliations()

	var err error
	switch {
	case item == reconcilePendingCAKey:
		err = a.reconcilePendingCA(ctx)

	case item == reconcileAllTargetsKey:
		err = a.reconcileAllTargets(ctx)

	case item == reconcileSecretTargetAnnotationKey:
		err = a.reconcileSecretTargetAnnotation(ctx)

	case item == reconcileServingCAPromotionKey:
		err = a.reconcileServingCAPromotion(ctx)

	case item == reconcileLeafCertificateKey:
		err = a.reconcileLeafCertificate(ctx)

	case item.reconcileType == reconcileSingleTargetKey(schema.GroupVersionKind{}, types.NamespacedName{}).reconcileType:
		err = a.reconcileSingleTarget(ctx, item.gvk, item.key)

	default:
		// Unknown work item
		klog.FromContext(ctx).Error(
			fmt.Errorf("processNextWorkItem: unknown work item, forgetting"),
			"error processing queue item",
			"item", item,
		)
		return true
	}

	if err != nil {
		klog.FromContext(ctx).Error(
			err,
			"error processing queue item",
			"item", item,
		)
		a.queue.AddRateLimited(item)
		return true
	}

	a.queue.Forget(item) // successful processing, reset rate limiter
	return true
}

type caInSecret struct {
	certKey string
	keyKey  string
}

var servingCAInSecret = caInSecret{
	certKey: api.TLSServingCertKey,
	keyKey:  api.TLSServingPrivateKeyKey,
}

var pendingCAInSecret = caInSecret{
	certKey: api.TLSPendingCertKey,
	keyKey:  api.TLSPendingPrivateKeyKey,
}

type caInfo struct {
	renewalPeriod certificate.TriggerWindow
	validUntil    time.Time
	cert          *x509.Certificate
	certPEM       []byte
	privateKey    crypto.Signer
}

func (i caInfo) shouldRenew(now time.Time) bool {
	return !now.Before(i.renewalPeriod.Start)
}

func (config caInSecret) check(secret *corev1.Secret) (*caInfo, error) {
	if secret == nil {
		return nil, fmt.Errorf("secret not found")
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("secret %s/%s is not of type kubernetes.io/tls", secret.Namespace, secret.Name)
	}

	keyPEM, ok := secret.Data[config.keyKey]
	if !ok || len(keyPEM) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing %q", secret.Namespace, secret.Name, config.keyKey)
	}
	caPrivateKey, err := pki.DecodePrivateKeyBytes(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	caCertPEM, ok := secret.Data[config.certKey]
	if !ok || len(caCertPEM) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing %q", secret.Namespace, secret.Name, config.certKey)
	}
	caCert, err := pki.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	equal, err := pki.PublicKeysEqual(caPrivateKey.Public(), caCert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed comparing CA public keys: %w", err)
	}
	if !equal {
		return nil, fmt.Errorf("private key does not match public key")
	}

	if time.Now().After(caCert.NotAfter) {
		return nil, fmt.Errorf("CA certificate has expired")
	}

	return &caInfo{
		renewalPeriod: certificate.RenewTriggerWindow(caCert),
		validUntil:    caCert.NotAfter,
		cert:          caCert,
		certPEM:       caCertPEM,
		privateKey:    caPrivateKey,
	}, nil
}

func (a *Authority) reconcilePendingCA(ctx context.Context) error {
	sec, err := a.secretLister.Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).Get(a.Options.AuthorityCertificate.SecretNamespacedName.Name)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return err
	}

	if !notFound {
		if servingInfo, err := servingCAInSecret.check(sec); err == nil && !servingInfo.shouldRenew(time.Now()) {
			// enqueue next renewal based on serving CA
			a.queue.AddAfter(reconcilePendingCAKey, time.Until(servingInfo.renewalPeriod.Random()))

			return nil // serving CA is valid, not expired & does not need rotation
		}

		// if the pending CA is different from the serving CA, and is valid & not expired,
		// we can wait for it to be promoted
		if !bytes.Equal(sec.Data[api.TLSPendingCertKey], sec.Data[api.TLSServingCertKey]) &&
			!bytes.Equal(sec.Data[api.TLSPendingPrivateKeyKey], sec.Data[api.TLSServingPrivateKeyKey]) {
			if pendingInfo, err := pendingCAInSecret.check(sec); err == nil {
				// enqueue new pending CA generation based on expiry of pending CA
				a.queue.AddAfter(reconcilePendingCAKey, time.Until(pendingInfo.validUntil))

				return nil // pending CA is already generated, is valid & not expired, wait for it to be promoted
			}
		}
	}

	// Generate new pending CA cert and key
	caCert, caPK, err := certificate.GenerateCA(a.Options.AuthorityCertificate.Duration)
	if err != nil {
		return err
	}
	certPEM, err := pki.EncodeCertificateAsPEM(caCert)
	if err != nil {
		return err
	}
	keyPEM, err := pki.EncodePrivateKey(caPK)
	if err != nil {
		return err
	}

	applySecret := applyconfigurationscorev1.
		Secret(a.Options.AuthorityCertificate.SecretNamespacedName.Name, a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
		WithType(corev1.SecretTypeTLS).
		WithLabels(map[string]string{
			api.DynamicAuthoritySecretLabel: "true",
		}).
		WithAnnotations(map[string]string{
			api.IssuingAuthorityIDAnnotation: a.authorityID,
		}).
		WithData(map[string][]byte{
			api.TLSPendingCertKey:       certPEM,
			api.TLSPendingPrivateKeyKey: keyPEM,
		})
	applyOptions := metav1.ApplyOptions{
		FieldManager: "webhook-cert-lib/pending-ca-reconciler-" + a.authorityID,
	}

	// A) If the secret does not exist yet (according to lister), we use a patch without force
	//	  to create it. We use a unique fieldmanager to force conflicts if the secret was created
	//    between our list and patch.
	// B) If the secret exists (according to lister), we use its resource version to
	//    avoid overwriting a pending CA that was created after we listed but before we patched.
	if !notFound && sec != nil {
		applySecret = applySecret.WithResourceVersion(sec.ResourceVersion)
		applyOptions = metav1.ApplyOptions{
			Force:        true,
			FieldManager: "webhook-cert-lib/pending-ca-reconciler",
		}
	}

	a.metrics.IncrementSecretPatches()
	sec, err = a.clientset.CoreV1().
		Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
		Apply(ctx, applySecret, applyOptions)
	if err != nil && !apierrors.IsConflict(err) {
		return err
	} else if apierrors.IsConflict(err) {
		// someone else created / updated the secret before us, likely with a pending CA
		return nil // wait for updated secret to trigger another reconcile
	}

	klog.FromContext(ctx).Info(
		"Generated new pending CA certificate and key",
		api.TLSPendingCertKey, certInfoFromPEM(sec.Data[api.TLSPendingCertKey]),
		api.TLSServingCertKey, certInfoFromPEM(sec.Data[api.TLSServingCertKey]),
		api.TLSAllTrustedCertsKey, certsInfoFromPEM(sec.Data[api.TLSAllTrustedCertsKey]),
		"bundle_version", trustBundle(sec).HashString()[:8],
	)

	return nil
}

// trustBundle combines the certificates in the secret into a bundle which should
// be injected in all targets.
func trustBundle(cert *corev1.Secret) *pki.CertPool {
	certPool := pki.NewCertPool(
		pki.WithFilteredExpiredCerts(true),
	)

	if cert != nil && cert.Data != nil {
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSServingCertKey])
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSPendingCertKey])
		_ = certPool.AddCertificatesFromPEM(cert.Data[api.TLSAllTrustedCertsKey])
	}

	return certPool
}

func (a *Authority) reconcileWithSecretInfo(fn func(secret *corev1.Secret, bundle *pki.CertPool) error) error {
	secret, err := a.secretLister.Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).Get(a.Options.AuthorityCertificate.SecretNamespacedName.Name)
	notFound := apierrors.IsNotFound(err)
	if err != nil && !notFound {
		return err
	}

	if notFound || secret == nil || secret.Data == nil {
		return nil // no secret yet, pending CA reconciler will create it
	}

	bundle := trustBundle(secret)

	return fn(secret, bundle)
}

func (a *Authority) reconcileSingleTarget(ctx context.Context, gvk schema.GroupVersionKind, key types.NamespacedName) error {
	return a.reconcileWithSecretInfo(func(secret *corev1.Secret, bundle *pki.CertPool) error {
		didPatch, err := a.injectableListPatchers[gvk].PatchObject(ctx, key, bundle.PEM(), metav1.ApplyOptions{
			Force:        true,
			FieldManager: "webhook-cert-lib/target-reconciler",
		})
		if err != nil {
			return err
		}

		if !didPatch {
			return nil // already up-to-date
		}

		a.metrics.IncrementTargetPatches()
		klog.FromContext(ctx).Info(
			"Injected trust bundle into target",
			"target_gk", gvk.GroupKind(),
			"target_key", key,
			"bundle_version", bundle.HashString()[:8],
		)

		return nil
	})
}

func (a *Authority) reconcileAllTargets(_ context.Context) error {
	return a.reconcileWithSecretInfo(func(secret *corev1.Secret, bundle *pki.CertPool) error {
		for gvk, listPatcher := range a.injectableListPatchers {
			objList, err := listPatcher.ListObjects(bundle.PEM())
			if err != nil {
				return err
			}

			for key, isUpToDate := range objList {
				if isUpToDate {
					continue // already up-to-date
				}

				a.queue.Add(reconcileSingleTargetKey(gvk, key))
			}
		}

		return nil // wait for informer to notice updated targets and add annotations
	})
}

func (a *Authority) reconcileSecretTargetAnnotation(ctx context.Context) error {
	return a.reconcileWithSecretInfo(func(secret *corev1.Secret, bundle *pki.CertPool) error {
		expectedTargets := make(map[TargetObject]struct{}, len(a.Options.Targets.Objects))
		for _, obj := range a.Options.Targets.Objects {
			expectedTargets[obj] = struct{}{}
		}

		for gvk, listPatcher := range a.injectableListPatchers {
			vwcList, err := listPatcher.ListObjects(bundle.PEM())
			if err != nil {
				return err
			}

			for key, isUpToDate := range vwcList {
				if !isUpToDate {
					// Not all targets are updated yet
					return nil // wait for individual target reconciles to complete
				}

				delete(expectedTargets, TargetObject{
					GroupKind:      gvk.GroupKind(),
					NamespacedName: key,
				})
			}
		}

		if len(expectedTargets) > 0 {
			klog.FromContext(ctx).Info(
				"Some targets were not found during annotation reconciliation",
				"missing_targets", slices.SortedFunc(maps.Keys(expectedTargets), func(a, b TargetObject) int {
					return strings.Compare(a.String(), b.String())
				}),
			)

			// Not all targets are updated yet
			return nil // wait for individual target reconciles to complete
		}

		if secret.Annotations[api.InjectedLastVersionAnnotation] == bundle.HashString() {
			return nil // annotation already up-to-date
		}

		injectionCompletedAt := time.Now().UTC().Format(time.RFC3339Nano)

		klog.FromContext(ctx).Info(
			"All targets were updated with trust bundles",
			"injection_completed_at", injectionCompletedAt,
			"bundle_version", bundle.HashString()[:8],
		)

		applySecret := applyconfigurationscorev1.
			Secret(a.Options.AuthorityCertificate.SecretNamespacedName.Name, a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
			WithAnnotations(map[string]string{
				api.InjectedAtTimestampAnnotation: injectionCompletedAt,
				api.InjectedLastVersionAnnotation: bundle.HashString(),
			})

		a.metrics.IncrementSecretPatches()
		_, err := a.clientset.CoreV1().
			Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
			Apply(ctx, applySecret, metav1.ApplyOptions{
				Force:        true,
				FieldManager: "webhook-cert-lib/target-reconciler",
			})
		if err != nil {
			return err
		}

		a.queue.AddAfter(reconcileServingCAPromotionKey, a.Options.PromotionDelay)

		return nil
	})
}

func shouldPromotePendingCA(secret *corev1.Secret, promotionDelay time.Duration) (bool, time.Time) {
	if _, err := pendingCAInSecret.check(secret); err != nil {
		return false, time.Time{} // pending CA not present, invalid or expired
	}

	if bytes.Equal(secret.Data[api.TLSPendingCertKey], secret.Data[api.TLSServingCertKey]) &&
		bytes.Equal(secret.Data[api.TLSPendingPrivateKeyKey], secret.Data[api.TLSServingPrivateKeyKey]) {
		return false, time.Time{} // pending CA is identical to serving CA, no need to promote
	}

	injectedVersionHex, hasVersionAnnotation := secret.Annotations[api.InjectedLastVersionAnnotation]
	injectedAtTimestamp, hasInjectedAt := secret.Annotations[api.InjectedAtTimestampAnnotation]

	if !hasVersionAnnotation || !hasInjectedAt {
		return false, time.Time{} // never injected
	}

	bundle := trustBundle(secret)
	if injectedVersionHex != bundle.HashString() {
		return false, time.Time{} // bundle has changed since last injection
	}

	injectedAt, err := time.Parse(time.RFC3339Nano, injectedAtTimestamp)
	if err != nil {
		return false, time.Time{} // invalid timestamp
	}

	return true, injectedAt.Add(promotionDelay)
}

func (a *Authority) reconcileServingCAPromotion(ctx context.Context) error {
	return a.reconcileWithSecretInfo(func(secret *corev1.Secret, bundle *pki.CertPool) error {
		shouldPromote, promoteAt := shouldPromotePendingCA(secret, a.Options.PromotionDelay)
		if !shouldPromote {
			return nil // not ready for promotion yet
		}

		if time.Now().Before(promoteAt) {
			a.queue.AddAfter(reconcileServingCAPromotionKey, time.Until(promoteAt))

			return nil // wait until promotion delay has passed
		}

		// promote pending to serving

		applySecret := applyconfigurationscorev1.
			Secret(a.Options.AuthorityCertificate.SecretNamespacedName.Name, a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
			WithType(corev1.SecretTypeTLS).
			WithData(map[string][]byte{
				api.TLSServingCertKey:       secret.Data[api.TLSPendingCertKey],
				api.TLSServingPrivateKeyKey: secret.Data[api.TLSPendingPrivateKeyKey],
				api.TLSAllTrustedCertsKey:   bundle.PEM(),
			})

		a.metrics.IncrementSecretPatches()
		sec, err := a.clientset.CoreV1().
			Secrets(a.Options.AuthorityCertificate.SecretNamespacedName.Namespace).
			Apply(ctx, applySecret, metav1.ApplyOptions{
				Force:        true,
				FieldManager: "webhook-cert-lib/serving-ca-reconciler",
			})
		if err != nil {
			return err
		}

		klog.FromContext(ctx).Info(
			"Promoted pending CA to serving CA",
			api.TLSPendingCertKey, certInfoFromPEM(sec.Data[api.TLSPendingCertKey]),
			api.TLSServingCertKey, certInfoFromPEM(sec.Data[api.TLSServingCertKey]),
			api.TLSAllTrustedCertsKey, certsInfoFromPEM(sec.Data[api.TLSAllTrustedCertsKey]),
			"bundle_version", trustBundle(sec).HashString()[:8],
		)

		// trigger leaf issuance promptly after promotion
		a.queue.Add(reconcileLeafCertificateKey)

		return nil // promotion done
	})
}

func (a *Authority) reconcileLeafCertificate(ctx context.Context) error {
	return a.reconcileWithSecretInfo(func(secret *corev1.Secret, bundle *pki.CertPool) error {
		servingInfo, err := servingCAInSecret.check(secret)
		if err != nil {
			return nil // nolint:nilerr // serving CA not present or invalid, wait for promotion
		}

		// if current leaf cert is valid and signed by current serving CA, and does not need renewal, we don't issue a new leaf
		if leaf := a.leaf.Load(); leaf != nil && bytes.Equal(leaf.ca, servingInfo.certPEM) {
			if !leaf.validUntil.Before(servingInfo.validUntil) {
				// leaf already lives until the ca cert expires

				return nil // we wait until the ca is rotated
			}

			if time.Now().Before(leaf.renewalPeriod.Start) {
				// leaf still valid and does not need renewal
				// enqueue next renewal based on leaf cert
				a.queue.AddAfter(reconcileLeafCertificateKey, time.Until(leaf.renewalPeriod.Random()))

				return nil // leaf cert is valid and signed by current serving CA, no action needed
			}

			// stored leaf needs renewal, continue to issue a new one
		}

		leafCert, leafPK, err := certificate.GenerateLeaf(a.leafDNSNames, a.leafDuration, servingInfo.cert, servingInfo.privateKey)
		if err != nil {
			return fmt.Errorf("failed generating leaf certificate: %w", err)
		}

		tlsCert, err := pki.ToTLSCertificate(leafCert, leafPK)
		if err != nil {
			return fmt.Errorf("failed assembling tls.Certificate: %w", err)
		}
		withExpiry := tlsCertWithExpiry{
			cert:          tlsCert,
			renewalPeriod: certificate.RenewTriggerWindow(leafCert),
			validUntil:    leafCert.NotAfter,
			ca:            servingInfo.certPEM,
		}
		a.leaf.Store(&withExpiry)

		klog.FromContext(ctx).Info(
			"New leaf certificate issued signed by current serving CA and available for serving",
			api.TLSServingCertKey, certInfoFromPEM(secret.Data[api.TLSServingCertKey]),
			"leaf_certificate", certInfo(leafCert),
		)

		// enqueue next renewal based on leaf cert
		a.queue.AddAfter(reconcileLeafCertificateKey, time.Until(withExpiry.renewalPeriod.Random()))

		return nil
	})
}
