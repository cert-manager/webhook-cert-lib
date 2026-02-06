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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cert-manager/webhook-cert-lib/pkg/authority"
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/injectable"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func loadKubeConfig(kubeconfig string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
}

func main() {
	kubeconfig := flag.String("kubeconfig", "", "Path to kubeconfig (optional)")
	addr := flag.String("addr", ":8443", "Address to serve HTTPS on")
	serviceName := flag.String("service-name", "example-webhook", "will be used in the DNS name for the webhook server certificate (<service-name>.<namespace>.svc)")
	vwcName := flag.String("validating-webhook-configuration-name", "example-webhook-validating", "Name of the ValidatingWebhookConfiguration to patch with the CA bundle")
	flag.Parse()

	cfg, err := loadKubeConfig(*kubeconfig)
	if err != nil {
		log.Fatalf("failed to load kubeconfig: %v", err)
	}

	inClusterSettings, err := authority.DetectInClusterSettings()
	if err != nil {
		log.Fatalf("failed to detect in-cluster settings: %v", err)
	}

	opts := authority.AuthorityOptions{
		AuthorityCertificate: authority.AuthorityCertificateOptions{
			SecretNamespacedName: inClusterSettings.SecretNamespacedName(*serviceName + "-ca"),
		},
		Targets: authority.TargetsOptions{
			Objects: []authority.TargetObject{
				{
					GroupKind: (injectable.ValidatingWebhookCaBundleInject{}).
						GroupVersionKind().
						GroupKind(),
					NamespacedName: types.NamespacedName{Name: *vwcName},
				},
			},
		},
		ServerCertificate: authority.ServerCertificateOptions{
			DNSNames: []string{
				inClusterSettings.ServiceDNSName(*serviceName),
			},
		},
	}

	a, err := authority.NewAuthorityForConfig(cfg, opts)
	if err != nil {
		log.Fatalf("failed to create authority: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := a.Start(ctx); err != nil {
			log.Fatalf("authority exited with error: %v", err)
		}
	}()

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	a.ServingCertificate(tlsCfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-ctx.Done():
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		default:
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		// Parse AdmissionReview request
		var review admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			log.Printf("/validate: failed to decode admission review: %v", err)
			http.Error(w, "failed to decode admission review", http.StatusBadRequest)
			return
		}

		// Default: allow the request. In a real webhook, inspect review.Request and decide.
		resp := admissionv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: true,
		}

		review.Response = &resp
		// Clear the request to reduce response size
		review.Request = nil

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(review); err != nil {
			log.Printf("/validate: failed to encode admission review response: %v", err)
		}
	})

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("starting webhook server on %s", srv.Addr)
		// TLS certificates are provided dynamically via tls.Config.GetCertificate
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()

	log.Printf("waiting for 2 seconds before shutting down server...")

	// give some time for kubernetes to remove this pod from service endpoints, disable
	// keep-alives to speed up connection close
	srv.SetKeepAlivesEnabled(false)
	time.Sleep(2 * time.Second)

	log.Printf("shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
