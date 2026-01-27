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

package certificate

import (
	"crypto/x509"
	"math/rand/v2"
	"time"
)

type TriggerWindow struct {
	Start time.Time
	End   time.Time
}

func (tw TriggerWindow) duration() time.Duration {
	return tw.End.Sub(tw.Start)
}

// Random returns a random time within the TriggerWindow.
// This value lies within [Start, End).
func (tw TriggerWindow) Random() time.Time {
	randomRenewalPoint := time.Duration(float64(tw.duration()) * rand.Float64()) // #nosec G404
	return tw.Start.Add(randomRenewalPoint)
}

// RenewTriggerWindow returns the period during which a certificate renewal should
// be scheduled (between 6/10 and 7/10 of its lifetime).
func RenewTriggerWindow(cert *x509.Certificate) TriggerWindow {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return TriggerWindow{
		Start: cert.NotBefore.Add(lifetime * 6 / 10),
		End:   cert.NotBefore.Add(lifetime * 7 / 10),
	}
}
