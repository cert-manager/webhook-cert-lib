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
	"testing"
	"time"
)

func TestRenewTriggerWindow_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		notBefore time.Time
		lifetime  time.Duration
	}{
		{
			name:      "bounds",
			notBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			lifetime:  100 * time.Hour,
		},
		{
			name:      "random_within_bounds",
			notBefore: time.Now().UTC().Truncate(time.Second),
			lifetime:  10 * time.Hour,
		},
		{
			name:      "very_short_lifetime",
			notBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			lifetime:  1 * time.Nanosecond,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: c.notBefore,
				NotAfter:  c.notBefore.Add(c.lifetime),
			}
			tw := RenewTriggerWindow(cert)

			wantStart := c.notBefore.Add(c.lifetime * 6 / 10)
			wantEnd := c.notBefore.Add(c.lifetime * 7 / 10)

			if !tw.Start.Equal(wantStart) {
				t.Fatalf("%s: Start = %v, want %v", c.name, tw.Start, wantStart)
			}
			if !tw.End.Equal(wantEnd) {
				t.Fatalf("%s: End = %v, want %v", c.name, tw.End, wantEnd)
			}

			// If the window collapsed to a point, Start == End and Random() should equal Start.
			if tw.Start.Equal(tw.End) {
				r := tw.Random()
				if !r.Equal(tw.Start) {
					t.Fatalf("%s: Random returned %v, want %v", c.name, r, tw.Start)
				}
				return
			}

			// Otherwise ensure Random returns values within [Start, End).
			for range 200 {
				r := tw.Random()
				if r.Before(tw.Start) || !r.Before(tw.End) {
					t.Fatalf("%s: Random returned %v outside window [%v, %v)", c.name, r, tw.Start, tw.End)
				}
			}
		})
	}
}
