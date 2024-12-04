/*
Copyright The cert-manager Authors.

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

package leadercontrollers

import (
	"github.com/cert-manager/webhook-cert-lib/pkg/authority/leader_controllers/injectable"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	fieldOwner = client.FieldOwner("cert-manager-dynamic-authority")
)

func newApplyPatch(ac injectable.ApplyConfiguration) applyPatch {
	return applyPatch{ac: ac}
}

type applyPatch struct {
	ac injectable.ApplyConfiguration
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return json.Marshal(p.ac)
}
