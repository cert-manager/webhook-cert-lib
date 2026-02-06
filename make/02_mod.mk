# Copyright 2026 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$(kind_cluster_config): make/config/kind/cluster.yaml | $(bin_dir)/scratch
	cat $< | \
	sed -e 's|{{KIND_IMAGES}}|$(CURDIR)/$(images_tar_dir)|g' \
	> $@

include make/test-unit.mk
include make/test-smoke.mk

.PHONY: generate-diagrams
# Generate architecture and rotation diagrams from mermaid source files.
# Is not part of the main build process, run manually when diagrams need updating.
# Requires Docker to be installed.
generate-diagrams:
	docker run --rm \
		-u `id -u`:`id -g` \
		-v $(CURDIR)/diagrams:/data \
		ghcr.io/mermaid-js/mermaid-cli/mermaid-cli \
		-t dark -b transparent \
		-i architecture.mmd \
		-o architecture.svg
		
	docker run --rm \
		-u `id -u`:`id -g` \
		-v $(CURDIR)/diagrams:/data \
		ghcr.io/mermaid-js/mermaid-cli/mermaid-cli \
		-t dark -b transparent \
		-i rotation.mmd \
		-o rotation.svg

.PHONY: test-e2e
test-e2e: test-smoke
test-e2e: # only defining this to make CI happy

.PHONY: test-integration
test-integration: # only defining this to make CI happy
