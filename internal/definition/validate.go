// Copyright 2022 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package definition

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/hacbs-contract/ec-cli/internal/evaluation_target/definition"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

var def_file = definition.NewDefinition

// ValidatePipeline calls NewPipelineEvaluator to obtain an PipelineEvaluator. It then executes the associated TestRunner
// which tests the associated pipeline file(s) against the associated policies, and displays the output.
func ValidateDefinition(ctx context.Context, fpath string, sources []source.PolicySource) (*output.Output, error) {
	p, err := def_file(ctx, fpath, sources)
	if err != nil {
		log.Debug("Failed to create pipeline definition file!")
		return nil, err
	}

	results, err := p.Evaluator.Evaluate(ctx, []string{p.Fpath})
	if err != nil {
		log.Debug("Problem running conftest policy check!")
		return nil, err
	}
	log.Debug("Conftest policy check complete")
	return &output.Output{PolicyCheck: results}, nil
}
