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

package pipeline_definition_file

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/conftest/output"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
)

type mockEvaluator struct{}

func (e mockEvaluator) Evaluate(ctx context.Context, inputs []string) ([]output.CheckResult, error) {
	return []output.CheckResult{}, nil
}

func (e mockEvaluator) Destroy() {
}

func mockNewConftestEvaluator(ctx context.Context, fs afero.Fs, policySources []source.PolicySource, p policy.Policy) (evaluator.Evaluator, error) {
	return mockEvaluator{}, nil
}

func mockPathExists(fs afero.Fs, path string) (bool, error) {
	if path == "/tmp" {
		return true, nil
	}
	return false, nil
}

func Test_NewPipelineDefinitionFile(t *testing.T) {
	newConftestEvaluator = mockNewConftestEvaluator
	pathExists = mockPathExists
	fs := afero.NewOsFs()
	pol, err := policy.NewOfflinePolicy(context.TODO(), policy.Now)
	assert.NoError(t, err)

	evaluated, _ := mockNewConftestEvaluator(context.TODO(), fs, []source.PolicySource{}, pol)
	tests := []struct {
		name    string
		fpath   string
		err     error
		defFile *DefinitionFile
	}{
		{
			name:  "successful",
			fpath: "/tmp",
			err:   nil,
			defFile: &DefinitionFile{
				Fpath:     "/tmp",
				Evaluator: evaluated,
			},
		},
		{
			name:    "path does not exists",
			fpath:   "asljdfad/fbaksjdfasdf",
			err:     fmt.Errorf("fpath '%s' does not exist", "asljdfad/fbaksjdfasdf"),
			defFile: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defFile, err := NewPipelineDefinitionFile(context.TODO(), fs, tt.fpath, []source.PolicySource{})
			assert.Equal(t, tt.err, err)
			assert.Equal(t, tt.defFile, defFile)
		})
	}
}
