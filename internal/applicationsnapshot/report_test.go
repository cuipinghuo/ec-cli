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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unit

package applicationsnapshot

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	hd "github.com/MakeNowJust/heredoc"
	"github.com/open-policy-agent/conftest/output"
	appstudioshared "github.com/redhat-appstudio/managed-gitops/appstudio-shared/apis/appstudio.redhat.com/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/format"
	"github.com/hacbs-contract/ec-cli/internal/policy"
)

//go:embed test_snapshot.json
var testSnapshot string

func Test_ReportJson(t *testing.T) {
	var snapshot appstudioshared.ApplicationSnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	expected := fmt.Sprintf(`
    {
      "success": false,
	  "key": "%s",
      "components": [
        {
          "name": "spam",
          "containerImage": "quay.io/caf/spam@sha256:123…",
          "violations": [{"msg": "violation1"}],
          "warnings": [{"msg": "warning1"}],
		  "successes": [{"msg": "success1"}],
          "success": false
        },
        {
          "name": "bacon",
          "containerImage": "quay.io/caf/bacon@sha256:234…",
          "violations": [{"msg": "violation2"}],
          "success": false
        },
        {
			"name": "eggs",
			"containerImage": "quay.io/caf/eggs@sha256:345…",
			"successes": [{"msg": "success3"}],
			"success": true
        }
      ],
	  "policy": {
		"publicKey": "%s"
	  }
    }
  	`, testPublicKeyCompact, testPublicKeyCompact)

	components := testComponentsFor(snapshot)

	ctx := context.Background()
	report, err := NewReport(components, createTestPolicy(t, ctx))
	assert.NoError(t, err)
	reportJson, err := report.toFormat(JSON)
	assert.NoError(t, err)
	assert.JSONEq(t, expected, string(reportJson))
	assert.False(t, report.Success)
}

func Test_ReportYaml(t *testing.T) {
	var snapshot *appstudioshared.ApplicationSnapshotSpec
	err := json.Unmarshal([]byte(testSnapshot), &snapshot)
	assert.NoError(t, err)

	expected := fmt.Sprintf(`
success: false
key: "%s"
components:
  - name: spam
    containerImage: quay.io/caf/spam@sha256:123…
    violations:
      - msg: violation1
    warnings:
      - msg: warning1
    successes:
      - msg: success1
    success: false
  - name: bacon
    containerImage: quay.io/caf/bacon@sha256:234…
    violations:
      - msg: violation2
    success: false
  - name: eggs
    containerImage: quay.io/caf/eggs@sha256:345…
    successes:
      - msg: success3
    success: true
policy:
  publicKey: "%s"
`, testPublicKeyCompact, testPublicKeyCompact)

	components := testComponentsFor(*snapshot)

	ctx := context.Background()
	report, err := NewReport(components, createTestPolicy(t, ctx))
	assert.NoError(t, err)
	reportYaml, err := report.toFormat(YAML)
	assert.NoError(t, err)
	assert.YAMLEq(t, expected, string(reportYaml))
	assert.False(t, report.Success)
}

func Test_ReportSummary(t *testing.T) {
	tests := []struct {
		name  string
		input Component
		want  summary
	}{
		{
			"testing one violation and warning",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			},
			summary{
				Components: []componentSummary{
					{
						Violations: map[string][]string{
							"short_name": {"short report"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report"},
						},
						Successes:       map[string][]string{},
						TotalViolations: 1,
						TotalSuccesses:  0,
						TotalWarnings:   1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
				Key:     testPublicKey,
			},
		},
		{
			"testing no metadata",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
					},
				},
				Success: false,
			},
			summary{
				Components: []componentSummary{
					{
						Violations:      map[string][]string{},
						Warnings:        map[string][]string{},
						Successes:       map[string][]string{},
						TotalViolations: 1,
						TotalWarnings:   1,
						Success:         false,
						TotalSuccesses:  0,
						Name:            "",
					},
				},
				Success: false,
				Key:     testPublicKey,
			},
		},
		{
			"testing multiple violations and warnings",
			Component{
				Violations: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
					{
						Message: "short report",
						Metadata: map[string]interface{}{
							"code": "short_name",
						},
					},
				},
				Success: false,
			},
			summary{
				Components: []componentSummary{
					{
						Violations: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						Warnings: map[string][]string{
							"short_name": {"short report", "There are 1 more \"short_name\" messages"},
						},
						Successes:       map[string][]string{},
						TotalViolations: 2,
						TotalWarnings:   2,
						Success:         false,
						TotalSuccesses:  0,
						Name:            "",
					},
				},
				Success: false,
				Key:     testPublicKey,
			},
		},
		{
			"with successes",
			Component{
				Violations: []output.Result{
					{
						Message: "violation",
						Metadata: map[string]interface{}{
							"code": "violation",
						},
					},
				},
				Warnings: []output.Result{
					{
						Message: "warning",
						Metadata: map[string]interface{}{
							"code": "warning",
						},
					},
				},
				Successes: []output.Result{
					{
						Message: "success",
						Metadata: map[string]interface{}{
							"code": "success",
						},
					},
				},
				Success: false,
			},
			summary{
				Components: []componentSummary{
					{
						Violations:      map[string][]string{"violation": {"violation"}},
						Warnings:        map[string][]string{"warning": {"warning"}},
						Successes:       map[string][]string{"success": {"success"}},
						TotalViolations: 1,
						TotalWarnings:   1,
						TotalSuccesses:  1,
						Success:         false,
						Name:            "",
					},
				},
				Success: false,
				Key:     testPublicKey,
			},
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("NewReport=%s", tc.name), func(t *testing.T) {
			ctx := context.Background()
			report, err := NewReport([]Component{tc.input}, createTestPolicy(t, ctx))
			assert.NoError(t, err)
			assert.Equal(t, tc.want, report.toSummary())
		})
	}

}

func Test_ReportHACBS(t *testing.T) {
	cases := []struct {
		name       string
		expected   string
		components []Component
		success    bool
	}{
		{
			name: "success",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SUCCESS",
				"successes": 3,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{{Success: true}, {Success: true}, {Success: true}},
			success:    true,
		},
		{
			name: "warning",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "WARNING",
				"successes": 2,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true},
				{Success: true, Warnings: []output.Result{{Message: "this is a warning"}}},
			},
			success: true,
		},
		{
			name: "failure",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{
				{Success: true},
				{Success: false, Violations: []output.Result{{Message: "this is a violation"}}},
			},
			success: false,
		},
		{
			name: "failure without violations",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{{Success: false}, {Success: true}},
			success:    false,
		},
		{
			name: "failure over warning",
			expected: `
			{
				"failures": 1,
				"namespace": "",
				"result": "FAILURE",
				"successes": 1,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 1
			}`,
			components: []Component{
				{Success: true},
				{Success: false, Violations: []output.Result{{Message: "this is a violation"}}},
				{Success: false, Warnings: []output.Result{{Message: "this is a warning"}}},
			},
			success: false,
		},
		{
			name: "skipped",
			expected: `
			{
				"failures": 0,
				"namespace": "",
				"result": "SKIPPED",
				"successes": 0,
				"timestamp": "1970-01-01T00:00:00Z",
				"warnings": 0
			}`,
			components: []Component{},
			success:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			defaultWriter, err := fs.Create("default")
			assert.NoError(t, err)

			ctx := context.Background()
			report, err := NewReport(c.components, createTestPolicy(t, ctx))
			assert.NoError(t, err)
			assert.False(t, report.created.IsZero())
			assert.Equal(t, c.success, report.Success)

			report.created = time.Unix(0, 0).UTC()

			p := format.NewTargetParser(JSON, defaultWriter, fs)
			assert.NoError(t, report.WriteAll([]string{"hacbs=report.json", "hacbs"}, p))

			reportText, err := afero.ReadFile(fs, "report.json")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(reportText))

			defaultReportText, err := afero.ReadFile(fs, "default")
			assert.NoError(t, err)
			assert.JSONEq(t, c.expected, string(defaultReportText))
		})
	}
}

func testComponentsFor(snapshot appstudioshared.ApplicationSnapshotSpec) []Component {
	components := []Component{
		{
			ApplicationSnapshotComponent: snapshot.Components[0],
			Violations: []output.Result{
				{
					Message: "violation1",
				},
			},
			Warnings: []output.Result{
				{
					Message: "warning1",
				},
			},
			Successes: []output.Result{
				{
					Message: "success1",
				},
			},
			Success: false,
		},
		{
			ApplicationSnapshotComponent: snapshot.Components[1],
			Violations: []output.Result{
				{
					Message: "violation2",
				},
			},
			Success: false,
		},
		{
			ApplicationSnapshotComponent: snapshot.Components[2],
			Successes: []output.Result{
				{
					Message: "success3",
				},
			},
			Success: true,
		},
	}
	return components
}

var testPublicKey = hd.Doc(`
	-----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd1WDOudb86dW6Ume+d0B8SILNdsW
	vn2vZNA6+5u53oaJRFDi15iOqDPlxMWbvwN1C0r8OpIvIQeOAWEjHqfx/w==
	-----END PUBLIC KEY-----
	`)

var testPublicKeyCompact = strings.ReplaceAll(testPublicKey, "\n", "\\n")

func createTestPolicy(t *testing.T, ctx context.Context) policy.Policy {
	p, err := policy.NewPolicy(ctx, "", "", testPublicKey, policy.Now)
	assert.NoError(t, err)
	return p
}
