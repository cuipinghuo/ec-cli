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

package validate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	hd "github.com/MakeNowJust/heredoc"
	conftestOutput "github.com/open-policy-agent/conftest/output"
	app "github.com/redhat-appstudio/application-api/api/v1alpha1"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/hacbs-contract/ec-cli/internal/applicationsnapshot"
	"github.com/hacbs-contract/ec-cli/internal/evaluator"
	"github.com/hacbs-contract/ec-cli/internal/output"
	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

const mockPublicKey string = `-----BEGIN PUBLIC KEY-----\n` +
	`MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPEwqj1tPu2Uwti2abGgGgURluuad\n` +
	`BK1e0Opk9WTCJ6WyP8Yo3Dl9wNJnjfzBGoRocUsfSd8foGKnFX1E34xVzw==\n` +
	`-----END PUBLIC KEY-----\n`

type data struct {
	imageRef string
	input    string
	filePath string
}

func Test_determineInputSpec(t *testing.T) {
	cases := []struct {
		name      string
		arguments data
		spec      *app.SnapshotSpec
		err       string
	}{
		{
			name: "imageRef",
			arguments: data{
				imageRef: "registry/image:tag",
			},
			spec: &app.SnapshotSpec{
				Components: []app.SnapshotComponent{
					{
						Name:           "Unnamed",
						ContainerImage: "registry/image:tag",
					},
				},
			},
		},
		{
			name: "empty ApplicationSnapshot string",
			arguments: data{
				input: "{}",
			},
			spec: &app.SnapshotSpec{},
		},
		{
			name: "faulty ApplicationSnapshot string",
			arguments: data{
				input: "{",
			},
			err: "unable to parse Snapshot specification from input: error converting YAML to JSON: yaml: line 1: did not find expected node content",
		},
		{
			name: "ApplicationSnapshot JSON string",
			arguments: data{
				input: `{
					"application": "app1",
					"components": [
					  {
						"name": "nodejs",
						"containerImage": "quay.io/hacbs-contract-demo/single-nodejs-app:877418e"
					  },
					  {
						"name": "petclinic",
						"containerImage": "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f"
					  },
					  {
						"name": "single-container-app",
						"containerImage": "quay.io/hacbs-contract-demo/single-container-app:62c06bf"
					  }
					]
				  }`,
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot YAML string",
			arguments: data{
				input: hd.Doc(`
					---
					application: app1
					components:
					- name: nodejs
					  containerImage: quay.io/hacbs-contract-demo/single-nodejs-app:877418e
					- name: petclinic
					  containerImage: quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f
					- name: single-container-app
					  containerImage: quay.io/hacbs-contract-demo/single-container-app:62c06bf
					`),
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
				},
			},
		},
		{
			name: "ApplicationSnapshot file",
			arguments: data{
				filePath: "test_application_snapshot.json",
			},
			spec: &app.SnapshotSpec{
				Application: "app1",
				Components: []app.SnapshotComponent{
					{
						Name:           "nodejs",
						ContainerImage: "quay.io/hacbs-contract-demo/single-nodejs-app:877418e",
					},
					{
						Name:           "petclinic",
						ContainerImage: "quay.io/hacbs-contract-demo/spring-petclinic:dc80a7f",
					},
					{
						Name:           "single-container-app",
						ContainerImage: "quay.io/hacbs-contract-demo/single-container-app:62c06bf",
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := applicationsnapshot.DetermineInputSpec(context.Background(), applicationsnapshot.Input{
				File:  c.arguments.filePath,
				JSON:  c.arguments.input,
				Image: c.arguments.imageRef,
			})
			if c.err != "" {
				assert.EqualError(t, err, c.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, c.spec, s)
		})
	}
}

func Test_ValidateImageCommand(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSyntaxCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						FileName:  "test.json",
						Namespace: "test.main",
						Successes: 1,
					},
					Successes: []conftestOutput.Result{
						{
							Message: "Pass",
							Metadata: map[string]interface{}{
								"code": "policy.nice",
							},
						},
					},
				},
			},
			ImageURL: url,
			ExitCode: 0,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"successes": [
				{"msg": "Pass", "metadata": {"code": "policy.nice"}}
			],
			"success": true
		  }
		],
		"policy": {
			"publicKey": "%s"
		}
	  }`, mockPublicKey, mockPublicKey), out.String())
}

func Test_ValidateErrorCommand(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name: "image validation failure",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
			},
			expected: `1 error occurred:
	* error validating image registry/image:tag of component Unnamed: expected

`,
		},
		{
			name: "invalid policy JSON",
			args: []string{
				"--image",
				"registry/image:tag",
				"--policy",
				`{"invalid": "json""}`,
			},
			expected: `1 error occurred:
	* unable to parse EnterpriseContractPolicy Spec: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
		{
			name: "invalid input JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
			},
			expected: `1 error occurred:
	* unable to parse Snapshot specification from input: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
		{
			name: "invalid input and policy JSON",
			args: []string{
				"--json-input",
				`{"invalid": "json""}`,
				"--policy",
				`{"invalid": "json""}`,
			},
			expected: `2 errors occurred:
	* unable to parse Snapshot specification from input: error converting YAML to JSON: yaml: found unexpected end of stream
	* unable to parse EnterpriseContractPolicy Spec: error converting YAML to JSON: yaml: found unexpected end of stream

`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			validate := func(context.Context, string, policy.Policy, bool) (*output.Output, error) {
				return nil, errors.New("expected")
			}

			cmd := validateImageCmd(validate)

			cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

			cmd.SetArgs(c.args)

			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true

			err := cmd.Execute()
			assert.EqualError(t, err, c.expected)
			assert.Empty(t, out.String())
		})
	}
}

func Test_FailureImageAccessibility(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "skipped due to inaccessible image ref"},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [
			  {"msg": "image ref not accessible. HEAD registry/image:tag: unexpected status code 404 Not Found (HEAD responses have no body, use GET for details)"},
			  {"msg": "skipped due to inaccessible image ref"},
			  {"msg": "skipped due to inaccessible image ref"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": "%s"
		}
	  }`, mockPublicKey, mockPublicKey), out.String())
}

func Test_FailureOutput(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "failed image signature check"},
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: false,
				Result: &conftestOutput.Result{Message: "failed attestation signature check"},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": false,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"violations": [
			  {"msg": "failed attestation signature check"},
			  {"msg": "failed image signature check"}
			],
			"success": false
		  }
		],
		"policy": {
			"publicKey": "%s"
		}
	  }`, mockPublicKey, mockPublicKey), out.String())
}

func Test_WarningOutput(t *testing.T) {
	validate := func(_ context.Context, url string, _ policy.Policy, _ bool) (*output.Output, error) {
		return &output.Output{
			ImageSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			ImageAccessibleCheck: output.VerificationStatus{
				Passed: true,
			},
			AttestationSignatureCheck: output.VerificationStatus{
				Passed: true,
			},
			PolicyCheck: evaluator.CheckResults{
				{
					CheckResult: conftestOutput.CheckResult{
						Warnings: []conftestOutput.Result{
							{Message: "warning for policy check 1"},
							{Message: "warning for policy check 2"},
						},
					},
				},
			},
			ImageURL: url,
		}, nil
	}

	cmd := validateImageCmd(validate)

	cmd.SetContext(utils.WithFS(context.TODO(), afero.NewMemMapFs()))

	cmd.SetArgs([]string{
		"--image",
		"registry/image:tag",
		"--policy",
		fmt.Sprintf(`{"publicKey": "%s"}`, mockPublicKey),
	})

	var out bytes.Buffer
	cmd.SetOut(&out)

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"success": true,
		"key": "%s",
		"components": [
		  {
			"name": "Unnamed",
			"containerImage": "registry/image:tag",
			"warnings": [
				{"msg": "warning for policy check 1"},
				{"msg": "warning for policy check 2"}
			],
			"success": true
		  }
		],
		"policy": {
			"publicKey": "%s"
		}
	  }`, mockPublicKey, mockPublicKey), out.String())
}
