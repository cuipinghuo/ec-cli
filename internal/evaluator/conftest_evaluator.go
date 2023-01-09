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

package evaluator

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/runner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/hacbs-contract/ec-cli/internal/policy"
	"github.com/hacbs-contract/ec-cli/internal/policy/source"
	"github.com/hacbs-contract/ec-cli/internal/utils"
)

type contextKey string

const runnerKey contextKey = "ec.evaluator.runner"

type testRunner interface {
	Run(context.Context, []string) ([]output.CheckResult, error)
}

// ConftestEvaluator represents a structure which can be used to evaluate targets
type conftestEvaluator struct {
	policySources []source.PolicySource
	namespace     string
	outputFormat  string
	workDir       string
	dataDir       string
	policyDir     string
	effectiveTime time.Time
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, fs afero.Fs, policySources []source.PolicySource, namespace string, p *policy.Policy) (Evaluator, error) {
	c := conftestEvaluator{
		policySources: policySources,
		namespace:     namespace,
		outputFormat:  "json",
		effectiveTime: p.EffectiveTime,
	}

	dir, err := utils.CreateWorkDir(fs)
	if err != nil {
		log.Debug("Failed to create work dir!")
		return nil, err
	}
	c.workDir = dir

	c.policyDir = filepath.Join(c.workDir, "policy")
	c.dataDir = filepath.Join(c.workDir, "data")

	log.Debugf("Created work dir %s", dir)

	if err := c.createDataDirectory(ctx, fs, p); err != nil {
		return nil, err
	}

	log.Debug("Conftest test runner created")
	return c, nil
}

func (c conftestEvaluator) Evaluate(ctx context.Context, inputs []string) ([]output.CheckResult, error) {
	results := make([]output.CheckResult, 0, 10)

	// Download all sources
	for _, s := range c.policySources {
		_, err := s.GetPolicy(ctx, c.workDir, false)
		if err != nil {
			log.Debugf("Unable to download source from %s!", s.PolicyUrl())
			// TODO do we want to download other policies instead of erroring out?
			return nil, err
		}
	}

	var r testRunner
	var ok bool
	if r, ok = ctx.Value(runnerKey).(testRunner); r == nil || !ok {

		r = &runner.TestRunner{
			Data:      []string{c.dataDir},
			Policy:    []string{c.policyDir},
			Namespace: []string{c.namespace},
			NoFail:    true,
			Output:    c.outputFormat,
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", inputs)
	runResults, err := r.Run(ctx, inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, err
	}

	now := c.effectiveTime
	for i, result := range runResults {
		failures := []output.Result{}
		for _, failure := range result.Failures {
			if !isResultEffective(failure, now) {
				// TODO: Instead of moving to warnings, create new attribute: "futureViolations"
				result.Warnings = append(result.Warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}
		result.Failures = failures
		runResults[i] = result
	}

	results = append(results, runResults...)

	return results, nil
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(fs afero.Fs, dataDir string, p *policy.Policy) error {
	if p == nil {
		return nil
	}

	configFilePath := filepath.Join(dataDir, "config.json")

	var config = map[string]interface{}{
		"config": map[string]interface{}{},
	}

	type policyConfig struct {
		NonBlocking *[]string `json:"non_blocking_checks,omitempty"` // TODO deprecated, to be removed
		Exclude     *[]string `json:"exclude,omitempty"`
		Include     *[]string `json:"include,omitempty"`
		Collections *[]string `json:"collections,omitempty"`
		WhenNs      int64     `json:"when_ns"`
	}
	pc := &policyConfig{}

	// TODO: Once the NonBlocking field has been removed, update to dump the spec.Config into an updated policyConfig struct
	if p.Exceptions != nil {
		log.Debug("Non-blocking exceptions found. These will be written to file ", dataDir)
		pc.NonBlocking = &p.Exceptions.NonBlocking
	}
	if p.Configuration != nil {
		log.Debug("Include rules found. These will be written to file ", dataDir)
		if p.Configuration.Include != nil {
			pc.Include = &p.Configuration.Include
		}
		log.Debug("Exclude rules found. These will be written to file ", dataDir)
		if p.Configuration.Exclude != nil {
			pc.Exclude = &p.Configuration.Exclude
		}
		log.Debug("Collections found. These will be written to file ", dataDir)
		if p.Configuration.Collections != nil {
			pc.Collections = &p.Configuration.Collections
		}
	}

	// Now that the future deny logic is handled in the ec-cli and not in rego,
	// this field is used only for the checking the effective times in the
	// acceptable bundles list. Always set it, even when we are using the current
	// time, so that a consistent current time is used everywhere.
	pc.WhenNs = p.EffectiveTime.UnixNano()

	// Add the policy config we just prepared
	config["config"] = map[string]interface{}{
		"policy": pc,
	}

	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	// Check to see if the data.json file exists
	exists, err := afero.Exists(fs, configFilePath)
	if err != nil {
		return err
	}
	// if so, remove it
	if exists {
		if err := fs.Remove(configFilePath); err != nil {
			return err
		}
	}
	// write our jsonData content to the data.json file in the data directory under the workDir
	log.Debugf("Writing config data to %s: %#v", configFilePath, string(configJSON))
	if err := afero.WriteFile(fs, configFilePath, configJSON, 0444); err != nil {
		return err
	}

	return nil
}

// createDataDirectory creates the base content in the data directory
func (c *conftestEvaluator) createDataDirectory(ctx context.Context, fs afero.Fs, p *policy.Policy) error {
	dataDir := c.dataDir
	exists, err := afero.DirExists(fs, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = fs.MkdirAll(dataDir, 0755)
	}

	if err := createConfigJSON(fs, dataDir, p); err != nil {
		return err
	}

	return nil
}

const (
	effectiveOnKey    = "effective_on"
	effectiveOnFormat = "2006-01-02T15:04:05Z"
)

// isResultEffective returns whether or not the given result's effective date is before now.
// Failure to determine the effective date is reported as the result being effective.
func isResultEffective(failure output.Result, now time.Time) bool {
	raw, ok := failure.Metadata[effectiveOnKey]
	if !ok {
		return true
	}
	str, ok := raw.(string)
	if !ok {
		log.Warnf("Ignoring non-string %q value %#v", effectiveOnKey, raw)
		return true
	}
	effectiveOn, err := time.Parse(effectiveOnFormat, str)
	if err != nil {
		log.Warnf("Invalid %q value %q", effectiveOnKey, failure.Metadata)
		return true
	}
	return effectiveOn.Before(now)
}
