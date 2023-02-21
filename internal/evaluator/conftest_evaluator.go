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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/conftest/output"
	"github.com/open-policy-agent/conftest/runner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/exp/slices"

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
	outputFormat  string
	workDir       string
	dataDir       string
	policyDir     string
	policy        policy.Policy
	fs            afero.Fs
}

// NewConftestEvaluator returns initialized conftestEvaluator implementing
// Evaluator interface
func NewConftestEvaluator(ctx context.Context, fs afero.Fs, policySources []source.PolicySource, p policy.Policy) (Evaluator, error) {
	c := conftestEvaluator{
		policySources: policySources,
		outputFormat:  "json",
		policy:        p,
		fs:            fs,
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

	if err := c.createDataDirectory(ctx, fs); err != nil {
		return nil, err
	}

	log.Debug("Conftest test runner created")
	return c, nil
}

// Destroy removes the working directory
func (c conftestEvaluator) Destroy() {
	if os.Getenv("EC_DEBUG") == "" {
		_ = c.fs.RemoveAll(c.workDir)
	}
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
			Data:          []string{c.dataDir},
			Policy:        []string{c.policyDir},
			AllNamespaces: true,
			NoFail:        true,
			Output:        c.outputFormat,
		}
	}

	log.Debugf("runner: %#v", r)
	log.Debugf("inputs: %#v", inputs)
	runResults, err := r.Run(ctx, inputs)
	if err != nil {
		// TODO do we want to evaluate further policies instead of erroring out?
		return nil, err
	}

	effectiveTime := c.policy.EffectiveTime()

	for i, result := range runResults {
		warnings := []output.Result{}
		failures := []output.Result{}

		for _, warning := range result.Warnings {
			if !c.isResultIncluded(warning) {
				log.Debugf("Skipping result warning: %#v", warning)
				continue
			}
			warnings = append(warnings, warning)
		}

		for _, failure := range result.Failures {
			if !c.isResultIncluded(failure) {
				log.Debugf("Skipping result failure: %#v", failure)
				continue
			}
			if !isResultEffective(failure, effectiveTime) {
				// TODO: Instead of moving to warnings, create new attribute: "futureViolations"
				warnings = append(warnings, failure)
			} else {
				failures = append(failures, failure)
			}
		}

		result.Warnings = warnings
		result.Failures = failures

		runResults[i] = result
	}

	results = append(results, runResults...)

	// Evaluate total successes, warnings, and failures. If all are 0, then
	// we have effectively failed, because no tests were actually ran due to
	// input error, etc.
	var total int

	for _, res := range results {
		total += res.Successes
		total += len(res.Warnings)
		total += len(res.Failures)
	}
	if total == 0 {
		log.Error("no successes, warnings, or failures, check input")
		return nil, fmt.Errorf("no successes, warnings, or failures, check input")
	}
	return results, nil
}

// createConfigJSON creates the config.json file with the provided configuration
// in the data directory
func createConfigJSON(ctx context.Context, fs afero.Fs, dataDir string, p policy.Policy) error {
	if p == nil {
		return nil
	}

	configFilePath := filepath.Join(dataDir, "config.json")

	var config = map[string]interface{}{
		"config": map[string]interface{}{},
	}

	type policyConfig struct {
		// TODO: NonBlocking and Exclude should eventually not be propagated to the
		// policy config. However, some policy rules, i.e. release.test, have custom
		// logic to exclude certain failures. Also, NonBlocking is deprecated and
		// should be removed soon.
		NonBlocking *[]string `json:"non_blocking_checks,omitempty"`
		Exclude     *[]string `json:"exclude,omitempty"`
		// TODO: Do not propagate Include and Collections once ec-policies start
		// emitting collections metadata.
		Include     *[]string `json:"include,omitempty"`
		Collections *[]string `json:"collections,omitempty"`
		WhenNs      int64     `json:"when_ns"`
	}
	pc := &policyConfig{}

	// TODO: Once the NonBlocking field has been removed, update to dump the spec.Config into an updated policyConfig struct
	if p.Spec().Exceptions != nil {
		log.Debug("Non-blocking exceptions found. These will be written to file ", dataDir)
		pc.NonBlocking = &p.Spec().Exceptions.NonBlocking
	}

	cfg := p.Spec().Configuration
	if cfg != nil {
		log.Debug("Include rules found. These will be written to file ", dataDir)
		if cfg.Include != nil {
			pc.Include = &cfg.Include
		}
		log.Debug("Exclude rules found. These will be written to file ", dataDir)
		if cfg.Exclude != nil {
			pc.Exclude = &cfg.Exclude
		}
		log.Debug("Collections found. These will be written to file ", dataDir)
		if cfg.Collections != nil {
			pc.Collections = &cfg.Collections
		}
	}

	// Now that the future deny logic is handled in the ec-cli and not in rego,
	// this field is used only for the checking the effective times in the
	// acceptable bundles list. Always set it, even when we are using the current
	// time, so that a consistent current time is used everywhere.
	pc.WhenNs = p.EffectiveTime().UnixNano()

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
func (c *conftestEvaluator) createDataDirectory(ctx context.Context, fs afero.Fs) error {
	dataDir := c.dataDir
	exists, err := afero.DirExists(fs, dataDir)
	if err != nil {
		return err
	}
	if !exists {
		log.Debugf("Data dir '%s' does not exist, will create.", dataDir)
		_ = fs.MkdirAll(dataDir, 0755)
	}

	if err := createConfigJSON(ctx, fs, dataDir, c.policy); err != nil {
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

// isResultIncluded returns whether or not the result should be included or
// discarded based on the policy configuration.
func (c conftestEvaluator) isResultIncluded(result output.Result) bool {
	ruleMatchers := makeMatchers(result)
	collectionMatchers := extractCollections(result)
	var includes, excludes, collections []string

	spec := c.policy.Spec()
	cfg := spec.Configuration
	if cfg != nil {
		if len(cfg.Collections) > 0 {
			collections = cfg.Collections
		}
		if len(cfg.Include) > 0 {
			includes = cfg.Include
		}
		if len(cfg.Exclude) > 0 {
			excludes = cfg.Exclude
		}
	}

	if spec.Exceptions != nil {
		// TODO: NonBlocking is deprecated. Remove it eventually
		excludes = append(excludes, spec.Exceptions.NonBlocking...)
	}

	if len(includes)+len(collections) == 0 {
		includes = []string{"*"}
	}

	isIncluded := hasAnyMatch(collectionMatchers, collections) || hasAnyMatch(ruleMatchers, includes)
	isExcluded := hasAnyMatch(ruleMatchers, excludes)
	return isIncluded && !isExcluded
}

// hasAnyMatch returns true if the haystack contains any of the needles.
func hasAnyMatch(needles, haystack []string) bool {
	for _, needle := range needles {
		if slices.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// makeMatchers returns the possible matching strings for the result.
func makeMatchers(result output.Result) []string {
	code := extractStringFromMetadata(result, "code")
	term := extractStringFromMetadata(result, "term")
	parts := strings.Split(code, ".")
	var pkg string
	if len(parts) >= 2 {
		pkg = parts[len(parts)-2]
	}
	rule := parts[len(parts)-1]

	var matchers []string

	if pkg != "" {
		matchers = append(matchers, pkg, fmt.Sprintf("%s.*", pkg), fmt.Sprintf("%s.%s", pkg, rule))
	}

	// A term can be applied to any of the package matchers above.
	if term != "" {
		for i, l := 0, len(matchers); i < l; i++ {
			matchers = append(matchers, fmt.Sprintf("%s:%s", matchers[i], term))
		}
	}

	matchers = append(matchers, "*")

	return matchers
}

// extractCollections returns the collections encoded in the result metadata.
func extractCollections(result output.Result) []string {
	var collections []string
	if maybeInterfaces, exists := result.Metadata["collections"]; exists {
		if interfaces, ok := maybeInterfaces.([]interface{}); ok {
			for _, maybeCollection := range interfaces {
				if collection, ok := maybeCollection.(string); ok {
					collections = append(collections, collection)
				}
			}
		}
	}
	return collections
}

// extractStringFromMetadata returns the string value from the result metadata at the given key.
func extractStringFromMetadata(result output.Result, key string) string {
	if maybeValue, exists := result.Metadata[key]; exists {
		if value, ok := maybeValue.(string); ok {
			return value
		}
	}
	return ""
}
