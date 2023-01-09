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

package tracker

import (
	"bytes"
	"context"
	"time"

	"github.com/ghodss/yaml"
	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/stuart-warren/yamlfmt"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/hacbs-contract/ec-cli/internal/image"
)

const (
	pipelineCollection = "pipeline-bundles"
	taskCollection     = "task-bundles"
)

type bundleRecord struct {
	Digest      string    `json:"digest"`
	EffectiveOn time.Time `json:"effective_on"`
	Tag         string    `json:"tag"`
	Repository  string    `json:"-"`
	Collection  string    `json:"-"`
}

type commonTasksRecord struct {
	Tasks       []string  `json:"tasks"`
	EffectiveOn time.Time `json:"effective_on"`
}

func (r *commonTasksRecord) updateTasksIntersection(newTasks sets.Set[string]) {
	if len(r.Tasks) == 0 {
		r.Tasks = sets.List(newTasks)
	} else if newTasks.Len() > 0 {
		existingTasks := sets.New(r.Tasks...)
		r.Tasks = sets.List(existingTasks.Intersection(newTasks))
	}
}

type Tracker struct {
	PipelineBundles map[string][]bundleRecord `json:"pipeline-bundles,omitempty"`
	TaskBundles     map[string][]bundleRecord `json:"task-bundles,omitempty"`
	RequiredTasks   []commonTasksRecord       `json:"required-tasks,omitempty"`
}

// newTracker returns a new initialized instance of Tracker. If path
// is "", an empty instance is returned.
func newTracker(fs afero.Fs, path string) (t Tracker, err error) {
	if path != "" {
		var contents []byte
		contents, err = afero.ReadFile(fs, path)
		if err != nil {
			return
		}
		err = yaml.Unmarshal(contents, &t)
		if err != nil {
			return
		}
	} else {
		t = Tracker{}
	}

	t.setDefaults()
	return
}

// setDefaults initializes the required nested attributes.
func (t *Tracker) setDefaults() {
	if t.PipelineBundles == nil {
		t.PipelineBundles = map[string][]bundleRecord{}
	}
	if t.TaskBundles == nil {
		t.TaskBundles = map[string][]bundleRecord{}
	}
}

// addBundleRecord includes the given bundle record to the tracker.
func (t *Tracker) addBundleRecord(record bundleRecord) {
	var collection map[string][]bundleRecord
	switch record.Collection {
	case pipelineCollection:
		collection = t.PipelineBundles
	case taskCollection:
		collection = t.TaskBundles
	default:
		log.Warnf("Ignoring record with unexpected collection: %#v", record)
		return
	}

	newRecords := []bundleRecord{record}
	if _, ok := collection[record.Repository]; !ok {
		collection[record.Repository] = newRecords
	} else {
		collection[record.Repository] = append(newRecords, collection[record.Repository]...)
	}
}

// addRequiredTasksRecord includes the given tasks record to the tracker as required tasks.
// If the most recent entry contains the same set of tasks, no action is taken.
func (t *Tracker) addRequiredTasksRecord(record commonTasksRecord) {
	if len(t.RequiredTasks) > 0 {
		existingTasks := sets.NewString(t.RequiredTasks[0].Tasks...)
		if existingTasks.Equal(sets.NewString(record.Tasks...)) {
			return
		}
	}
	t.RequiredTasks = append([]commonTasksRecord{record}, t.RequiredTasks...)
}

// Output serializes the Tracker state as YAML
func (t Tracker) Output() ([]byte, error) {
	out, err := yaml.Marshal(t)
	if err != nil {
		return nil, err
	}

	// sorts the YAML document making it deterministic
	return yamlfmt.Format(bytes.NewBuffer(out))
}

// Track implements the common workflow of loading an existing tracker file and adding
// records to one of its collections.
// Each url is expected to reference a valid Tekton bundle. Each bundle may be added
// to none, 1, or 2 collections depending on the Tekton resource types they include.
func Track(ctx context.Context, fs afero.Fs, urls []string, input string, prune bool) ([]byte, error) {
	refs, err := image.ParseAndResolveAll(urls, name.StrictValidation)
	if err != nil {
		return nil, err
	}

	t, err := newTracker(fs, input)
	if err != nil {
		return nil, err
	}

	effective_on := effectiveOn()
	requiredTasks := commonTasksRecord{EffectiveOn: effective_on}
	for _, ref := range refs {
		info, err := newBundleInfo(ctx, ref, requiredTasks)
		if err != nil {
			return nil, err
		}

		for _, collection := range sets.List(info.collections) {
			t.addBundleRecord(bundleRecord{
				Digest:      ref.Digest,
				Tag:         ref.Tag,
				EffectiveOn: effective_on,
				Repository:  ref.Repository,
				Collection:  collection,
			})
		}
		requiredTasks = info.commonPipelineTasks

	}
	t.addRequiredTasksRecord(requiredTasks)

	t.filterBundles(prune)
	t.filterRequiredTasks(prune)

	return t.Output()
}

// effectiveOn returns an RFC3339 representation of the beginning of the
// closest day 30 days into the future. 30 is a best guess number. In the
// future, this may have to be configurable.
func effectiveOn() time.Time {
	day := time.Hour * 24
	duration := day * 30
	// Round to the 0 time of the day for consistency. Also, zero out nanoseconds
	// to avoid RFC3339Nano from being used by MarshalJSON.
	return time.Now().Add(duration).UTC().Round(day)
}

// filterBundles applies filterRecords to PipelienBundles and TaskBundles.
func (t *Tracker) filterBundles(prune bool) {
	for ref, records := range t.PipelineBundles {
		t.PipelineBundles[ref] = filterRecords(records, prune)
	}
	for ref, records := range t.TaskBundles {
		t.TaskBundles[ref] = filterRecords(records, prune)
	}
}

// filterRecords reduces the list of records by removing superfulous entries.
// It removes records that have the same Repository and Digest. If prune is
// true, it skips any record that is no longer acceptable. Any record with an
// EffectiveOn date in the future, and the record with the most recent
// EffectiveOn date *not* in the future are considered acceptable.
func filterRecords(records []bundleRecord, prune bool) []bundleRecord {
	now := time.Now().UTC()

	unique := make([]bundleRecord, 0, len(records))
	keys := map[string]bool{}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		// NOTE: Newly added records will have a repository, but existing ones
		// will not. This is expected because the output does not persist the
		// repository for each record. Instead, the repository is the attribute
		// which references the list of records.
		key := r.Digest
		if _, ok := keys[key]; ok {
			continue
		}
		keys[key] = true
		unique = append([]bundleRecord{r}, unique...)
	}

	relevant := make([]bundleRecord, 0, len(unique))
	for _, r := range unique {
		relevant = append(relevant, r)
		if prune && now.After(r.EffectiveOn) {
			break
		}
	}

	return relevant
}

// filterRequiredTasks reduces the list of required tasks by removing superfulous
// entries. If prune is true, it skips any entry that is no longer acceptable.
// Any entry with an EffectiveOn date in the future, and the entry with the most
// recent EffectiveOn date *not* in the future are considered acceptable.
func (t *Tracker) filterRequiredTasks(prune bool) {
	if !prune {
		return
	}
	now := time.Now().UTC()

	filtered := make([]commonTasksRecord, 0, len(t.RequiredTasks))
	for _, r := range t.RequiredTasks {
		filtered = append(filtered, r)
		if now.After(r.EffectiveOn) {
			break
		}
	}
	t.RequiredTasks = filtered
}
