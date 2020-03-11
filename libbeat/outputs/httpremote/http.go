// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package httpremote

import (
	"bytes"
	"net/http"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/outputs"
	"github.com/elastic/beats/libbeat/outputs/codec"
	"github.com/elastic/beats/libbeat/publisher"
)

func init() {
	outputs.RegisterType("httpremote", makeHTTPRemote)
}

type httpRemote struct {
	beat     beat.Info
	observer outputs.Observer
	codec    codec.Codec
	uri      string
}

// makeHTTPRemote instantiates a new file output instance.
func makeHTTPRemote(
	_ outputs.IndexManager,
	beat beat.Info,
	observer outputs.Observer,
	cfg *common.Config,
) (outputs.Group, error) {
	config := defaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return outputs.Fail(err)
	}

	// disable bulk support in publisher pipeline
	cfg.SetInt("bulk_max_size", -1, -1)

	fo := &httpRemote{
		beat:     beat,
		observer: observer,
	}
	if err := fo.init(beat, config); err != nil {
		return outputs.Fail(err)
	}

	return outputs.Success(-1, 0, fo)
}

func (out *httpRemote) init(beat beat.Info, c config) error {
	var err error
	out.uri = c.URL
	out.codec, err = codec.CreateEncoder(beat, c.Codec)
	if err != nil {
		return err
	}
	return nil
}

// Implement Outputer
func (out *httpRemote) Close() error {
	return nil
}

func (out *httpRemote) Publish(
	batch publisher.Batch,
) error {
	defer batch.ACK()

	st := out.observer
	events := batch.Events()
	st.NewBatch(len(events))
	cli := &http.Client{}
	dropped := 0
	for i := range events {
		event := &events[i]

		serializedEvent, err := out.codec.Encode(out.beat.Beat, &event.Content)
		if err != nil {
			if event.Guaranteed() {
				logp.Critical("Failed to serialize the event: %v", err)
			} else {
				logp.Warn("Failed to serialize the event: %v", err)
			}
			logp.Debug("file", "Failed event: %v", event)

			dropped++
			continue
		}

		req, err := http.NewRequest("POST", out.uri, bytes.NewBuffer(serializedEvent))
		if err != nil {
			if event.Guaranteed() {
				logp.Critical("Failed to init the httpRemote request: %v", err)
			} else {
				logp.Warn("Failed to serialize the httpRemote request: %v", err)
			}
			logp.Debug("httpremote", "Failed event: %v", event)

			dropped++
			continue
		}
		if _, err = cli.Do(req); err != nil {
			st.WriteError(err)

			if event.Guaranteed() {
				logp.Critical("Sending event to httpRemote failed with: %v", err)
			} else {
				logp.Warn("Sending event to httpRemote failed with: %v", err)
			}

			dropped++
			continue
		}

		st.WriteBytes(len(serializedEvent) + 1)
	}

	st.Dropped(dropped)
	st.Acked(len(events) - dropped)

	return nil
}

func (out *httpRemote) String() string {
	return "httpremote(" + out.uri + ")"
}
