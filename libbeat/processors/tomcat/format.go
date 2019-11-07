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

package tomcat

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/processors"
	jsprocessor "github.com/elastic/beats/libbeat/processors/script/javascript/module/processor"
)

const logName = "processor.tomcat"

func init() {
	processors.RegisterPlugin("tomcat", New)
	jsprocessor.RegisterPlugin("tomcat", New)
}

type processor struct {
	config
	log *logp.Logger
}

// New constructs a new convert processor.
func New(cfg *common.Config) (processors.Processor, error) {
	c := defaultConfig()
	if err := cfg.Unpack(&c); err != nil {
		return nil, errors.Wrap(err, "fail to unpack the convert processor configuration")
	}

	return newConvert(c)
}

func newConvert(c config) (*processor, error) {
	log := logp.NewLogger(logName)
	if c.Tag != "" {
		log = log.With("instance_id", c.Tag)
	}

	return &processor{config: c, log: log}, nil
}

func (p *processor) String() string {
	json, _ := json.Marshal(p.config)
	return "convert=" + string(json)
}

func (p *processor) Run(event *beat.Event) (*beat.Event, error) {
	msgSrc, _ := event.Fields.GetValue("message")
	msg, _ := msgSrc.(string)
	t, vv := formatTomcat(msg)
	for k, v := range vv {
		event.Fields.Put(k, v)
	}
	if len(vv) > 0 {
		event.Fields.Delete("message")
		event.Timestamp = ts
	}
	return event, nil
}

func formatTomcat(msg string) (ts time.Time, data map[string]string) {
	data = make(map[string]string)
	msg = strings.ReplaceAll(msg, "  ", " ")
	ss := strings.SplitN(msg, " ", -1)
	if len(ss) <= 10 {
		return time.Now(), data
	}
	data["client_ip"] = ss[0]
	ts, _ = time.ParseInLocation("02/Jan/2006:13:04:05", ss[3][1:], time.Local)
	data["timestamp"] = t.Unix()
	u, _ := url.Parse(ss[6])
	data["url"] = u.Path
	data["http_status"] = ss[8]
	data["elapsed"] = ss[10]
	return data
}
