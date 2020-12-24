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
	"fmt"
	"strings"

	"github.com/elastic/beats/libbeat/outputs/codec"
)

type config struct {
	URL   string       `config:"url"`
	Codec codec.Config `config:"codec"`
	Token string       `json:"token"`
	Topic string       `json:"topic"`
}

var (
	defaultConfig = config{URL: "http://127.0.0.1/ss"}
)

func (c *config) Validate() error {
	if !strings.HasPrefix(c.URL, "http") && !strings.HasPrefix(c.URL, "https") {
		return fmt.Errorf("bad url:%s", c.URL)
	}
	return nil
}
