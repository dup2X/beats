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

package selfformat

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
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

const logName = "processor.selfformat"

func init() {
	processors.RegisterPlugin("selfformat", New)
	jsprocessor.RegisterPlugin("Selfformat", New)
}

const (
	FormatAPI         = "api"
	FormatNginx       = "nginx"
	FormatTomcat      = "tomcat"
	FormatJavaOld     = "java_old"
	FormatFrontFedOld = "fed_old_log"
	FormatFrontFed    = "fed_log"
	FormatPHPLog      = "php_normal"
	FormatAPIV2       = "api_v2"
	FormatEventB      = "event_b"
)

type processor struct {
	config
	log  *logp.Logger
	keys map[string]bool
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
	tags, err := event.Fields.GetValue("tags")
	if err != nil {
		return event, nil
	}
	tagList, ok := tags.([]string)
	if !ok {
		return event, nil
	}
	var tag string
	for _, t := range tagList {
		switch t {
		case FormatAPI, FormatNginx, FormatTomcat, FormatFrontFedOld, FormatPHPLog, FormatFrontFed, FormatAPIV2, FormatEventB:
			tag = t
			break
		}
	}
	msgSrc, _ := event.Fields.GetValue("message")
	msg, _ := msgSrc.(string)
	switch tag {
	case FormatAPI:
		event.Fields.Put("tag", tag)
		header, logTag, vv := formatAPI(msg)
		event.Fields.Put("log_tag", logTag)
		for k, v := range vv {
			event.Fields.Put(k, v)
		}
		if len(vv) > 0 {
			event.Fields.Delete("message")
		}
		if header != "" {
			lindex := strings.Index(header, "]")
			if lindex < len(header) && lindex > 0 {
				tinfo := header[1:lindex]
				header = header[lindex+1:]
				lindex = strings.LastIndex(tinfo, " ")
				ms, _ := strconv.ParseInt(tinfo[lindex:], 10, 64)
				t, err := time.ParseInLocation("2006/01/02 15:04:05", tinfo[:lindex], time.Local)
				if err != nil {
					return event, nil
				}
				t.Add(time.Duration(ms) * time.Millisecond)
				event.Timestamp = t
			}
		}
		event.Fields.Put("header", header)
	case FormatJavaOld:
		event.Fields.Put("tag", tag)
		level, t := formatJavaOld(msg)
		event.Timestamp = t
		event.Fields.Put("level", level)
	case FormatNginx:
		event.Fields.Put("tag", tag)
		t, vv := formatNginx(msg)
		for k, v := range vv {
			event.Fields.Put(k, v)
		}
		if len(vv) > 0 {
			event.Fields.Delete("message")
			event.Timestamp = t
		}
	case FormatTomcat:
		event.Fields.Put("tag", tag)
		t, vv := formatTomcat(msg)
		for k, v := range vv {
			event.Fields.Put(k, v)
		}
		if len(vv) > 0 {
			event.Fields.Delete("message")
			event.Timestamp = t
		}
	case FormatFrontFedOld:
		event.Fields.Put("tag", tag)
		ext, t := formatFrontFedOld(msg)
		for k, v := range ext {
			event.Fields.Put(k, v)
		}
		if len(ext) > 0 {
			event.Fields.Delete("message")
		}
		event.Timestamp = t
	case FormatFrontFed:
		event.Fields.Put("tag", tag)
		ext, t := formatFedLog(msg)
		for k, v := range ext {
			if k != "timestamp" {
				event.Fields.Put(k, v)
			}
		}
		event.Fields.Put("timestamp", t)
		event.Fields.Put("row_timestamp", t)
		event.Fields.Put("row_uuid", fmt.Sprintf("%x", md5.Sum([]byte(msg))))
		//event.Timestamp = t
		if len(ext) > 0 {
			event.Fields.Delete("message")
		}
	case FormatPHPLog:
		event.Fields.Put("tag", tag)
		kv, t := formatPHPNormalLog(msg)
		event.Fields.Put("kvs", len(kv))
		for k, v := range kv {
			event.Fields.Put(k, v)
		}
		event.Timestamp = t
	case FormatAPIV2:
		event.Fields.Put("tag", tag)
		kv, t := FormatAPINormalLog(msg)
		for k, v := range kv {
			event.Fields.Put(k, v)
		}
		event.Timestamp = t
	case FormatEventB:
		event.Fields.Put("tag", tag)
		kv, t := FormatEventBVersion(msg)
		for k, v := range kv {
			event.Fields.Put(k, v)
		}
		event.Timestamp = t
	}
	return event, nil
}

func formatAPI(msg string) (header string, logTag string, data map[string]string) {
	index := strings.Index(msg, "] ")
	data = make(map[string]string)
	if index > 0 && index < len(msg) {
		header = msg[:index]
		index1 := strings.Index(msg, "||")
		logTag = msg[index+2 : index1]
		ks := strings.Split(msg[index1+2:], "||")
		for _, kk := range ks {
			sec := strings.Split(kk, "=")
			if len(sec) == 2 {
				data[sec[0]] = sec[1]
			}
		}
	}
	return
}

func formatNginx(msg string) (ts time.Time, data map[string]string) {
	data = make(map[string]string)
	msg = strings.ReplaceAll(msg, "  ", " ")
	ss := strings.SplitN(msg, " ", -1)
	if len(ss) <= 10 {
		return time.Now(), data
	}
	data["client_ip"] = ss[0]
	ts, _ = time.ParseInLocation("02/Jan/2006:15:04:05", ss[3][1:], time.Local)
	data["timestamp"] = fmt.Sprint(ts.Unix())
	u, _ := url.Parse(ss[6])
	data["url"] = u.Path
	data["http_status"] = ss[8]
	//data["elapsed"] = ss[10]
	return ts, data
}

func formatTomcat(msg string) (ts time.Time, data map[string]string) {
	data = make(map[string]string)
	msg = strings.ReplaceAll(msg, "  ", " ")
	ss := strings.SplitN(msg, " ", -1)
	if len(ss) <= 10 {
		return time.Now(), data
	}
	data["client_ip"] = ss[0]
	var err error
	ts, err = time.ParseInLocation("02/Jan/2006:15:04:05", ss[3][1:], time.Local)
	if err != nil {
		println(ss[3][1:], err.Error())
	}
	data["timestamp"] = fmt.Sprint(ts.Unix())
	u, _ := url.Parse(ss[6])
	data["url"] = u.Path
	data["http_status"] = ss[8]
	data["elapsed"] = ss[10]
	return ts, data
}

func formatJavaOld(msg string) (level string, ts time.Time) {
	msg = strings.ReplaceAll(msg, "  ", " ")
	ss := strings.SplitN(msg, " ", -1)
	level = ss[0]
	if len(ss) <= 4 {
		return "INFO", time.Now()
	}
	var err error
	ts, err = time.ParseInLocation("2006-01-02 15:04:05", ss[3][1:]+" "+ss[4][:len(ss[4])-5], time.Local)
	if err != nil {
		println(ss[3][1:], err.Error())
	}
	return level, ts
}

func formatFrontFedOld(msg string) (kv map[string]interface{}, ts time.Time) {
	msg = strings.ReplaceAll(msg, "  ", " ")
	ss := strings.SplitN(msg, " ", -1)
	if len(ss) <= 6 {
		return nil, time.Now()
	}
	var err error
	ts, err = time.Parse("02/Jan/2006:15:04:05", ss[3][1:])
	if err != nil {
		println(ss[3][1:], err.Error())
	}
	req, err := url.ParseRequestURI(ss[6])
	params := req.Query()
	ext := params.Get("extparams")
	extParams := make(map[string]interface{})
	err = json.Unmarshal([]byte(ext), &extParams)
	for k := range params {
		if k == "extparams" {
			continue
		}
		v := params.Get(k)
		extParams[k] = v
	}
	if len(ss) > 10 {
		extParams["Refer"] = ss[10]
	}
	if len(ss) > 11 {
		extParams["UA"] = strings.Join(ss[11:len(ss)-1], " ")
	}
	return extParams, ts
}

func formatPHPNormalLog(msg string) (map[string]interface{}, time.Time) {
	ret := make(map[string]interface{})
	var err error
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", msg[1:20], time.Local)
	if err != nil {
		println(msg[1:20], err.Error())
		return ret, time.Now()
	}
	headerLen := strings.Index(msg, "||")
	tagStart := strings.LastIndex(msg[:headerLen], "]")
	ltag := msg[tagStart+1 : headerLen]
	ret["ltag"] = ltag
	items := strings.Split(msg, "||")
	for i := range items {
		kv := strings.Split(items[i], "=")
		if kv != nil && len(kv) == 2 {
			if kv[1] == "" || kv[0] == "" {
				continue
			}
			fmt.Printf("%s=%s\n", kv[0], kv[1])
			ret[kv[0]] = kv[1]
		}
	}
	return ret, ts
}

func formatFedLog(msg string) (map[string]interface{}, int64) {
	ret := make(map[string]interface{})
	itemsSrc := strings.Split(msg, "||")
	if len(itemsSrc) < 2 {
		return ret, 0
	}
	items := itemsSrc[2:]
	for i := range items {
		idx := strings.Index(items[i], "=")
		if idx < 1 {
			continue
		}
		if idx+1 >= len(items[i]) {
			//	continue
		}
		var kv = make([]string, 2)
		kv[0] = items[i][:idx]
		kv[1] = items[i][idx+1:]
		//	fmt.Printf("%s=%s\n", kv[0], kv[1])
		ret[kv[0]] = kv[1]
	}
	extra := make(map[string]interface{})
	input := make(map[string]interface{})
	json.Unmarshal([]byte(fmt.Sprint(ret["url_params"])), &input)
	json.Unmarshal([]byte(fmt.Sprint(ret["extra"])), &extra)
	for k, v := range extra {
		if _, ok := ret[k]; !ok {
			ret[k] = v
		}
	}
	for k, v := range input {
		ret["input_"+k] = v
	}
	ts := time.Now().UnixNano() / 1e6
	if _, ok := ret["server_ts_ms"]; ok {
		var err error
		ts, err = strconv.ParseInt(fmt.Sprint(ret["server_ts_ms"]), 10, 64)
		if err != nil {
			fmt.Printf("timestamp==err===%v\n", err)
		}
		delete(ret, "server_ts_ms")
	}
	return ret, ts
}

func FormatAPINormalLog(msg string) (map[string]interface{}, time.Time) {
	ret := make(map[string]interface{})
	var err error
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", msg[1:20], time.Local)
	if err != nil {
		println(msg[1:20], err.Error())
		return ret, time.Now()
	}
	headerLen := strings.Index(msg, "||")
	if headerLen < 1 || len(msg) < headerLen+2 {
		return ret, ts
	}
	tagStart := strings.LastIndex(msg[:headerLen], "]")
	ltag := msg[tagStart+1 : headerLen]
	ret["ltag"] = strings.TrimSpace(ltag)
	items := strings.Split(msg, "||")
	for i := range items {
		kv := strings.Split(items[i], "=")
		if kv != nil && len(kv) == 2 {
			if kv[1] == "" || kv[0] == "" || kv[0] == "host" {
				continue
			}
			ret[kv[0]] = strings.TrimLeft(kv[1], " ")
		}
	}
	return ret, ts
}

func FormatEventBVersion(msg string) (map[string]interface{}, time.Time) {
	ret := make(map[string]interface{})
	var err error
	m, err := regexp.Compile(`\[(\d{4}-\d{2}-\d{2} \d{2}\:\d{2}\:\d{2})\.\d+\].+merchantNum = (\d+).+({.+})`)
	if err != nil {
		println(err.Error())
		return ret, time.Now()
	}
	ss1 := m.FindStringSubmatch(msg)
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", ss1[1], time.Local)
	if err != nil {
		println(ss1[1], err.Error())
		return ret, time.Now()
	}
	err = json.Unmarshal([]byte(ss1[3]), &ret)
	if err != nil {
		println(ss1[3], err.Error())
		return ret, time.Now()
	}
	ret["merchant_num"] = ss1[2]
	return ret, ts
}
