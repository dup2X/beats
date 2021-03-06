// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build linux,386 linux,amd64

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/joeshaw/multierror"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/x-pack/auditbeat/module/system/socket/dns"
	"github.com/elastic/beats/x-pack/auditbeat/tracing"
)

type logWrapper testing.T

func (l *logWrapper) Errorf(format string, args ...interface{}) {
	l.Logf("error: "+format, args)
}

func (l *logWrapper) Warnf(format string, args ...interface{}) {
	l.Logf("warning: "+format, args)
}

func (l *logWrapper) Infof(format string, args ...interface{}) {
	l.Logf("info: "+format, args)
}

func (l *logWrapper) Debugf(format string, args ...interface{}) {
	l.Logf("debug: "+format, args)
}

func TestTCPConnWithProcess(t *testing.T) {
	const (
		localIP            = "192.168.33.10"
		remoteIP           = "172.19.12.13"
		localPort          = 38842
		remotePort         = 443
		sock       uintptr = 0xff1234
	)
	st := makeState(nil, (*logWrapper)(t), time.Second, 0, time.Second)
	lPort, rPort := be16(localPort), be16(remotePort)
	lAddr, rAddr := ipv4(localIP), ipv4(remoteIP)
	evs := []event{
		callExecve(meta(1234, 1234, 1), []string{"/usr/bin/curl", "https://example.net/", "-o", "/tmp/site.html"}),
		&commitCreds{Meta: meta(1234, 1234, 2), UID: 501, GID: 20, EUID: 501, EGID: 20},
		&execveRet{Meta: meta(1234, 1234, 2), Retval: 1234},
		&inetCreate{Meta: meta(1234, 1235, 5), Proto: 0},
		&sockInitData{Meta: meta(1234, 1235, 5), Sock: sock},
		&tcpIPv4ConnectCall{Meta: meta(1234, 1235, 8), Sock: sock, RAddr: rAddr, RPort: rPort},
		&ipLocalOutCall{
			Meta:  meta(1234, 1235, 8),
			Sock:  sock,
			Size:  20,
			LAddr: lAddr,
			LPort: lPort,
			RAddr: rAddr,
			RPort: rPort,
		},
		&tcpConnectResult{Meta: meta(1234, 1235, 9), Retval: 0},
		&tcpV4DoRcv{
			Meta:  meta(0, 0, 12),
			Sock:  sock,
			Size:  12,
			LAddr: lAddr,
			LPort: lPort,
			RAddr: rAddr,
			RPort: rPort,
		},
		&inetReleaseCall{Meta: meta(0, 0, 15), Sock: sock},
		&tcpV4DoRcv{
			Meta:  meta(0, 0, 17),
			Sock:  sock,
			Size:  7,
			LAddr: lAddr,
			LPort: lPort,
			RAddr: rAddr,
			RPort: rPort,
		},
		&doExit{Meta: meta(1234, 1234, 18)},
	}
	if err := feedEvents(evs, st, t); err != nil {
		t.Fatal(err)
	}
	st.ExpireOlder()
	flows, err := getFlows(st.DoneFlows(), all)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, flows, 1)
	flow := flows[0]
	t.Log("read flow", flow)
	for field, expected := range map[string]interface{}{
		"source.ip":           localIP,
		"source.port":         localPort,
		"source.packets":      uint64(1),
		"source.bytes":        uint64(20),
		"client.ip":           localIP,
		"client.port":         localPort,
		"destination.ip":      remoteIP,
		"destination.port":    remotePort,
		"destination.packets": uint64(2),
		"destination.bytes":   uint64(19),
		"server.ip":           remoteIP,
		"server.port":         remotePort,
		"network.direction":   "outbound",
		"network.transport":   "tcp",
		"network.type":        "ipv4",
		"process.pid":         1234,
		"process.name":        "curl",
		"user.id":             "501",
	} {
		if !assertValue(t, flow, expected, field) {
			t.Fatal("expected value not found")
		}
	}
}

func assertValue(t *testing.T, ev beat.Event, expected interface{}, field string) bool {
	value, err := ev.GetValue(field)
	if err != nil {
		t.Fatal(err, "field", field)
	}
	return assert.Equal(t, expected, value)
}

func be16(val uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], val)
	return tracing.MachineEndian.Uint16(buf[:])
}

func be32(val uint32) uint32 {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], val)
	return tracing.MachineEndian.Uint32(buf[:])
}

func be64(val uint64) uint64 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	return tracing.MachineEndian.Uint64(buf[:])
}

func ipv4(ip string) uint32 {
	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		panic("bad ip")
	}
	return tracing.MachineEndian.Uint32(netIP)
}

func feedEvents(evs []event, st *state, t *testing.T) error {
	for idx, ev := range evs {
		t.Logf("Delivering event %d: %s", idx, ev.String())
		// TODO: err
		if err := ev.Update(st); err != nil {
			return errors.Wrapf(err, "error feeding event '%s'", ev.String())
		}
	}
	return nil
}

func all(*flow) bool {
	return true
}

type noDNSResolution struct{}

func (noDNSResolution) ResolveIP(pid uint32, ip net.IP) (domain string, found bool) {
	return "", false
}

func getFlows(list linkedList, filter func(*flow) bool) (evs []beat.Event, err error) {
	var errs multierror.Errors
	for elem := list.get(); elem != nil; elem = list.get() {
		flow, ok := elem.(*flow)
		if !ok || !flow.isValid() {
			errs = append(errs, errors.New("invalid flow"))
			continue
		}
		if !filter(flow) {
			continue
		}
		ev, err := flow.toEvent(true)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		evs = append(evs, ev.BeatEvent(moduleName, metricsetName))
	}
	return evs, errs.Err()
}

func callExecve(meta tracing.Metadata, args []string) *execveCall {
	ptr := &execveCall{
		Meta: meta,
	}
	lim := len(args)
	if lim > maxProgArgs {
		lim = maxProgArgs
	}
	for i := 0; i < lim; i++ {
		ptr.Ptrs[i] = 1
	}
	if lim < len(args) {
		ptr.Ptrs[lim] = 1
	}
	switch lim {
	case 5:
		copyCString(ptr.Param4[:], []byte(args[4]))
		fallthrough
	case 4:
		copyCString(ptr.Param3[:], []byte(args[3]))
		fallthrough
	case 3:
		copyCString(ptr.Param2[:], []byte(args[2]))
		fallthrough
	case 2:
		copyCString(ptr.Param1[:], []byte(args[1]))
		fallthrough
	case 1:
		copyCString(ptr.Param0[:], []byte(args[0]))
	case 0:
		return nil
	}
	ptr.Path = ptr.Param0
	return ptr
}

func meta(pid uint32, tid uint32, timestamp uint64) tracing.Metadata {
	return tracing.Metadata{
		Timestamp: timestamp,
		TID:       tid,
		PID:       pid,
	}
}

func copyCString(dst []byte, src []byte) {
	copy(dst, src)
	if len(src) < len(dst) {
		dst[len(src)] = 0
	} else {
		dst[len(dst)-1] = 0
	}
}

type dnsTestCase struct {
	found      bool
	proc       *process
	ip, domain string
}

type dnsTestCases []dnsTestCase

func (c dnsTestCases) Run(t *testing.T) {
	for idx, test := range c {
		msg := fmt.Sprintf("test entry #%d : %+v", idx, test)
		domain, found := test.proc.ResolveIP(net.ParseIP(test.ip))
		assert.Equal(t, test.found, found, msg)
		assert.Equal(t, test.domain, domain, msg)
	}
}

func TestDNSTracker(t *testing.T) {
	const infiniteExpiration = time.Hour * 3
	local1 := net.UDPAddr{IP: net.ParseIP("192.168.0.2"), Port: 55555}
	local2 := net.UDPAddr{IP: net.ParseIP("192.168.0.2"), Port: 55556}
	trV4 := dns.Transaction{
		TXID:      1234,
		Client:    local1,
		Server:    net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		Domain:    "example.net",
		Addresses: []net.IP{net.ParseIP("192.0.2.12"), net.ParseIP("192.0.2.13")},
	}
	trV6 := dns.Transaction{
		TXID:      1235,
		Client:    local2,
		Server:    net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		Domain:    "example.com",
		Addresses: []net.IP{net.ParseIP("2001:db8::1111"), net.ParseIP("2001:db8::2222")},
	}
	t.Run("transaction before register", func(t *testing.T) {
		proc1 := &process{pid: 123}
		proc2 := &process{pid: 124}
		tracker := newDNSTracker(infiniteExpiration)
		tracker.AddTransaction(trV4)
		tracker.AddTransaction(trV6)
		tracker.RegisterEndpoint(local1, proc1)
		tracker.RegisterEndpoint(local2, proc1)
		dnsTestCases{
			{true, proc1, "192.0.2.12", "example.net"},
			{true, proc1, "192.0.2.13", "example.net"},
			{true, proc1, "2001:db8::1111", "example.com"},
			{true, proc1, "2001:db8::2222", "example.com"},
			{false, proc2, "192.0.2.12", ""},
			{false, proc2, "2001:db8::2222", ""},
			{false, proc1, "192.168.0.2", ""},
			{false, proc1, "2001:db8::3333", ""},
		}.Run(t)
	})
	t.Run("transaction after register", func(t *testing.T) {
		proc1 := &process{pid: 123}
		proc2 := &process{pid: 124}
		tracker := newDNSTracker(infiniteExpiration)
		tracker.RegisterEndpoint(local1, proc1)
		tracker.RegisterEndpoint(local2, proc1)
		tracker.AddTransaction(trV4)
		tracker.AddTransaction(trV6)
		dnsTestCases{
			{true, proc1, "192.0.2.12", "example.net"},
			{true, proc1, "192.0.2.13", "example.net"},
			{true, proc1, "2001:db8::1111", "example.com"},
			{true, proc1, "2001:db8::2222", "example.com"},
			{false, proc2, "192.0.2.12", ""},
			{false, proc2, "2001:db8::2222", ""},
			{false, proc1, "192.168.0.2", ""},
			{false, proc1, "2001:db8::3333", ""},
		}.Run(t)
	})
	t.Run("unknown local endpoint", func(t *testing.T) {
		proc1 := &process{pid: 123}
		proc2 := &process{pid: 124}
		tracker := newDNSTracker(infiniteExpiration)
		tracker.RegisterEndpoint(local1, proc1)
		tracker.AddTransaction(trV4)
		tracker.AddTransaction(trV6)
		dnsTestCases{
			{true, proc1, "192.0.2.12", "example.net"},
			{true, proc1, "192.0.2.13", "example.net"},
			{false, proc1, "2001:db8::1111", ""},
			{false, proc1, "2001:db8::2222", ""},
			{false, proc2, "192.0.2.12", ""},
			{false, proc2, "2001:db8::2222", ""},
			{false, proc1, "192.168.0.2", ""},
			{false, proc1, "2001:db8::3333", ""},
		}.Run(t)
	})
	t.Run("expiration", func(t *testing.T) {
		proc1 := &process{pid: 123}
		tracker := newDNSTracker(10 * time.Millisecond)
		tracker.AddTransaction(trV4)
		tracker.AddTransaction(trV6)
		time.Sleep(time.Millisecond * 50)
		tracker.RegisterEndpoint(local1, proc1)
		tracker.RegisterEndpoint(local2, proc1)
		dnsTestCases{
			{false, proc1, "192.0.2.12", ""},
			{false, proc1, "192.0.2.13", ""},
			{false, proc1, "2001:db8::1111", ""},
			{false, proc1, "2001:db8::2222", ""},
		}.Run(t)
	})
	t.Run("same IP different domains", func(t *testing.T) {
		proc1 := &process{pid: 123}
		proc2 := &process{pid: 124}
		trV4alt := dns.Transaction{
			TXID:      1234,
			Client:    local2,
			Server:    net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
			Domain:    "example.com",
			Addresses: []net.IP{net.ParseIP("192.0.2.12"), net.ParseIP("192.0.2.13")},
		}
		tracker := newDNSTracker(infiniteExpiration)
		tracker.AddTransaction(trV4)
		tracker.AddTransaction(trV4alt)
		tracker.RegisterEndpoint(local1, proc1)
		tracker.RegisterEndpoint(local2, proc2)
		dnsTestCases{
			{true, proc1, "192.0.2.12", "example.net"},
			{true, proc2, "192.0.2.12", "example.com"},
		}.Run(t)
	})
}
