/*
 *	Copyright 2022 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2014 The Go Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	config1 "github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/suite"
	"github.com/hertz-contrib/http2/config"
	"github.com/hertz-contrib/http2/hpack"
	"golang.org/x/net/http2"
)

var stderrVerbose = flag.Bool("stderr_verbose", false, "Mirror verbosity to stderr, unbuffered")

func stderrv() io.Writer {
	if *stderrVerbose {
		return os.Stderr
	}

	return ioutil.Discard
}

type hertzServerTester struct {
	cc             net.Conn // client conn
	t              testing.TB
	fr             *Framer
	hertz          *server.Hertz
	url            string
	serverLogBuf   bytes.Buffer // logger for httptest.Server
	logFilter      []string     // substrings to filter out
	scMu           sync.Mutex   // guards sc
	sc             *serverConn
	hpackDec       *hpack.Decoder
	decodedHeaders [][2]string

	// If http2debug!=2, then we capture Frame debug logs that will be written
	// to t.Log after a test fails. The read and write logs use separate locks
	// and buffers so we don't accidentally introduce synchronization between
	// the read and write goroutines, which may hide data races.
	frameReadLogMu   sync.Mutex
	frameReadLogBuf  bytes.Buffer
	frameWriteLogMu  sync.Mutex
	frameWriteLogBuf bytes.Buffer

	// writing headers:
	headerBuf bytes.Buffer
	hpackEnc  *hpack.Encoder
}

type serverFactory struct {
	option *config.Config
}

// New is called by Hertz during engine.Run()
func (s *serverFactory) New(core suite.Core) (server protocol.Server, err error) {
	return &Server{
		BaseEngine: BaseEngine{
			Config: *s.option,
			Core:   core,
		},
	}, nil
}

func NewServerFactory(opts ...config.Option) suite.ServerFactory {
	option := config.NewConfig(opts...)
	return &serverFactory{
		option: option,
	}
}

func init() {
	testHookOnPanicMu = new(sync.Mutex)
	goAwayTimeout = 25 * time.Millisecond
}

func resetHooks() {
	testHookOnPanicMu.Lock()
	testHookOnPanic = nil
	testHookOnPanicMu.Unlock()
}

type hertzServerTesterOpt string

var (
	optOnlyServer        = hertzServerTesterOpt("only_server")
	optQuiet             = hertzServerTesterOpt("quiet_logging")
	optFramerReuseFrames = hertzServerTesterOpt("frame_reuse_frames")

	serverPort int32 = 8080
)

func newHertzServerTester(t testing.TB, handler app.HandlerFunc, opts ...interface{}) *hertzServerTester {
	resetHooks()

	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	cert, err := tls.LoadX509KeyPair("examples/certificate/server.crt", "examples/certificate/server.key")
	if err != nil {
		fmt.Println(err.Error())
	}

	port := atomic.AddInt32(&serverPort, 1)
	URL := fmt.Sprintf("127.0.0.1:%d", port)

	cfg.Certificates = append(cfg.Certificates, cert)
	cfg.NextProtos = append(cfg.NextProtos, "h2")

	server_opts := []config1.Option{server.WithHostPorts(URL), server.WithALPN(true), server.WithTLS(cfg)}
	h2Opts := []config.Option{}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{NextProtoTLS},
	}

	//	var onlyServer, quiet, framerReuseFrames bool
	var onlyServer, framerReuseFrames bool
	// h2server := new(Server)
	for _, opt := range opts {
		switch v := opt.(type) {
		case func(*tls.Config):
			v(tlsConfig)
		case config.Option:
			h2Opts = append(h2Opts, v)
		case config1.Option:
			server_opts = append(server_opts, v)
		case hertzServerTesterOpt:
			switch v {
			case optOnlyServer:
				onlyServer = true
			case optFramerReuseFrames:
				framerReuseFrames = true
			}
		default:
			t.Fatalf("unknown newHertzServerTester option type %T", v)
		}
	}

	h := server.New(server_opts...)

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory(h2Opts...))
	h.Any("/*any", handler)

	st := &hertzServerTester{
		t:     t,
		hertz: h,
		url:   URL,
	}
	st.hpackEnc = hpack.NewEncoder(&st.headerBuf)
	st.hpackDec = hpack.NewDecoder(initialHeaderTableSize, st.onHeaderField)
	st.addLogFilter("Transport readFrame error")

	testHookGetServerConn = func(v *serverConn) {
		st.scMu.Lock()
		defer st.scMu.Unlock()
		st.sc = v
	}
	hlog.SetOutput(io.MultiWriter(stderrv(), twriter{t: t, filter: st}))

	go h.Spin()
	time.Sleep(100 * time.Millisecond)

	if !onlyServer {
		cc, err := tls.Dial("tcp", st.url, tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		st.cc = cc
		st.fr = NewFramer(cc, newMockTLSConn(cc))
		if framerReuseFrames {
			st.fr.SetReuseFrames()
		}
		if !logFrameReads && !logFrameWrites {
			st.fr.logReads = true
			st.fr.logWrites = true
		}
	}

	return st
}

func (st *hertzServerTester) IsFilter(p string) bool {
	for _, phrase := range st.logFilter {
		if strings.Contains(p, phrase) {
			return true
		}
	}
	return false
}

func (st *hertzServerTester) Close() {
	if st.t.Failed() {
		st.frameReadLogMu.Lock()
		if st.frameReadLogBuf.Len() > 0 {
			st.t.Logf("Framer read log:\n%s", st.frameReadLogBuf.String())
		}
		st.frameReadLogMu.Unlock()

		st.frameWriteLogMu.Lock()
		if st.frameWriteLogBuf.Len() > 0 {
			st.t.Logf("Framer write log:\n%s", st.frameWriteLogBuf.String())
		}
		st.frameWriteLogMu.Unlock()

		// If we failed already (and are likely in a Fatal,
		// unwindowing), force close the connection, so the
		// httptest.Server doesn't wait forever for the conn
		// to close.
		if st.cc != nil {
			st.cc.Close()
		}
	}
	if st.cc != nil {
		st.cc.Close()
	}
	hlog.SetOutput(os.Stderr)
}

func readFrameTimeout(fr *Framer, wait time.Duration) (Frame, error) {
	ch := make(chan interface{}, 1)
	go func() {
		fr, err := fr.ReadFrame()
		if err != nil {
			ch <- err
		} else {
			ch <- fr
		}
	}()
	t := time.NewTimer(wait)
	select {
	case v := <-ch:
		t.Stop()
		if fr, ok := v.(Frame); ok {
			return fr, nil
		}
		return nil, v.(error)
	case <-t.C:
		return nil, errors.New("timeout waiting for frame")
	}
}

type standardServerTester struct {
	cc             net.Conn // client conn
	t              testing.TB
	ts             *httptest.Server
	fr             *Framer
	serverLogBuf   bytes.Buffer // logger for httptest.Server
	logFilter      []string     // substrings to filter out
	scMu           sync.Mutex   // guards sc
	sc             *serverConn
	hpackDec       *hpack.Decoder
	decodedHeaders [][2]string

	// If http2debug!=2, then we capture Frame debug logs that will be written
	// to t.Log after a test fails. The read and write logs use separate locks
	// and buffers so we don't accidentally introduce synchronization between
	// the read and write goroutines, which may hide data races.
	frameReadLogMu   sync.Mutex
	frameReadLogBuf  bytes.Buffer
	frameWriteLogMu  sync.Mutex
	frameWriteLogBuf bytes.Buffer

	// writing headers:
	headerBuf bytes.Buffer
	hpackEnc  *hpack.Encoder
}

func (st *standardServerTester) IsFilter(p string) bool {
	for _, phrase := range st.logFilter {
		if strings.Contains(p, phrase) {
			return true
		}
	}
	return false
}

func (st *standardServerTester) onHeaderField(f hpack.HeaderField) {
	if f.Name == "date" {
		return
	}
	st.decodedHeaders = append(st.decodedHeaders, [2]string{f.Name, f.Value})
}

func (st *standardServerTester) Close() {
	if st.t.Failed() {
		st.frameReadLogMu.Lock()
		if st.frameReadLogBuf.Len() > 0 {
			st.t.Logf("Framer read log:\n%s", st.frameReadLogBuf.String())
		}
		st.frameReadLogMu.Unlock()

		st.frameWriteLogMu.Lock()
		if st.frameWriteLogBuf.Len() > 0 {
			st.t.Logf("Framer write log:\n%s", st.frameWriteLogBuf.String())
		}
		st.frameWriteLogMu.Unlock()

		// If we failed already (and are likely in a Fatal,
		// unwindowing), force close the connection, so the
		// httptest.Server doesn't wait forever for the conn
		// to close.
		if st.cc != nil {
			st.cc.Close()
		}
	}
	if st.cc != nil {
		st.cc.Close()
	}
	hlog.SetOutput(os.Stderr)
}

func newStandardServerTester(t testing.TB, handler http.HandlerFunc, opts ...interface{}) *standardServerTester {
	resetHooks()

	ts := httptest.NewUnstartedServer(handler)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{NextProtoTLS},
	}

	//	var onlyServer, quiet, framerReuseFrames bool
	var onlyServer, quiet, framerReuseFrames bool
	h2server := new(http2.Server)
	for _, opt := range opts {
		switch v := opt.(type) {
		case func(*tls.Config):
			v(tlsConfig)
		case func(*httptest.Server):
			v(ts)
		case func(*http2.Server):
			v(h2server)
		case hertzServerTesterOpt:
			switch v {
			case optOnlyServer:
				onlyServer = true
			case optQuiet:
				quiet = true
			case optFramerReuseFrames:
				framerReuseFrames = true
			}
		case func(net.Conn, http.ConnState):
			ts.Config.ConnState = v
		default:
			t.Fatalf("unknown newHertzServerTester option type %T", v)
		}
	}

	http2.ConfigureServer(ts.Config, h2server)

	st := &standardServerTester{
		t:  t,
		ts: ts,
	}
	st.hpackEnc = hpack.NewEncoder(&st.headerBuf)
	st.hpackDec = hpack.NewDecoder(initialHeaderTableSize, st.onHeaderField)

	ts.TLS = ts.Config.TLSConfig // the httptest.Server has its own copy of this TLS config
	if quiet {
		ts.Config.ErrorLog = log.New(ioutil.Discard, "", 0)
	} else {
		ts.Config.ErrorLog = log.New(io.MultiWriter(stderrv(), twriter{t: t, filter: st}, &st.serverLogBuf), "", log.LstdFlags)
	}
	ts.StartTLS()

	if VerboseLogs {
		hlog.Infof("HERTZ: Running test server at: %s", ts.URL)
	}
	testHookGetServerConn = func(v *serverConn) {
		st.scMu.Lock()
		defer st.scMu.Unlock()
		st.sc = v
	}
	hlog.SetOutput(io.MultiWriter(stderrv(), twriter{t: t, filter: st}))

	if !onlyServer {
		cc, err := tls.Dial("tcp", ts.Listener.Addr().String(), tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		st.cc = cc
		st.fr = NewFramer(cc, newMockTLSConn(cc))
		if framerReuseFrames {
			st.fr.SetReuseFrames()
		}
		if !logFrameReads && !logFrameWrites {
			st.fr.logReads = true
			st.fr.logWrites = true
		}
	}
	return st
}

func (st *hertzServerTester) writeData(streamID uint32, endStream bool, data []byte) {
	if err := st.fr.WriteData(streamID, endStream, data); err != nil {
		st.t.Fatalf("Error writing DATA: %v", err)
	}
}

func (st *hertzServerTester) writeDataPadded(streamID uint32, endStream bool, data, pad []byte) {
	if err := st.fr.WriteDataPadded(streamID, endStream, data, pad); err != nil {
		st.t.Fatalf("Error writing DATA: %v", err)
	}
}

func (st *hertzServerTester) stream(id uint32) *stream {
	ch := make(chan *stream, 1)
	st.sc.serveMsgCh <- func(int) {
		ch <- st.sc.streams[id]
	}
	return <-ch
}

func (st *hertzServerTester) streamState(id uint32) streamState {
	ch := make(chan streamState, 1)
	st.sc.serveMsgCh <- func(int) {
		state, _ := st.sc.state(id)
		ch <- state
	}
	return <-ch
}

func (st *hertzServerTester) readFrame() (Frame, error) {
	return st.fr.ReadFrame()
}

func (st *hertzServerTester) wantHeaders() *HeadersFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a HEADERS frame: %v", err)
	}
	hf, ok := f.(*HeadersFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *HeadersFrame", f)
	}
	return hf
}

func (st *hertzServerTester) wantContinuation() *ContinuationFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a CONTINUATION frame: %v", err)
	}
	cf, ok := f.(*ContinuationFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *ContinuationFrame", f)
	}
	return cf
}

func (st *hertzServerTester) wantData() *DataFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a DATA frame: %v", err)
	}
	df, ok := f.(*DataFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *DataFrame", f)
	}
	return df
}

func (st *hertzServerTester) wantSettings() *SettingsFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a SETTINGS frame: %v", err)
	}
	sf, ok := f.(*SettingsFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *SettingsFrame", f)
	}
	return sf
}

func (st *hertzServerTester) wantPing() *PingFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a PING frame: %v", err)
	}
	pf, ok := f.(*PingFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *PingFrame", f)
	}
	return pf
}

func (st *hertzServerTester) wantGoAway() *GoAwayFrame {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a GOAWAY frame: %v", err)
	}
	gf, ok := f.(*GoAwayFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *GoAwayFrame", f)
	}
	return gf
}

func (st *hertzServerTester) wantRSTStream(streamID uint32, errCode ErrCode) {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting an RSTStream frame: %v", err)
	}
	rs, ok := f.(*RSTStreamFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *RSTStreamFrame", f)
	}
	if rs.FrameHeader.StreamID != streamID {
		st.t.Fatalf("RSTStream StreamID = %d; want %d", rs.FrameHeader.StreamID, streamID)
	}
	if rs.ErrCode != errCode {
		st.t.Fatalf("RSTStream ErrCode = %d (%s); want %d (%s)", rs.ErrCode, rs.ErrCode, errCode, errCode)
	}
}

func (st *hertzServerTester) wantWindowUpdate(streamID, incr uint32) {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatalf("Error while expecting a WINDOW_UPDATE frame: %v", err)
	}
	wu, ok := f.(*WindowUpdateFrame)
	if !ok {
		st.t.Fatalf("got a %T; want *WindowUpdateFrame", f)
	}
	if wu.FrameHeader.StreamID != streamID {
		st.t.Fatalf("WindowUpdate StreamID = %d; want %d", wu.FrameHeader.StreamID, streamID)
	}
	if wu.Increment != incr {
		st.t.Fatalf("WindowUpdate increment = %d; want %d", wu.Increment, incr)
	}
}

func (st *hertzServerTester) wantSettingsAck() {
	f, err := st.readFrame()
	if err != nil {
		st.t.Fatal(err)
	}
	sf, ok := f.(*SettingsFrame)
	if !ok {
		st.t.Fatalf("Wanting a settings ACK, received a %T", f)
	}
	if !sf.Header().Flags.Has(FlagSettingsAck) {
		st.t.Fatal("Settings Frame didn't have ACK set")
	}
}

// greet initiates the client's HTTP/2 connection into a state where
// frames may be sent.
func (st *hertzServerTester) greet() {
	st.greetAndCheckSettings(func(Setting) error { return nil })
}

func (st *hertzServerTester) greetAndCheckSettings(checkSetting func(s Setting) error) {
	st.writePreface()
	st.writeInitialSettings()
	st.wantSettings().ForeachSetting(checkSetting)
	st.writeSettingsAck()

	// The initial WINDOW_UPDATE and SETTINGS ACK can come in any order.
	var gotSettingsAck bool
	var gotWindowUpdate bool

	for i := 0; i < 2; i++ {
		f, err := st.readFrame()
		if err != nil {
			st.t.Fatal(err)
		}
		switch f := f.(type) {
		case *SettingsFrame:
			if !f.Header().Flags.Has(FlagSettingsAck) {
				st.t.Fatal("Settings Frame didn't have ACK set")
			}
			gotSettingsAck = true

		case *WindowUpdateFrame:
			if f.FrameHeader.StreamID != 0 {
				st.t.Fatalf("WindowUpdate StreamID = %d; want 0", f.FrameHeader.StreamID)
			}
			incr := uint32(st.sc.srv.initialConnRecvWindowSize() - initialWindowSize)
			if f.Increment != incr {
				st.t.Fatalf("WindowUpdate increment = %d; want %d", f.Increment, incr)
			}
			gotWindowUpdate = true

		default:
			st.t.Fatalf("Wanting a settings ACK or window update, received a %T", f)
		}
	}

	if !gotSettingsAck {
		st.t.Fatalf("Didn't get a settings ACK")
	}
	if !gotWindowUpdate {
		st.t.Fatalf("Didn't get a window update")
	}
}

func (st *hertzServerTester) writePreface() {
	n, err := st.cc.Write(clientPreface)
	if err != nil {
		st.t.Fatalf("Error writing client preface: %v", err)
	}
	if n != len(clientPreface) {
		st.t.Fatalf("Writing client preface, wrote %d bytes; want %d", n, len(clientPreface))
	}
}

func (st *hertzServerTester) writeInitialSettings() {
	if err := st.fr.WriteSettings(); err != nil {
		if runtime.GOOS == "openbsd" && strings.HasSuffix(err.Error(), "write: broken pipe") {
			st.t.Logf("Error writing initial SETTINGS frame from client to server: %v", err)
			st.t.Skipf("Skipping test with known OpenBSD failure mode. (See https://go.dev/issue/52208.)")
		}
		st.t.Fatalf("Error writing initial SETTINGS frame from client to server: %v", err)
	}
}

func (st *hertzServerTester) writeSettingsAck() {
	if err := st.fr.WriteSettingsAck(); err != nil {
		st.t.Fatalf("Error writing ACK of server's SETTINGS: %v", err)
	}
}

func (st *hertzServerTester) writeHeaders(p HeadersFrameParam) {
	if err := st.fr.WriteHeaders(p); err != nil {
		st.t.Fatalf("Error writing HEADERS: %v", err)
	}
}

func (st *hertzServerTester) writePriority(id uint32, p PriorityParam) {
	if err := st.fr.WritePriority(id, p); err != nil {
		st.t.Fatalf("Error writing PRIORITY: %v", err)
	}
}

// bodylessReq1 writes a HEADERS frames with StreamID 1 and EndStream and EndHeaders set.
func (st *hertzServerTester) bodylessReq1(headers ...string) {
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1, // clients send odd numbers
		BlockFragment: st.encodeHeader(headers...),
		EndStream:     true,
		EndHeaders:    true,
	})
}

func (st *hertzServerTester) encodeHeaderField(k, v string) {
	err := st.hpackEnc.WriteField(hpack.HeaderField{Name: k, Value: v})
	if err != nil {
		st.t.Fatalf("HPACK encoding error for %q/%q: %v", k, v, err)
	}
}

// encodeHeaderRaw is the magic-free version of encodeHeader.
// It takes 0 or more (k, v) pairs and encodes them.
func (st *hertzServerTester) encodeHeaderRaw(headers ...string) []byte {
	if len(headers)%2 == 1 {
		panic("odd number of kv args")
	}
	st.headerBuf.Reset()
	for len(headers) > 0 {
		k, v := headers[0], headers[1]
		st.encodeHeaderField(k, v)
		headers = headers[2:]
	}
	return st.headerBuf.Bytes()
}

// encodeHeader encodes headers and returns their HPACK bytes. headers
// must contain an even number of key/value pairs. There may be
// multiple pairs for keys (e.g. "cookie").  The :method, :path, and
// :scheme headers default to GET, / and https. The :authority header
// defaults to st.ts.Listener.Addr().
func (st *hertzServerTester) encodeHeader(headers ...string) []byte {
	if len(headers)%2 == 1 {
		panic("odd number of kv args")
	}

	st.headerBuf.Reset()
	defaultAuthority := st.url

	if len(headers) == 0 {
		// Fast path, mostly for benchmarks, so test code doesn't pollute
		// profiles when we're looking to improve server allocations.
		st.encodeHeaderField(":method", "GET")
		st.encodeHeaderField(":scheme", "https")
		st.encodeHeaderField(":authority", defaultAuthority)
		st.encodeHeaderField(":path", "/")
		return st.headerBuf.Bytes()
	}

	if len(headers) == 2 && headers[0] == ":method" {
		// Another fast path for benchmarks.
		st.encodeHeaderField(":method", headers[1])
		st.encodeHeaderField(":scheme", "https")
		st.encodeHeaderField(":authority", defaultAuthority)
		st.encodeHeaderField(":path", "/")
		return st.headerBuf.Bytes()
	}

	pseudoCount := map[string]int{}
	keys := []string{":method", ":scheme", ":authority", ":path"}
	vals := map[string][]string{
		":method":    {"GET"},
		":scheme":    {"https"},
		":authority": {defaultAuthority},
		":path":      {"/"},
	}
	for len(headers) > 0 {
		k, v := headers[0], headers[1]
		headers = headers[2:]
		if _, ok := vals[k]; !ok {
			keys = append(keys, k)
		}
		if strings.HasPrefix(k, ":") {
			pseudoCount[k]++
			if pseudoCount[k] == 1 {
				vals[k] = []string{v}
			} else {
				// Allows testing of invalid headers w/ dup pseudo fields.
				vals[k] = append(vals[k], v)
			}
		} else {
			vals[k] = append(vals[k], v)
		}
	}
	for _, k := range keys {
		for _, v := range vals[k] {
			st.encodeHeaderField(k, v)
		}
	}
	return st.headerBuf.Bytes()
}

// testServerRequest sets up an idle HTTP/2 connection and lets you
// write a single request with writeReq, and then verify that the
// *http.Request is built correctly in checkReq.
func testServerRequest(t *testing.T, writeReq func(tester *hertzServerTester), checkReq func(requestContext *app.RequestContext)) {
	gotReq := make(chan bool, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		if ctx.Request.BodyStream() == nil {
			t.Fatal("nil Body")
		}
		checkReq(ctx)
		gotReq <- true
	})
	defer st.Close()

	st.greet()
	writeReq(st)
	<-gotReq
}

func TestServer(t *testing.T) {
	gotReq := make(chan bool, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Response.Header.Set("Foo", "Bar")
		gotReq <- true
	})
	defer st.Close()

	st.greet()
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1, // clients send odd numbers
		BlockFragment: st.encodeHeader(),
		EndStream:     true, // no DATA frames
		EndHeaders:    true,
	})

	<-gotReq
}

func TestServer_Request_Get(t *testing.T) {
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader("foo-bar", "some-value"),
			EndStream:     true, // no DATA frames
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		if string(ctx.Request.Method()) != "GET" {
			t.Errorf("Method = %q; want GET", string(ctx.Request.Method()))
		}
		if string(ctx.Request.URI().Path()) != "/" {
			t.Errorf("URL.Path = %q; want /", string(ctx.Request.URI().Path()))
		}
		if ctx.Request.Header.ContentLength() != -1 {
			t.Errorf("ContentLength = %v; want -1", ctx.Request.Header.ContentLength())
		}
		if ctx.Request.ConnectionClose() {
			t.Error("Close = true; want false")
		}
		if !strings.Contains(ctx.RemoteAddr().String(), ":") {
			t.Errorf("RemoteAddr = %q; want something with a colon", ctx.RemoteAddr().String())
		}
		if ctx.Request.Header.GetProtocol() != "HTTP/2.0" {
			t.Errorf("Proto = %q; want HTTP/2.0", ctx.Request.Header.GetProtocol())
		}
		wantHeader := http.Header{
			"Foo-Bar": []string{"some-value"},
		}
		for k, v := range wantHeader {
			actualKey := ctx.Request.Header.Get(k)
			if actualKey != v[0] {
				t.Errorf("Header %q = %q; want %q", k, actualKey, v)
			}
		}
		if n, err := ctx.Request.BodyStream().Read([]byte(" ")); err != io.EOF || n != 0 {
			t.Errorf("Read = %d, %v; want 0, EOF", n, err)
		}
	})
}

func TestServer_Request_Get_PathSlashes(t *testing.T) {
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":path", "/%2f/"),
			EndStream:     true, // no DATA frames
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		if string(ctx.Request.RequestURI()[22:]) != "/%2f/" {
			t.Errorf("RequestURI = %q; want /%%2f/", string(ctx.Request.RequestURI()[22:]))
		}
		if string(ctx.Request.URI().Path()) != "/" {
			t.Errorf("URL.Path = %q; want /", string(ctx.Request.URI().Path()))
		}
	})
}

// TODO: add a test with EndStream=true on the HEADERS but setting a
// Content-Length anyway. Should we just omit it and force it to
// zero?
func TestServer_Request_Post_NoContentLength_EndStream(t *testing.T) {
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":method", "POST"),
			EndStream:     true,
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		if string(ctx.Request.Method()) != "POST" {
			t.Errorf("Method = %q; want POST", string(ctx.Request.Method()))
		}
		if ctx.Request.Header.ContentLength() != -1 {
			t.Errorf("ContentLength = %v; want -1", ctx.Request.Header.ContentLength())
		}
		if n, err := ctx.Request.BodyStream().Read([]byte(" ")); err != io.EOF || n != 0 {
			t.Errorf("Read = %d, %v; want 0, EOF", n, err)
		}
	})
}

func testBodyContents(t *testing.T, wantContentLength int64, wantBody string, write func(st *hertzServerTester)) {
	testServerRequest(t, write, func(ctx *app.RequestContext) {
		if string(ctx.Request.Method()) != "POST" {
			t.Errorf("Method = %q; want POST", string(ctx.Request.Method()))
		}
		if int64(ctx.Request.Header.ContentLength()) != wantContentLength {
			t.Errorf("ContentLength = %v; want %d", ctx.Request.Header.ContentLength(), wantContentLength)
		}
		all, err := ioutil.ReadAll(ctx.Request.BodyStream())
		if err != nil {
			t.Fatal(err)
		}
		if string(all) != wantBody {
			t.Errorf("Read = %q; want %q", all, wantBody)
		}
		if err := ctx.Request.BodyStream().(io.Closer).Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

func testBodyContentsFail(t *testing.T, wantContentLength int64, wantReadError string, write func(st *hertzServerTester)) {
	testServerRequest(t, write, func(ctx *app.RequestContext) {
		if string(ctx.Request.Method()) != "POST" {
			t.Errorf("Method = %q; want POST", string(ctx.Request.Method()))
		}
		if int64(ctx.Request.Header.ContentLength()) != wantContentLength {
			t.Errorf("ContentLength = %v; want %d", ctx.Request.Header.ContentLength(), wantContentLength)
		}
		all, err := ioutil.ReadAll(ctx.Request.BodyStream())
		if err == nil {
			t.Fatalf("expected an error (%q) reading from the body. Successfully read %q instead.",
				wantReadError, all)
		}
		if !strings.Contains(err.Error(), wantReadError) {
			t.Fatalf("Body.Read = %v; want substring %q", err, wantReadError)
		}
		if err := ctx.Request.BodyStream().(io.Closer).Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

func TestServer_Request_Post_Body_ImmediateEOF(t *testing.T) {
	testBodyContents(t, -1, "", func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":method", "POST"),
			EndStream:     false, // to say DATA frames are coming
			EndHeaders:    true,
		})
		st.writeData(1, true, nil) // just kidding. empty body.
	})
}

func TestServer_Request_Post_Body_OneData(t *testing.T) {
	const content = "Some content"
	testBodyContents(t, -1, content, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":method", "POST"),
			EndStream:     false, // to say DATA frames are coming
			EndHeaders:    true,
		})
		st.writeData(1, true, []byte(content))
	})
}

func TestServer_Request_Post_Body_TwoData(t *testing.T) {
	const content = "Some content"
	testBodyContents(t, -1, content, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":method", "POST"),
			EndStream:     false, // to say DATA frames are coming
			EndHeaders:    true,
		})
		st.writeData(1, false, []byte(content[:5]))
		st.writeData(1, true, []byte(content[5:]))
	})
}

func TestServer_Request_Post_Body_ContentLength_Correct(t *testing.T) {
	const content = "Some content"
	testBodyContents(t, int64(len(content)), content, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1, // clients send odd numbers
			BlockFragment: st.encodeHeader(
				":method", "POST",
				"content-length", strconv.Itoa(len(content)),
			),
			EndStream:  false, // to say DATA frames are coming
			EndHeaders: true,
		})
		st.writeData(1, true, []byte(content))
	})
}

func TestServer_Request_Post_Body_ContentLength_TooLarge(t *testing.T) {
	testBodyContentsFail(t, 3, "request declared a Content-Length of 3 but only wrote 2 bytes",
		func(st *hertzServerTester) {
			st.writeHeaders(HeadersFrameParam{
				StreamID: 1, // clients send odd numbers
				BlockFragment: st.encodeHeader(
					":method", "POST",
					"content-length", "3",
				),
				EndStream:  false, // to say DATA frames are coming
				EndHeaders: true,
			})
			st.writeData(1, true, []byte("12"))
		})
}

func TestServer_Request_Post_Body_ContentLength_TooSmall(t *testing.T) {
	testBodyContentsFail(t, 4, "sender tried to send more than declared Content-Length of 4 bytes",
		func(st *hertzServerTester) {
			st.writeHeaders(HeadersFrameParam{
				StreamID: 1, // clients send odd numbers
				BlockFragment: st.encodeHeader(
					":method", "POST",
					"content-length", "4",
				),
				EndStream:  false, // to say DATA frames are coming
				EndHeaders: true,
			})
			st.writeData(1, true, []byte("12345"))
			// Return flow control bytes back, since the data handler closed
			// the stream.
			// TODO: check if must return window update
			// st.wantWindowUpdate(0, 5)
		})
}

// Using a Host header, instead of :authority
func TestServer_Request_Get_Host(t *testing.T) {
	const host = "example.com"
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":authority", "", "host", host),
			EndStream:     true,
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		if string(ctx.Request.Header.Host()) != host {
			t.Errorf("Host = %q; want %q", string(ctx.Host()), host)
		}
	})
}

// Using an :authority pseudo-header, instead of Host
func TestServer_Request_Get_Authority(t *testing.T) {
	const host = "example.com"
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":authority", host),
			EndStream:     true,
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		if string(ctx.Host()) != host {
			t.Errorf("Host = %q; want %q", string(ctx.Host()), host)
		}
	})
}

func TestServer_Request_WithContinuation(t *testing.T) {
	wantHeader := http.Header{
		"Foo-One":   []string{"value-one"},
		"Foo-Two":   []string{"value-two"},
		"Foo-Three": []string{"value-three"},
	}
	testServerRequest(t, func(st *hertzServerTester) {
		fullHeaders := st.encodeHeader(
			"foo-one", "value-one",
			"foo-two", "value-two",
			"foo-three", "value-three",
		)
		remain := fullHeaders
		chunks := 0
		for len(remain) > 0 {
			const maxChunkSize = 5
			chunk := remain
			if len(chunk) > maxChunkSize {
				chunk = chunk[:maxChunkSize]
			}
			remain = remain[len(chunk):]

			if chunks == 0 {
				st.writeHeaders(HeadersFrameParam{
					StreamID:      1, // clients send odd numbers
					BlockFragment: chunk,
					EndStream:     true,  // no DATA frames
					EndHeaders:    false, // we'll have continuation frames
				})
			} else {
				err := st.fr.WriteContinuation(1, len(remain) == 0, chunk)
				if err != nil {
					t.Fatal(err)
				}
			}
			chunks++
		}
		if chunks < 2 {
			t.Fatal("too few chunks")
		}
	}, func(ctx *app.RequestContext) {
		for k, v := range wantHeader {
			actualKey := ctx.Request.Header.Get(k)
			if actualKey != v[0] {
				t.Errorf("Header %q = %q; want %q", k, actualKey, v)
			}
		}
	})
}

// Concatenated cookie headers. ("8.1.2.5 Compressing the Cookie Header Field")
func TestServer_Request_CookieConcat(t *testing.T) {
	const host = "example.com"
	testServerRequest(t, func(st *hertzServerTester) {
		st.bodylessReq1(
			":authority", host,
			"cookie", "a=b",
			"cookie", "c=d",
			"cookie", "e=f",
		)
	}, func(ctx *app.RequestContext) {
		const want = "a=b; c=d; e=f"
		if got := ctx.Request.Header.Get("Cookie"); got != want {
			t.Errorf("Cookie = %q; want %q", got, want)
		}
	})
}

func testRejectRequest(t *testing.T, send func(*hertzServerTester)) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		t.Error("server request made it to handler; should've been rejected")
	})
	defer st.Close()

	st.greet()
	send(st)
	st.wantRSTStream(1, ErrCodeProtocol)
}

func TestServer_Request_Reject_CapitalHeader(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("UPPER", "v") })
}

func TestServer_Request_Reject_HeaderFieldNameColon(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("has:colon", "v") })
}

func TestServer_Request_Reject_HeaderFieldNameNULL(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("has\x00null", "v") })
}

func TestServer_Request_Reject_HeaderFieldNameEmpty(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("", "v") })
}

func TestServer_Request_Reject_HeaderFieldValueNewline(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("foo", "has\nnewline") })
}

func TestServer_Request_Reject_HeaderFieldValueCR(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("foo", "has\rcarriage") })
}

func TestServer_Request_Reject_HeaderFieldValueDEL(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1("foo", "has\x7fdel") })
}

func TestServer_Request_Reject_Pseudo_Missing_method(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1(":method", "") })
}

func (st *hertzServerTester) addLogFilter(phrase string) {
	st.logFilter = append(st.logFilter, phrase)
}

func TestServer_Request_Reject_Pseudo_ExactlyOne(t *testing.T) {
	// 8.1.2.3 Request Pseudo-Header Fields
	// "All HTTP/2 requests MUST include exactly one valid value" ...
	testRejectRequest(t, func(st *hertzServerTester) {
		st.addLogFilter("duplicate pseudo-header")
		st.bodylessReq1(":method", "GET", ":method", "POST")
	})
}

func TestServer_Request_Reject_Pseudo_AfterRegular(t *testing.T) {
	// 8.1.2.3 Request Pseudo-Header Fields
	// "All pseudo-header fields MUST appear in the header block
	// before regular header fields. Any request or response that
	// contains a pseudo-header field that appears in a header
	// block after a regular header field MUST be treated as
	// malformed (Section 8.1.2.6)."
	testRejectRequest(t, func(st *hertzServerTester) {
		st.addLogFilter("pseudo-header after regular header")
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		enc.WriteField(hpack.HeaderField{Name: "regular", Value: "foobar"})
		enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: buf.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		})
	})
}

func TestServer_Request_Reject_Pseudo_Missing_path(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1(":path", "") })
}

func TestServer_Request_Reject_Pseudo_Missing_scheme(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1(":scheme", "") })
}

func TestServer_Request_Reject_Pseudo_scheme_invalid(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) { st.bodylessReq1(":scheme", "bogus") })
}

func TestServer_Request_Reject_Pseudo_Unknown(t *testing.T) {
	testRejectRequest(t, func(st *hertzServerTester) {
		st.addLogFilter(`invalid pseudo-header ":unknown_thing"`)
		st.bodylessReq1(":unknown_thing", "")
	})
}

func testRejectRequestWithProtocolError(t *testing.T, send func(*hertzServerTester)) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		t.Error("server request made it to handler; should've been rejected")
	}, optQuiet)
	defer st.Close()

	st.greet()
	send(st)
	gf := st.wantGoAway()
	if gf.ErrCode != ErrCodeProtocol {
		t.Errorf("err code = %v; want %v", gf.ErrCode, ErrCodeProtocol)
	}
}

// Section 5.1, on idle connections: "Receiving any frame other than
// HEADERS or PRIORITY on a stream in this state MUST be treated as a
// connection error (Section 5.4.1) of type PROTOCOL_ERROR."
func TestRejectFrameOnIdle_WindowUpdate(t *testing.T) {
	testRejectRequestWithProtocolError(t, func(st *hertzServerTester) {
		st.fr.WriteWindowUpdate(123, 456)
	})
}

func TestRejectFrameOnIdle_Data(t *testing.T) {
	testRejectRequestWithProtocolError(t, func(st *hertzServerTester) {
		st.fr.WriteData(123, true, nil)
	})
}

func TestRejectFrameOnIdle_RSTStream(t *testing.T) {
	testRejectRequestWithProtocolError(t, func(st *hertzServerTester) {
		st.fr.WriteRSTStream(123, ErrCodeCancel)
	})
}

func TestServer_Request_Connect(t *testing.T) {
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":authority", "example.com:123",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	}, func(ctx *app.RequestContext) {
		if g, w := string(ctx.Request.Method()), "CONNECT"; g != w {
			t.Errorf("Method = %q; want %q", g, w)
		}
		if g, w := string(ctx.Request.RequestURI()), "://example.com:123"; g != w {
			t.Errorf("RequestURI = %q; want %q", g, w)
		}
		if g, w := string(ctx.Host()), "example.com:123"; g != w {
			t.Errorf("URL.Host = %q; want %q", g, w)
		}
	})
}

func TestServer_Request_Connect_InvalidPath(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":authority", "example.com:123",
				":path", "/bogus",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	})
}

func TestServer_Request_Connect_InvalidScheme(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1,
			BlockFragment: st.encodeHeaderRaw(
				":method", "CONNECT",
				":authority", "example.com:123",
				":scheme", "https",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	})
}

func TestServer_Ping(t *testing.T) {
	st := newHertzServerTester(t, nil)
	defer st.Close()
	st.greet()

	// Server should ignore this one, since it has ACK set.
	ackPingData := [8]byte{1, 2, 4, 8, 16, 32, 64, 128}
	if err := st.fr.WritePing(true, ackPingData); err != nil {
		t.Fatal(err)
	}

	// But the server should reply to this one, since ACK is false.
	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := st.fr.WritePing(false, pingData); err != nil {
		t.Fatal(err)
	}

	pf := st.wantPing()
	if !pf.Flags.Has(FlagPingAck) {
		t.Error("response ping doesn't have ACK set")
	}
	if pf.Data != pingData {
		t.Errorf("response ping has data %q; want %q", pf.Data, pingData)
	}
}

func TestServer_RejectsLargeFrames(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" || runtime.GOOS == "zos" {
		t.Skip("see golang.org/issue/13434, golang.org/issue/37321")
	}
	st := newHertzServerTester(t, nil)
	defer st.Close()
	st.greet()

	// Write too large of a frame (too large by one byte)
	// We ignore the return value because it's expected that the server
	// will only read the first 9 bytes (the headre) and then disconnect.
	st.fr.WriteRawFrame(0xff, 0, 0, make([]byte, defaultMaxReadFrameSize+1))

	gf := st.wantGoAway()
	if gf.ErrCode != ErrCodeFrameSize {
		t.Errorf("GOAWAY err = %v; want %v", gf.ErrCode, ErrCodeFrameSize)
	}
	if st.serverLogBuf.Len() != 0 {
		// Previously we spun here for a bit until the GOAWAY disconnect
		// timer fired, logging while we fired.
		t.Errorf("unexpected server output: %.500s\n", st.serverLogBuf.Bytes())
	}
}

func TestServer_Handler_Sends_WindowUpdate(t *testing.T) {
	puppet := newHandlerPuppet()
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		puppet.act(c, ctx)
	})
	defer st.Close()
	defer puppet.done()

	st.greet()

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1, // clients send odd numbers
		BlockFragment: st.encodeHeader(":method", "POST"),
		EndStream:     false, // data coming
		EndHeaders:    true,
	})
	st.writeData(1, false, []byte("abcdef"))
	puppet.do(readBodyHandler(t, "abc"))
	st.wantWindowUpdate(0, 3)
	st.wantWindowUpdate(1, 3)

	puppet.do(readBodyHandler(t, "def"))
	st.wantWindowUpdate(0, 3)
	st.wantWindowUpdate(1, 3)

	st.writeData(1, true, []byte("ghijkl")) // END_STREAM here
	puppet.do(readBodyHandler(t, "ghi"))
	puppet.do(readBodyHandler(t, "jkl"))
	st.wantWindowUpdate(0, 3)
	st.wantWindowUpdate(0, 3) // no more stream-level, since END_STREAM
}

// the version of the TestServer_Handler_Sends_WindowUpdate with padding.
// See golang.org/issue/16556
func TestServer_Handler_Sends_WindowUpdate_Padding(t *testing.T) {
	puppet := newHandlerPuppet()
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		puppet.act(c, ctx)
	})
	defer st.Close()
	defer puppet.done()

	st.greet()

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(":method", "POST"),
		EndStream:     false,
		EndHeaders:    true,
	})
	st.writeDataPadded(1, false, []byte("abcdef"), []byte{0, 0, 0, 0})

	// Expect to immediately get our 5 bytes of padding back for
	// both the connection and stream (4 bytes of padding + 1 byte of length)
	st.wantWindowUpdate(0, 5)
	st.wantWindowUpdate(1, 5)

	puppet.do(readBodyHandler(t, "abc"))
	st.wantWindowUpdate(0, 3)
	st.wantWindowUpdate(1, 3)

	puppet.do(readBodyHandler(t, "def"))
	st.wantWindowUpdate(0, 3)
	st.wantWindowUpdate(1, 3)
}

func TestServer_Send_GoAway_After_Bogus_WindowUpdate(t *testing.T) {
	st := newHertzServerTester(t, nil)
	defer st.Close()
	st.greet()
	if err := st.fr.WriteWindowUpdate(0, 1<<31-1); err != nil {
		t.Fatal(err)
	}
	gf := st.wantGoAway()
	if gf.ErrCode != ErrCodeFlowControl {
		t.Errorf("GOAWAY err = %v; want %v", gf.ErrCode, ErrCodeFlowControl)
	}
	if gf.LastStreamID != 0 {
		t.Errorf("GOAWAY last stream ID = %v; want %v", gf.LastStreamID, 0)
	}
}

func TestServer_Send_RstStream_After_Bogus_WindowUpdate(t *testing.T) {
	inHandler := make(chan bool)
	blockHandler := make(chan bool)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		inHandler <- true
		<-blockHandler
	})
	defer st.Close()
	defer close(blockHandler)
	st.greet()
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(":method", "POST"),
		EndStream:     false, // keep it open
		EndHeaders:    true,
	})
	<-inHandler
	// Send a bogus window update:
	if err := st.fr.WriteWindowUpdate(1, 1<<31-1); err != nil {
		t.Fatal(err)
	}
	st.wantRSTStream(1, ErrCodeFlowControl)
}

// testServerPostUnblock sends a hanging POST with unsent data to handler,
// then runs fn once in the handler, and verifies that the error returned from
// handler is acceptable. It fails if takes over 5 seconds for handler to exit.
func testServerPostUnblock(t *testing.T,
	handler func(c context.Context, ctx *app.RequestContext) error,
	fn func(*hertzServerTester),
	checkErr func(error),
	otherHeaders ...string,
) {
	inHandler := make(chan bool)
	errc := make(chan error, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		inHandler <- true
		errc <- handler(c, ctx)
	})
	defer st.Close()
	st.greet()
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(append([]string{":method", "POST"}, otherHeaders...)...),
		EndStream:     false, // keep it open
		EndHeaders:    true,
	})
	<-inHandler
	fn(st)
	err := <-errc
	if checkErr != nil {
		checkErr(err)
	}
}

func TestServer_RSTStream_Unblocks_Read(t *testing.T) {
	testServerPostUnblock(t,
		func(c context.Context, ctx *app.RequestContext) (err error) {
			_, err = ctx.Request.BodyStream().Read(make([]byte, 1))
			return
		},
		func(st *hertzServerTester) {
			if err := st.fr.WriteRSTStream(1, ErrCodeCancel); err != nil {
				t.Fatal(err)
			}
		},
		func(err error) {
			want := StreamError{StreamID: 0x1, Code: 0x8}
			if !reflect.DeepEqual(err, want) {
				t.Errorf("Read error = %v; want %v", err, want)
			}
		},
	)
}

func TestServer_DeadConn_Unblocks_Read(t *testing.T) {
	testServerPostUnblock(t,
		func(c context.Context, ctx *app.RequestContext) (err error) {
			_, err = ctx.Request.BodyStream().Read(make([]byte, 1))
			return
		},
		func(st *hertzServerTester) { st.cc.Close() },
		func(err error) {
			if err == nil {
				t.Error("unexpected nil error from Request.Body.Read")
			}
		},
	)
}

func TestServer_StateTransitions(t *testing.T) {
	var st *hertzServerTester
	inHandler := make(chan bool)
	writeData := make(chan bool)
	leaveHandler := make(chan bool)
	st = newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		inHandler <- true
		if st.stream(1) == nil {
			t.Errorf("nil stream 1 in handler")
		}
		if got, want := st.streamState(1), stateOpen; got != want {
			t.Errorf("in handler, state is %v; want %v", got, want)
		}
		writeData <- true
		if n, err := ctx.Request.BodyStream().Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("body read = %d, %v; want 0, EOF", n, err)
		}
		if got, want := st.streamState(1), stateHalfClosedRemote; got != want {
			t.Errorf("in handler, state is %v; want %v", got, want)
		}

		<-leaveHandler
	})
	st.greet()
	if st.stream(1) != nil {
		t.Fatal("stream 1 should be empty")
	}
	if got := st.streamState(1); got != stateIdle {
		t.Fatalf("stream 1 should be idle; got %v", got)
	}

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(":method", "POST"),
		EndStream:     false, // keep it open
		EndHeaders:    true,
	})
	<-inHandler
	<-writeData
	st.writeData(1, true, nil)

	leaveHandler <- true
	hf := st.wantHeaders()
	if !hf.StreamEnded() {
		t.Fatal("expected END_STREAM flag")
	}

	if got, want := st.streamState(1), stateClosed; got != want {
		t.Errorf("at end, state is %v; want %v", got, want)
	}
	if st.stream(1) != nil {
		t.Fatal("at end, stream 1 should be gone")
	}
}

// test HEADERS w/o EndHeaders + another HEADERS (should get rejected)
func TestServer_Rejects_HeadersNoEnd_Then_Headers(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    false,
		})
		st.writeHeaders(HeadersFrameParam{ // Not a continuation.
			StreamID:      3, // different stream.
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
		})
	})
}

// test HEADERS w/o EndHeaders + PING (should get rejected)
func TestServer_Rejects_HeadersNoEnd_Then_Ping(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    false,
		})
		if err := st.fr.WritePing(false, [8]byte{}); err != nil {
			t.Fatal(err)
		}
	})
}

// test HEADERS w/ EndHeaders + a continuation HEADERS (should get rejected)
func TestServer_Rejects_HeadersEnd_Then_Continuation(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
		})
		st.wantHeaders()
		if err := st.fr.WriteContinuation(1, true, encodeHeaderNoImplicit(t, "foo", "bar")); err != nil {
			t.Fatal(err)
		}
	})
}

// test HEADERS w/o EndHeaders + a continuation HEADERS on wrong stream ID
func TestServer_Rejects_HeadersNoEnd_Then_ContinuationWrongStream(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    false,
		})
		if err := st.fr.WriteContinuation(3, true, encodeHeaderNoImplicit(t, "foo", "bar")); err != nil {
			t.Fatal(err)
		}
	})
}

// No HEADERS on stream 0.
func TestServer_Rejects_Headers0(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.fr.AllowIllegalWrites = true
		st.writeHeaders(HeadersFrameParam{
			StreamID:      0,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
		})
	})
}

// No CONTINUATION on stream 0.
func TestServer_Rejects_Continuation0(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.fr.AllowIllegalWrites = true
		if err := st.fr.WriteContinuation(0, true, st.encodeHeader()); err != nil {
			t.Fatal(err)
		}
	})
}

// No PRIORITY on stream 0.
func TestServer_Rejects_Priority0(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		st.fr.AllowIllegalWrites = true
		st.writePriority(0, PriorityParam{StreamDep: 1})
	})
}

// No HEADERS frame with a self-dependence.
func TestServer_Rejects_HeadersSelfDependence(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.fr.AllowIllegalWrites = true
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
			Priority:      PriorityParam{StreamDep: 1},
		})
	})
}

// No PRIORITY frame with a self-dependence.
func TestServer_Rejects_PrioritySelfDependence(t *testing.T) {
	testServerRejectsStream(t, ErrCodeProtocol, func(st *hertzServerTester) {
		st.fr.AllowIllegalWrites = true
		st.writePriority(1, PriorityParam{StreamDep: 1})
	})
}

func TestServer_Rejects_PushPromise(t *testing.T) {
	testServerRejectsConn(t, func(st *hertzServerTester) {
		pp := PushPromiseParam{
			StreamID:  1,
			PromiseID: 3,
		}
		if err := st.fr.WritePushPromise(pp); err != nil {
			t.Fatal(err)
		}
	})
}

// testServerRejectsConn tests that the server hangs up with a GOAWAY
// frame and a server close after the client does something
// deserving a CONNECTION_ERROR.
func testServerRejectsConn(t *testing.T, writeReq func(*hertzServerTester)) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {})
	st.addLogFilter("connection error: PROTOCOL_ERROR")
	defer st.Close()
	st.greet()
	writeReq(st)

	st.wantGoAway()

	fr, err := st.fr.ReadFrame()
	if err == nil {
		t.Errorf("ReadFrame got frame of type %T; want io.EOF", fr)
	}
	if err != io.EOF {
		t.Errorf("ReadFrame = %v; want io.EOF", err)
	}
}

// testServerRejectsStream tests that the server sends a RST_STREAM with the provided
// error code after a client sends a bogus request.
func testServerRejectsStream(t *testing.T, code ErrCode, writeReq func(*hertzServerTester)) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {})
	defer st.Close()
	st.greet()
	writeReq(st)
	st.wantRSTStream(1, code)
}

func getSlash(st *hertzServerTester) { st.bodylessReq1() }

func TestServer_Response_NoData(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		// Nothing.
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if !hf.StreamEnded() {
			t.Fatal("want END_STREAM flag")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
	})
}

func TestServer_Response_NoData_Header_FooBar(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ctx.Response.Header.Set("Foo-Bar", "some-value")
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if !hf.StreamEnded() {
			t.Fatal("want END_STREAM flag")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"foo-bar", "some-value"},
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", "0"},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Got headers %v; want %v", goth, wanth)
		}
	})
}

// Reject content-length headers containing a sign.
// See https://golang.org/issue/39017
func TestServerIgnoresContentLengthSignWhenWritingChunks(t *testing.T) {
	tests := []struct {
		name   string
		cl     string
		wantCL string
	}{
		{
			name:   "proper content-length",
			cl:     "3",
			wantCL: "3",
		},
		{
			name:   "ignore cl with plus sign",
			cl:     "+3",
			wantCL: "0",
		},
		{
			name:   "ignore cl with minus sign",
			cl:     "-3",
			wantCL: "0",
		},
		{
			name:   "max int64, for safe uint64->int64 conversion",
			cl:     "9223372036854775807",
			wantCL: "9223372036854775807",
		},
		{
			name:   "overflows int64, so ignored",
			cl:     "9223372036854775808",
			wantCL: "0",
		},
	}

	for _, tt := range tests {
		testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
			ctx.Response.Header.Set("content-length", tt.cl)
			return nil
		}, func(st *hertzServerTester) {
			getSlash(st)
			hf := st.wantHeaders()
			goth := st.decodeHeader(hf.HeaderBlockFragment())
			wanth := [][2]string{
				{":status", "200"},
				{"content-type", "text/plain; charset=utf-8"},
				{"content-length", tt.wantCL},
			}
			if !reflect.DeepEqual(goth, wanth) {
				t.Errorf("For case %q, value %q, got = %q; want %q", tt.name, tt.cl, goth, wanth)
			}
		})
	}
}

// Reject content-length headers containing a sign.
// See https://golang.org/issue/39017
func TestServerRejectsContentLengthWithSignNewRequests(t *testing.T) {
	tests := []struct {
		name   string
		cl     string
		wantCL int64
	}{
		{
			name:   "proper content-length",
			cl:     "3",
			wantCL: 3,
		},
		{
			name:   "ignore cl with plus sign",
			cl:     "+3",
			wantCL: -1,
		},
		{
			name:   "ignore cl with minus sign",
			cl:     "-3",
			wantCL: -1,
		},
		{
			name:   "max int64, for safe uint64->int64 conversion",
			cl:     "9223372036854775807",
			wantCL: 9223372036854775807,
		},
		{
			name:   "overflows int64, so ignored",
			cl:     "9223372036854775808",
			wantCL: -1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			writeReq := func(st *hertzServerTester) {
				st.writeHeaders(HeadersFrameParam{
					StreamID:      1, // clients send odd numbers
					BlockFragment: st.encodeHeader("content-length", tt.cl),
					EndStream:     false,
					EndHeaders:    true,
				})
				st.writeData(1, false, []byte(""))
			}
			checkReq := func(ctx *app.RequestContext) {
				if int64(ctx.Request.Header.ContentLength()) != tt.wantCL {
					t.Fatalf("Got: %d\nWant: %d", ctx.Request.Header.ContentLength(), tt.wantCL)
				}
			}
			testServerRequest(t, writeReq, checkReq)
		})
	}
}

func TestServer_Response_Data_Sniff_DoesntOverride(t *testing.T) {
	const msg = "<html>this is HTML."
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ctx.Response.Header.Set("Content-Type", "foo/bar")
		ctx.WriteString(msg)
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("don't want END_STREAM, expecting data")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"content-type", "foo/bar"},
			{"content-length", strconv.Itoa(len(msg))},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Got headers %v; want %v", goth, wanth)
		}
		df := st.wantData()
		if !df.StreamEnded() {
			t.Error("expected DATA to have END_STREAM flag")
		}
		if got := string(df.Data()); got != msg {
			t.Errorf("got DATA %q; want %q", got, msg)
		}
	})
}

func TestServer_Response_TransferEncoding_chunked(t *testing.T) {
	const msg = "hi"
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ctx.Response.Header.Set("Transfer-Encoding", "chunked") // should be stripped
		ctx.WriteString(msg)
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", strconv.Itoa(len(msg))},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Got headers %v; want %v", goth, wanth)
		}
	})
}

func TestServer_Response_LargeWrite(t *testing.T) {
	const size = 1 << 20
	const maxFrameSize = 16 << 10
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		n, err := ctx.Write(bytes.Repeat([]byte("a"), size))
		if err != nil {
			return fmt.Errorf("Write error: %v", err)
		}
		if n != size {
			return fmt.Errorf("wrong size %d from Write", n)
		}
		return nil
	}, func(st *hertzServerTester) {
		if err := st.fr.WriteSettings(
			Setting{SettingInitialWindowSize, 0},
			Setting{SettingMaxFrameSize, maxFrameSize},
		); err != nil {
			t.Fatal(err)
		}
		st.wantSettingsAck()

		getSlash(st) // make the single request

		// Give the handler quota to write:
		if err := st.fr.WriteWindowUpdate(1, size); err != nil {
			t.Fatal(err)
		}
		// Give the handler quota to write to connection-level
		// window as well
		if err := st.fr.WriteWindowUpdate(0, size); err != nil {
			t.Fatal(err)
		}
		hf := st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("unexpected END_STREAM flag")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"content-type", "text/plain; charset=utf-8"}, // sniffed
			// and no content-length
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Got headers %v; want %v", goth, wanth)
		}
		var bytes, frames int
		for {
			df := st.wantData()
			bytes += len(df.Data())
			frames++
			for _, b := range df.Data() {
				if b != 'a' {
					t.Fatal("non-'a' byte seen in DATA")
				}
			}
			if df.StreamEnded() {
				break
			}
		}
		if bytes != size {
			t.Errorf("Got %d bytes; want %d", bytes, size)
		}
		if want := int(size / maxFrameSize); frames < want || frames > want*2 {
			t.Errorf("Got %d frames; want %d", frames, size)
		}
	})
}

// Test that the handler can't write more than the client allows
func TestServer_Response_LargeWrite_FlowControlled(t *testing.T) {
	// Make these reads. Before each read, the client adds exactly enough
	// flow-control to satisfy the read. Numbers chosen arbitrarily.
	reads := []int{123, 1, 13, 127}
	size := 0
	for _, n := range reads {
		size += n
	}

	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		// w.(http.Flusher).Flush()
		n, err := ctx.Write(bytes.Repeat([]byte("a"), size))
		if err != nil {
			return fmt.Errorf("Write error: %v", err)
		}
		if n != size {
			return fmt.Errorf("wrong size %d from Write", n)
		}
		return nil
	}, func(st *hertzServerTester) {
		// Set the window size to something explicit for this test.
		// It's also how much initial data we expect.
		if err := st.fr.WriteSettings(Setting{SettingInitialWindowSize, uint32(reads[0])}); err != nil {
			t.Fatal(err)
		}
		st.wantSettingsAck()

		getSlash(st) // make the single request

		hf := st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("unexpected END_STREAM flag")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}

		df := st.wantData()
		if got := len(df.Data()); got != reads[0] {
			t.Fatalf("Initial window size = %d but got DATA with %d bytes", reads[0], got)
		}

		for _, quota := range reads[1:] {
			if err := st.fr.WriteWindowUpdate(1, uint32(quota)); err != nil {
				t.Fatal(err)
			}
			df := st.wantData()
			if int(quota) != len(df.Data()) {
				t.Fatalf("read %d bytes after giving %d quota", len(df.Data()), quota)
			}
		}
	})
}

func TestServer_Response_Automatic100Continue(t *testing.T) {
	const msg = "foo"
	const reply = "bar"
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		if v := ctx.Request.Header.Get("Expect"); v != "" {
			t.Errorf("Expect header = %q; want empty", v)
		}
		buf := make([]byte, len(msg))
		// This read should trigger the 100-continue being sent.
		if n, err := io.ReadFull(ctx.Request.BodyStream(), buf); err != nil || n != len(msg) || string(buf) != msg {
			return fmt.Errorf("ReadFull = %q, %v; want %q, nil", buf[:n], err, msg)
		}
		_, err := ctx.WriteString(reply)
		return err
	}, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader(":method", "POST", "expect", "100-continue"),
			EndStream:     false,
			EndHeaders:    true,
		})
		hf := st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("unexpected END_STREAM flag")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "100"},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Fatalf("Got headers %v; want %v", goth, wanth)
		}

		// Okay, they sent status 100, so we can send our
		// gigantic and/or sensitive "foo" payload now.
		st.writeData(1, true, []byte(msg))

		st.wantWindowUpdate(0, uint32(len(msg)))

		hf = st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("expected data to follow")
		}
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}
		goth = st.decodeHeader(hf.HeaderBlockFragment())
		wanth = [][2]string{
			{":status", "200"},
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", strconv.Itoa(len(reply))},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Got headers %v; want %v", goth, wanth)
		}

		df := st.wantData()
		if string(df.Data()) != reply {
			t.Errorf("Client read %q; want %q", df.Data(), reply)
		}
		if !df.StreamEnded() {
			t.Errorf("expect data stream end")
		}
	})
}

func TestServer_Rejects_Too_Many_Streams(t *testing.T) {
	const testPath = "/some/path"

	inHandler := make(chan uint32)
	leaveHandler := make(chan bool)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		id := ctx.Request.BodyStream().(*requestBody).stream.id
		inHandler <- id
		if id == 1+(defaultMaxStreams+1)*2 && string(ctx.Request.URI().Path()) != testPath {
			t.Errorf("decoded final path as %q; want %q", string(ctx.Request.URI().Path()), testPath)
		}
		<-leaveHandler
	})
	defer st.Close()
	st.greet()
	nextStreamID := uint32(1)
	streamID := func() uint32 {
		defer func() { nextStreamID += 2 }()
		return nextStreamID
	}
	sendReq := func(id uint32, headers ...string) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      id,
			BlockFragment: st.encodeHeader(headers...),
			EndStream:     true,
			EndHeaders:    true,
		})
	}
	for i := 0; i < defaultMaxStreams; i++ {
		sendReq(streamID())
		<-inHandler
	}
	defer func() {
		for i := 0; i < defaultMaxStreams; i++ {
			leaveHandler <- true
		}
	}()

	// And this one should cross the limit:
	// (It's also sent as a CONTINUATION, to verify we still track the decoder context,
	// even if we're rejecting it)
	rejectID := streamID()
	headerBlock := st.encodeHeader(":path", testPath)
	frag1, frag2 := headerBlock[:3], headerBlock[3:]
	st.writeHeaders(HeadersFrameParam{
		StreamID:      rejectID,
		BlockFragment: frag1,
		EndStream:     true,
		EndHeaders:    false, // CONTINUATION coming
	})
	if err := st.fr.WriteContinuation(rejectID, true, frag2); err != nil {
		t.Fatal(err)
	}
	st.wantRSTStream(rejectID, ErrCodeProtocol)

	// But let a handler finish:
	leaveHandler <- true
	st.wantHeaders()

	// And now another stream should be able to start:
	goodID := streamID()
	sendReq(goodID, ":path", testPath)
	if got := <-inHandler; got != goodID {
		t.Errorf("Got stream %d; want %d", got, goodID)
	}
}

// So many response headers that the server needs to use CONTINUATION frames:
func TestServer_Response_ManyHeaders_With_Continuation(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		for i := 0; i < 5000; i++ {
			ctx.Response.Header.Set(fmt.Sprintf("x-header-%d", i), fmt.Sprintf("x-value-%d", i))
		}
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if hf.HeadersEnded() {
			t.Fatal("got unwanted END_HEADERS flag")
		}
		n := 0
		for {
			n++
			cf := st.wantContinuation()
			if cf.HeadersEnded() {
				break
			}
		}
		if n < 5 {
			t.Errorf("Only got %d CONTINUATION frames; expected 5+ (currently 6)", n)
		}
	})
}

// This previously crashed (reported by Mathieu Lonjaret as observed
// while using Camlistore) because we got a DATA frame from the client
// after the handler exited and our logic at the time was wrong,
// keeping a stream in the map in stateClosed, which tickled an
// invariant check later when we tried to remove that stream (via
// defer sc.closeAllStreamsOnConnClose) when the serverConn serve loop
// ended.
func TestServer_NoCrash_HandlerClose_Then_ClientClose(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		// nothing
		return nil
	}, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     false, // DATA is coming
			EndHeaders:    true,
		})
		hf := st.wantHeaders()
		if !hf.HeadersEnded() || !hf.StreamEnded() {
			t.Fatalf("want END_HEADERS+END_STREAM, got %v", hf)
		}

		// Sent when the a Handler closes while a client has
		// indicated it's still sending DATA:
		st.wantRSTStream(1, ErrCodeNo)

		// Now the handler has ended, so it's ended its
		// stream, but the client hasn't closed its side
		// (stateClosedLocal).  So send more data and verify
		// it doesn't crash with an internal invariant panic, like
		// it did before.
		st.writeData(1, true, []byte("foo"))

		// Get our flow control bytes back, since the handler didn't get them.
		st.wantWindowUpdate(0, uint32(len("foo")))

		// Sent after a peer sends data anyway (admittedly the
		// previous RST_STREAM might've still been in-flight),
		// but they'll get the more friendly 'cancel' code
		// first.
		st.wantRSTStream(1, ErrCodeStreamClosed)

		// Set up a bunch of machinery to record the panic we saw
		// previously.
		var (
			panMu    sync.Mutex
			panicVal interface{}
		)

		testHookOnPanicMu.Lock()
		testHookOnPanic = func(sc *serverConn, pv interface{}) bool {
			panMu.Lock()
			panicVal = pv
			panMu.Unlock()
			return true
		}
		testHookOnPanicMu.Unlock()

		// Now force the serve loop to end, via closing the connection.
		st.cc.Close()
		<-st.sc.doneServing

		panMu.Lock()
		got := panicVal
		panMu.Unlock()
		if got != nil {
			t.Errorf("Got panic: %v", got)
		}
	})
}

func (st *hertzServerTester) onHeaderField(f hpack.HeaderField) {
	if f.Name == "date" {
		return
	}
	st.decodedHeaders = append(st.decodedHeaders, [2]string{f.Name, f.Value})
}

func (st *hertzServerTester) decodeHeader(headerBlock []byte) (pairs [][2]string) {
	st.decodedHeaders = nil
	if _, err := st.hpackDec.Write(headerBlock); err != nil {
		st.t.Fatalf("hpack decoding error: %v", err)
	}
	if err := st.hpackDec.Close(); err != nil {
		st.t.Fatalf("hpack decoding error: %v", err)
	}
	return st.decodedHeaders
}

// testServerResponse sets up an idle HTTP/2 connection. The client function should
// write a single request that must be handled by the handler.
func testServerResponse(t testing.TB,
	handler func(c context.Context, ctx *app.RequestContext) error,
	client func(*hertzServerTester),
) {
	errc := make(chan error, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		if ctx.Request.BodyStream() == nil {
			t.Fatal("nil Body")
		}
		err := handler(c, ctx)
		select {
		case errc <- err:
		default:
			t.Errorf("unexpected duplicate request")
		}
	})
	defer st.Close()

	st.greet()
	client(st)

	if err := <-errc; err != nil {
		t.Fatalf("Error in handler: %v", err)
	}
}

// readBodyHandler returns an http Handler func that reads len(want)
// bytes from r.Body and fails t if the contents read were not
// the value of want.
func readBodyHandler(t *testing.T, want string) func(c context.Context, ctx *app.RequestContext) {
	return func(c context.Context, ctx *app.RequestContext) {
		buf := make([]byte, len(want))
		_, err := io.ReadFull(ctx.Request.BodyStream(), buf)
		if err != nil {
			t.Error(err)
			return
		}
		if string(buf) != want {
			t.Errorf("read %q; want %q", buf, want)
		}
	}
}

// Issue 12843
func TestServerDoS_MaxHeaderListSize(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {})
	defer st.Close()

	// shake hands
	frameSize := defaultMaxReadFrameSize
	var advHeaderListSize *uint32
	st.greetAndCheckSettings(func(s Setting) error {
		switch s.ID {
		case SettingMaxFrameSize:
			if s.Val < minMaxFrameSize {
				frameSize = minMaxFrameSize
			} else if s.Val > maxFrameSize {
				frameSize = maxFrameSize
			} else {
				frameSize = int(s.Val)
			}
		case SettingMaxHeaderListSize:
			advHeaderListSize = &s.Val
		}
		return nil
	})

	if advHeaderListSize == nil {
		t.Errorf("server didn't advertise a max header list size")
	} else if *advHeaderListSize == 0 {
		t.Errorf("server advertised a max header list size of 0")
	}

	st.encodeHeaderField(":method", "GET")
	st.encodeHeaderField(":path", "/")
	st.encodeHeaderField(":scheme", "https")
	cookie := strings.Repeat("*", 4058)
	st.encodeHeaderField("cookie", cookie)
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.headerBuf.Bytes(),
		EndStream:     true,
		EndHeaders:    false,
	})

	// Capture the short encoding of a duplicate ~4K cookie, now
	// that we've already sent it once.
	st.headerBuf.Reset()
	st.encodeHeaderField("cookie", cookie)

	// Now send 1MB of it.
	const size = 1 << 20
	b := bytes.Repeat(st.headerBuf.Bytes(), size/st.headerBuf.Len())
	for len(b) > 0 {
		chunk := b
		if len(chunk) > frameSize {
			chunk = chunk[:frameSize]
		}
		b = b[len(chunk):]
		st.fr.WriteContinuation(1, len(b) == 0, chunk)
	}

	h := st.wantHeaders()
	if !h.HeadersEnded() {
		t.Fatalf("Got HEADERS without END_HEADERS set: %v", h)
	}
	headers := st.decodeHeader(h.HeaderBlockFragment())
	want := [][2]string{
		{":status", "431"},
		{"content-type", "text/plain; charset=utf-8"},
		{"content-length", "63"},
	}
	if !reflect.DeepEqual(headers, want) {
		t.Errorf("Headers mismatch.\n got: %q\nwant: %q\n", headers, want)
	}
}

func TestCompressionErrorOnWrite(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		// No response body.
	})
	st.addLogFilter("connection error: COMPRESSION_ERROR")
	defer st.Close()
	st.greet()

	maxAllowed := st.sc.framer.maxHeaderStringLen()

	// Crank this up, now that we have a conn connected with the
	// hpack.Decoder's max string length set has been initialized
	// from the earlier low ~8K value. We want this higher so don't
	// hit the max header list size. We only want to test hitting
	// the max string size.

	// First a request with a header that's exactly the max allowed size
	// for the hpack compression. It's still too long for the header list
	// size, so we'll get the 431 error, but that keeps the compression
	// context still valid.
	hbf := st.encodeHeader("foo", strings.Repeat("a", maxAllowed))

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbf,
		EndStream:     true,
		EndHeaders:    true,
	})
	h := st.wantHeaders()
	if !h.HeadersEnded() {
		t.Fatalf("Got HEADERS without END_HEADERS set: %v", h)
	}
	headers := st.decodeHeader(h.HeaderBlockFragment())
	want := [][2]string{
		{":status", "431"},
		{"content-type", "text/plain; charset=utf-8"},
		{"content-length", "63"},
	}
	if !reflect.DeepEqual(headers, want) {
		t.Errorf("Headers mismatch.\n got: %q\nwant: %q\n", headers, want)
	}
	df := st.wantData()
	if !strings.Contains(string(df.Data()), "HTTP Error 431") {
		t.Errorf("Unexpected data body: %q", df.Data())
	}
	if !df.StreamEnded() {
		t.Fatalf("expect data stream end")
	}

	// And now send one that's just one byte too big.
	hbf = st.encodeHeader("bar", strings.Repeat("b", maxAllowed+1))
	st.writeHeaders(HeadersFrameParam{
		StreamID:      3,
		BlockFragment: hbf,
		EndStream:     true,
		EndHeaders:    true,
	})
	ga := st.wantGoAway()
	if ga.ErrCode != ErrCodeCompression {
		t.Errorf("GOAWAY err = %v; want ErrCodeCompression", ga.ErrCode)
	}
}

func TestCompressionErrorOnClose(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		// No response body.
	})
	st.addLogFilter("connection error: COMPRESSION_ERROR")
	defer st.Close()
	st.greet()

	hbf := st.encodeHeader("foo", "bar")
	hbf = hbf[:len(hbf)-1] // truncate one byte from the end, so hpack.Decoder.Close fails.
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbf,
		EndStream:     true,
		EndHeaders:    true,
	})
	ga := st.wantGoAway()
	if ga.ErrCode != ErrCodeCompression {
		t.Errorf("GOAWAY err = %v; want ErrCodeCompression", ga.ErrCode)
	}
}

// test that a server handler can read trailers from a client
func TestServerReadsTrailers(t *testing.T) {
	const testBody = "some test body"
	writeReq := func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader("trailer", "Foo, Bar, Baz"),
			EndStream:     false,
			EndHeaders:    true,
		})
		st.writeData(1, false, []byte(testBody))
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1, // clients send odd numbers
			BlockFragment: st.encodeHeaderRaw(
				"foo", "foov",
				"bar", "barv",
				"baz", "bazv",
				"surprise", "wasn't declared; shouldn't show up",
			),
			EndStream:  true,
			EndHeaders: true,
		})
	}
	checkReq := func(ctx *app.RequestContext) {
		wantTrailer := http.Header{
			"Foo": nil,
			"Bar": nil,
			"Baz": nil,
		}
		for k, v := range wantTrailer {
			actualKey := ctx.Request.Header.Trailer().Get(k)
			if actualKey != "" {
				t.Errorf("initial Trailer %q = %q; want %q", k, actualKey, v)
			}
		}
		slurp, err := ioutil.ReadAll(ctx.Request.BodyStream())
		if string(slurp) != testBody {
			t.Errorf("read body %q; want %q", slurp, testBody)
		}
		if err != nil {
			t.Fatalf("Body slurp: %v", err)
		}
		wantTrailerAfter := http.Header{
			"Foo": {"foov"},
			"Bar": {"barv"},
			"Baz": {"bazv"},
		}
		for k, v := range wantTrailerAfter {
			actualKey := ctx.Request.Header.Trailer().Get(k)
			if actualKey != v[0] {
				t.Errorf("final Trailer %q = %q; want %q", k, actualKey, v)
			}
		}
	}
	testServerRequest(t, writeReq, checkReq)
}

// test that a server handler can send trailers
func TestServerWritesTrailers(t *testing.T) {
	// See https://httpwg.github.io/specs/rfc7540.html#rfc.section.8.1.3
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		// Regular headers:
		ctx.Response.Header.Set("Foo", "Bar")
		ctx.Response.Header.Set("Content-Length", "5") // len("Hello")

		ctx.WriteString("Hello")

		ctx.Response.Header.Trailer().Set("Server-Trailer-A", "valuea")
		ctx.Response.Header.Trailer().Set("Server-Trailer-C", "valuec") // skipping B
		ctx.Response.Header.Trailer().Set("Post-Header-Trailer", "hi1")
		ctx.Response.Header.Trailer().Set("post-header-trailer2", "hi2")
		ctx.Response.Header.Trailer().Set("Range", "invalid")
		ctx.Response.Header.Trailer().Set("Foo\x01Bogus", "invalid")
		ctx.Response.Header.Trailer().Set("Transfer-Encoding", "should not be included; Forbidden by RFC 7230 4.1.2")
		ctx.Response.Header.Trailer().Set("Content-Length", "should not be included; Forbidden by RFC 7230 4.1.2")
		ctx.Response.Header.Trailer().Set("Trailer", "should not be included; Forbidden by RFC 7230 4.1.2")
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if hf.StreamEnded() {
			t.Fatal("response HEADERS had END_STREAM")
		}
		if !hf.HeadersEnded() {
			t.Fatal("response HEADERS didn't have END_HEADERS")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"trailer", "Server-Trailer-A, Server-Trailer-C, Post-Header-Trailer, Post-Header-Trailer2, Foo\u0001bogus"},
			{"foo", "Bar"},
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", "5"},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Header mismatch.\n got: %v\nwant: %v", goth, wanth)
		}
		df := st.wantData()
		if string(df.Data()) != "Hello" {
			t.Fatalf("Client read %q; want Hello", df.Data())
		}
		if df.StreamEnded() {
			t.Fatalf("data frame had STREAM_ENDED")
		}
		tf := st.wantHeaders() // for the trailers
		if !tf.StreamEnded() {
			t.Fatalf("trailers HEADERS lacked END_STREAM")
		}
		if !tf.HeadersEnded() {
			t.Fatalf("trailers HEADERS lacked END_HEADERS")
		}
		wanth = [][2]string{
			{"server-trailer-a", "valuea"},
			{"server-trailer-c", "valuec"},
			{"post-header-trailer", "hi1"},
			{"post-header-trailer2", "hi2"},
		}
		goth = st.decodeHeader(tf.HeaderBlockFragment())
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Header mismatch.\n got: %v\nwant: %v", goth, wanth)
		}
	})
}

// validate transmitted header field names & values
// golang.org/issue/14048
func TestServerDoesntWriteInvalidHeaders(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ctx.Response.Header.Add("OK1", "x")
		ctx.Response.Header.Add("Bad:Colon", "x") // colon (non-token byte) in key
		ctx.Response.Header.Add("Bad1\x00", "x")  // null in key
		// ctx.Response.Header.Add("Bad2", "x\x00y") // null in value
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if !hf.StreamEnded() {
			t.Error("response HEADERS lacked END_STREAM")
		}
		if !hf.HeadersEnded() {
			t.Fatal("response HEADERS didn't have END_HEADERS")
		}
		goth := st.decodeHeader(hf.HeaderBlockFragment())
		wanth := [][2]string{
			{":status", "200"},
			{"ok1", "x"},
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", "0"},
		}
		if !reflect.DeepEqual(goth, wanth) {
			t.Errorf("Header mismatch.\n got: %v\nwant: %v", goth, wanth)
		}
	})
}

func BenchmarkServerGets(b *testing.B) {
	defer disableGoroutineTracking()()
	b.ReportAllocs()

	const msg = "Hello, world"
	st := newHertzServerTester(b, func(c context.Context, ctx *app.RequestContext) {
		ctx.WriteString(msg)
	})
	defer st.Close()
	st.greet()

	// Give the server quota to reply. (plus it has the 64KB)
	if err := st.fr.WriteWindowUpdate(0, uint32(b.N*len(msg))); err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		id := 1 + uint32(i)*2
		st.writeHeaders(HeadersFrameParam{
			StreamID:      id,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
		})
		st.wantHeaders()
		df := st.wantData()
		if !df.StreamEnded() {
			b.Fatalf("DATA didn't have END_STREAM; got %v", df)
		}
	}
}

func BenchmarkServerPosts(b *testing.B) {
	defer disableGoroutineTracking()()
	b.ReportAllocs()

	const msg = "Hello, world"
	st := newHertzServerTester(b, func(c context.Context, ctx *app.RequestContext) {
		// Consume the (empty) body from th peer before replying, otherwise
		// the server will sometimes (depending on scheduling) send the peer a
		// a RST_STREAM with the CANCEL error code.
		if n, err := io.Copy(ioutil.Discard, ctx.Request.BodyStream()); n != 0 || err != nil {
			b.Errorf("Copy error; got %v, %v; want 0, nil", n, err)
		}
		ctx.WriteString(msg)
	})
	defer st.Close()
	st.greet()

	// Give the server quota to reply. (plus it has the 64KB)
	if err := st.fr.WriteWindowUpdate(0, uint32(b.N*len(msg))); err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		id := 1 + uint32(i)*2
		st.writeHeaders(HeadersFrameParam{
			StreamID:      id,
			BlockFragment: st.encodeHeader(":method", "POST"),
			EndStream:     false,
			EndHeaders:    true,
		})
		st.writeData(id, true, nil)
		st.wantHeaders()
		df := st.wantData()
		if !df.StreamEnded() {
			b.Fatalf("DATA didn't have END_STREAM; got %v", df)
		}
	}
}

// Send a stream of messages from server to client in separate data frames.
// Brings up performance issues seen in long streams.
// Created to show problem in go issue #18502
func BenchmarkServerToClientStreamDefaultOptions(b *testing.B) {
	benchmarkServerToClientStream(b)
}

// Justification for Change-Id: Iad93420ef6c3918f54249d867098f1dadfa324d8
// Expect to see memory/alloc reduction by opting in to Frame reuse with the Framer.
func BenchmarkServerToClientStreamReuseFrames(b *testing.B) {
	benchmarkServerToClientStream(b, optFramerReuseFrames)
}

func benchmarkServerToClientStream(b *testing.B, newServerOpts ...interface{}) {
	defer disableGoroutineTracking()()
	b.ReportAllocs()
	const msgLen = 1
	// default window size
	const windowSize = 1<<16 - 1

	// next message to send from the server and for the client to expect
	nextMsg := func(i int) []byte {
		msg := make([]byte, msgLen)
		msg[0] = byte(i)
		if len(msg) != msgLen {
			panic("invalid test setup msg length")
		}
		return msg
	}

	st := newHertzServerTester(b, func(c context.Context, ctx *app.RequestContext) {
		// Consume the (empty) body from th peer before replying, otherwise
		// the server will sometimes (depending on scheduling) send the peer a
		// a RST_STREAM with the CANCEL error code.
		if n, err := io.Copy(ioutil.Discard, ctx.Response.BodyStream()); n != 0 || err != nil {
			b.Errorf("Copy error; got %v, %v; want 0, nil", n, err)
		}
		for i := 0; i < b.N; i += 1 {
			ctx.Write(nextMsg(i))
			// w.(http.Flusher).Flush()
		}
	}, newServerOpts...)
	defer st.Close()
	st.greet()

	const id = uint32(1)

	st.writeHeaders(HeadersFrameParam{
		StreamID:      id,
		BlockFragment: st.encodeHeader(":method", "POST"),
		EndStream:     false,
		EndHeaders:    true,
	})

	st.writeData(id, true, nil)
	st.wantHeaders()

	pendingWindowUpdate := uint32(0)

	for i := 0; i < b.N; i += 1 {
		expected := nextMsg(i)
		df := st.wantData()
		if !bytes.Equal(expected, df.data) {
			b.Fatalf("Bad message received; want %v; got %v", expected, df.data)
		}
		// try to send infrequent but large window updates so they don't overwhelm the test
		pendingWindowUpdate += uint32(len(df.data))
		if pendingWindowUpdate >= windowSize/2 {
			if err := st.fr.WriteWindowUpdate(0, pendingWindowUpdate); err != nil {
				b.Fatal(err)
			}
			if err := st.fr.WriteWindowUpdate(id, pendingWindowUpdate); err != nil {
				b.Fatal(err)
			}
			pendingWindowUpdate = 0
		}
	}
	df := st.wantData()
	if !df.StreamEnded() {
		b.Fatalf("DATA didn't have END_STREAM; got %v", df)
	}
}

func TestServerNoAutoContentLengthOnHead(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		// No response body. (or smaller than one frame)
	})
	defer st.Close()
	st.greet()
	st.writeHeaders(HeadersFrameParam{
		StreamID:      1, // clients send odd numbers
		BlockFragment: st.encodeHeader(":method", "HEAD"),
		EndStream:     true,
		EndHeaders:    true,
	})
	h := st.wantHeaders()
	headers := st.decodeHeader(h.HeaderBlockFragment())
	want := [][2]string{
		{":status", "200"},
		{"content-type", "text/plain; charset=utf-8"},
	}
	if !reflect.DeepEqual(headers, want) {
		t.Errorf("Headers mismatch.\n got: %q\nwant: %q\n", headers, want)
	}
}

func disableGoroutineTracking() (restore func()) {
	old := DebugGoroutines
	DebugGoroutines = false
	return func() { DebugGoroutines = old }
}

func BenchmarkServer_GetRequest(b *testing.B) {
	defer disableGoroutineTracking()()
	b.ReportAllocs()
	const msg = "Hello, world."
	st := newHertzServerTester(b, func(c context.Context, ctx *app.RequestContext) {
		n, err := io.Copy(ioutil.Discard, ctx.Request.BodyStream())
		if err != nil || n > 0 {
			b.Errorf("Read %d bytes, error %v; want 0 bytes.", n, err)
		}
		ctx.WriteString(msg)
	})
	defer st.Close()

	st.greet()
	// Give the server quota to reply. (plus it has the 64KB)
	if err := st.fr.WriteWindowUpdate(0, uint32(b.N*len(msg))); err != nil {
		b.Fatal(err)
	}
	hbf := st.encodeHeader(":method", "GET")
	for i := 0; i < b.N; i++ {
		streamID := uint32(1 + 2*i)
		st.writeHeaders(HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbf,
			EndStream:     true,
			EndHeaders:    true,
		})
		st.wantHeaders()
		st.wantData()
	}
}

func BenchmarkServer_PostRequest(b *testing.B) {
	defer disableGoroutineTracking()()
	b.ReportAllocs()
	const msg = "Hello, world."
	st := newHertzServerTester(b, func(c context.Context, ctx *app.RequestContext) {
		n, err := io.Copy(ioutil.Discard, ctx.Request.BodyStream())
		if err != nil || n > 0 {
			b.Errorf("Read %d bytes, error %v; want 0 bytes.", n, err)
		}
		ctx.WriteString(msg)
	})
	defer st.Close()
	st.greet()
	// Give the server quota to reply. (plus it has the 64KB)
	if err := st.fr.WriteWindowUpdate(0, uint32(b.N*len(msg))); err != nil {
		b.Fatal(err)
	}
	hbf := st.encodeHeader(":method", "POST")
	for i := 0; i < b.N; i++ {
		streamID := uint32(1 + 2*i)
		st.writeHeaders(HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbf,
			EndStream:     false,
			EndHeaders:    true,
		})
		st.writeData(streamID, true, nil)
		st.wantHeaders()
		st.wantData()
	}
}

// golang.org/issue/14214
func TestServer_Rejects_ConnHeaders(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		t.Error("should not get to Handler")
	})
	defer st.Close()
	st.greet()
	st.bodylessReq1("connection", "foo")
	hf := st.wantHeaders()
	goth := st.decodeHeader(hf.HeaderBlockFragment())
	wanth := [][2]string{
		{":status", "400"},
		{"content-type", "text/plain; charset=utf-8"},
		{"content-length", "50"},
	}
	if !reflect.DeepEqual(goth, wanth) {
		t.Errorf("Got headers %v; want %v", goth, wanth)
	}
}

type hpackEncoder struct {
	enc *hpack.Encoder
	buf bytes.Buffer
}

func (he *hpackEncoder) encodeHeaderRaw(t *testing.T, headers ...string) []byte {
	if len(headers)%2 == 1 {
		panic("odd number of kv args")
	}
	he.buf.Reset()
	if he.enc == nil {
		he.enc = hpack.NewEncoder(&he.buf)
	}
	for len(headers) > 0 {
		k, v := headers[0], headers[1]
		err := he.enc.WriteField(hpack.HeaderField{Name: k, Value: v})
		if err != nil {
			t.Fatalf("HPACK encoding error for %q/%q: %v", k, v, err)
		}
		headers = headers[2:]
	}
	return he.buf.Bytes()
}

func TestCheckValidHTTP2Request(t *testing.T) {
	tests := []struct {
		h    [][2]string
		want error
	}{
		{
			h: [][2]string{
				{"Te", "trailers"},
			},
			want: nil,
		},
		{
			h: [][2]string{
				{"Te", "begos"},
			},
			want: errors.New(`request header "TE" may only be "trailers" in HTTP/2`),
		},
		{
			h: [][2]string{
				{"Foo", ""},
			},
			want: nil,
		},
		{
			h: [][2]string{
				{"Connection", "1"},
			},
			want: errors.New(`request header "Connection" is not valid in HTTP/2`),
		},
		{
			h: [][2]string{
				{"Proxy-Connection", "2"},
			},
			want: errors.New(`request header "Proxy-Connection" is not valid in HTTP/2`),
		},
		{
			h: [][2]string{
				{"Keep-Alive", "3"},
			},
			want: errors.New(`request header "Keep-Alive" is not valid in HTTP/2`),
		},
		{
			h: [][2]string{
				{"Upgrade", "4"},
			},
			want: errors.New(`request header "Upgrade" is not valid in HTTP/2`),
		},
	}
	for i, tt := range tests {
		header := &protocol.RequestHeader{}
		for _, vv := range tt.h {
			header.Add(vv[0], vv[1])
		}
		got := checkValidHTTP2RequestHeaders(header)
		if !equalError(got, tt.want) {
			t.Errorf("%d. checkValidHTTP2Request = %v; want %v", i, got, tt.want)
		}
	}
}

type funcReader func([]byte) (n int, err error)

func (f funcReader) Read(p []byte) (n int, err error) { return f(p) }

// golang.org/issue/16481 -- return flow control when streams close with unread data.
// (The Server version of the bug. See also TestUnreadFlowControlReturned_Transport)
func TestUnreadFlowControlReturned_Server(t *testing.T) {
	for _, tt := range []struct {
		name  string
		reqFn func(ctx *app.RequestContext)
	}{
		{
			"body-open",
			func(ctx *app.RequestContext) {},
		},
		{
			"body-closed",
			func(ctx *app.RequestContext) {
				ctx.Request.BodyStream().(io.Closer).Close()
			},
		},
		{
			"read-1-byte-and-close",
			func(ctx *app.RequestContext) {
				b := make([]byte, 1)
				ctx.Request.BodyStream().Read(b)
				ctx.Request.BodyStream().(io.Closer).Close()
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			unblock := make(chan bool, 1)
			defer close(unblock)

			st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
				// Don't read the 16KB request body. Wait until the client's
				// done sending it and then return. This should cause the Server
				// to then return those 16KB of flow control to the client.
				tt.reqFn(ctx)
				<-unblock
			}, optOnlyServer)
			defer st.Close()

			u, err := url.Parse("https://" + st.url)
			if err != nil {
				t.Fatal(err)
			}
			tr := &HostClient{
				ClientConfig: &config.ClientConfig{
					TLSConfig:        tlsConfigInsecure,
					DisableKeepAlive: false,
					Dialer:           standard.NewDialer(),
				},
				IsTLS: true,
				Addr:  u.Host,
			}
			defer tr.CloseIdleConnections()

			// This previously hung on the 4th iteration.
			iters := 100
			if testing.Short() {
				iters = 20
			}
			for i := 0; i < iters; i++ {
				body := io.MultiReader(
					io.LimitReader(neverEnding('A'), 16<<10),
					funcReader(func([]byte) (n int, err error) {
						unblock <- true
						return 0, io.EOF
					}),
				)
				req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
				req.SetMethod("POST")
				req.SetRequestURI(u.String())
				req.SetBodyStream(body, -1)
				err = tr.Do(context.Background(), req, rsp)
				if err != nil {
					t.Fatal(tt.name, err)
				}
				rsp.BodyStream().(io.Closer).Close()
			}
		})
	}
}

func TestServerIdleTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	},
		config.WithIdleTimeout(500*time.Millisecond),
	)
	defer st.Close()

	st.greet()
	ga := st.wantGoAway()
	if ga.ErrCode != ErrCodeNo {
		t.Errorf("GOAWAY error = %v; want ErrCodeNo", ga.ErrCode)
	}
}

func TestServerIdleTimeout_AfterRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	const timeout = 250 * time.Millisecond

	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		time.Sleep(timeout * 2)
	},
		config.WithIdleTimeout(timeout),
	)
	defer st.Close()

	st.greet()

	// Send a request which takes twice the timeout. Verifies the
	// idle timeout doesn't fire while we're in a request:
	st.bodylessReq1()
	st.wantHeaders()

	// But the idle timeout should be rearmed after the request
	// is done:
	ga := st.wantGoAway()
	if ga.ErrCode != ErrCodeNo {
		t.Errorf("GOAWAY error = %v; want ErrCodeNo", ga.ErrCode)
	}
}

// grpc-go closes the Request.Body currently with a Read.
// Verify that it doesn't race.
// See https://github.com/grpc/grpc-go/pull/938
func TestRequestBodyReadCloseRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		body := &requestBody{
			pipe: &pipe{
				b: new(bytes.Buffer),
			},
		}
		body.pipe.CloseWithError(io.EOF)

		done := make(chan bool, 1)
		buf := make([]byte, 10)
		go func() {
			time.Sleep(1 * time.Millisecond)
			body.Close()
			done <- true
		}()
		body.Read(buf)
		<-done
	}
}

func TestIssue20704Race(t *testing.T) {
	if testing.Short() && os.Getenv("GO_BUILDER_NAME") == "" {
		t.Skip("skipping in short mode")
	}
	const (
		itemSize  = 1 << 10
		itemCount = 100
	)

	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		for i := 0; i < itemCount; i++ {
			_, err := ctx.Write(make([]byte, itemSize))
			if err != nil {
				return
			}
		}
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig:        tlsConfigInsecure,
			DisableKeepAlive: false,
			Dialer:           standard.NewDialer(),
		},
		IsTLS: true,
		Addr:  u.Host,
	}
	defer tr.CloseIdleConnections()

	for i := 0; i < 1000; i++ {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatal(err)
		}
		// Force a RST stream to the server by closing without
		// reading the body:
		rsp.BodyStream().(io.Closer).Close()
	}
}

func TestServer_Rejects_TooSmall(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ioutil.ReadAll(ctx.Request.BodyStream())
		return nil
	}, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID: 1, // clients send odd numbers
			BlockFragment: st.encodeHeader(
				":method", "POST",
				"content-length", "4",
			),
			EndStream:  false, // to say DATA frames are coming
			EndHeaders: true,
		})
		st.writeData(1, true, []byte("12345"))
		// st.wantWindowUpdate(0, 5)
		st.wantRSTStream(1, ErrCodeProtocol)
	})
}

// Tests that a handler setting "Connection: close" results in a GOAWAY being sent,
// and the connection still completing.
func TestServerHandlerConnectionClose(t *testing.T) {
	unblockHandler := make(chan bool, 1)
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		ctx.Response.Header.Set("Connection", "close")
		ctx.Response.Header.Set("Foo", "bar")
		// w.(http.Flusher).Flush()
		return nil
	}, func(st *hertzServerTester) {
		defer close(unblockHandler) // backup; in case of errors
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1,
			BlockFragment: st.encodeHeader(),
			EndStream:     true,
			EndHeaders:    true,
		})
		var sawGoAway bool
		var sawRes bool
		for {
			f, err := st.readFrame()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			switch f := f.(type) {
			case *GoAwayFrame:
				sawGoAway = true
				if f.LastStreamID != 1 || f.ErrCode != ErrCodeNo {
					t.Errorf("unexpected GOAWAY frame: %v", summarizeFrame(f))
				}
				// Create a stream and reset it.
				// The server should ignore the stream.
				st.writeHeaders(HeadersFrameParam{
					StreamID:      3,
					BlockFragment: st.encodeHeader(),
					EndStream:     false,
					EndHeaders:    true,
				})
				st.fr.WriteRSTStream(3, ErrCodeCancel)
				// Create a stream and send data to it.
				// The server should return flow control, even though it
				// does not process the stream.
				st.writeHeaders(HeadersFrameParam{
					StreamID:      5,
					BlockFragment: st.encodeHeader(),
					EndStream:     false,
					EndHeaders:    true,
				})
				// Write enough data to trigger a window update.
				st.writeData(5, true, make([]byte, 1<<19))
			case *HeadersFrame:
				goth := st.decodeHeader(f.HeaderBlockFragment())
				wanth := [][2]string{
					{":status", "200"},
					{"foo", "bar"},
					{"content-type", "text/plain; charset=utf-8"},
					{"content-length", "0"},
				}
				if !reflect.DeepEqual(goth, wanth) {
					t.Errorf("got headers %v; want %v", goth, wanth)
				}
				sawRes = true
			case *DataFrame:
				if f.StreamID != 1 || !f.StreamEnded() || len(f.Data()) != 0 {
					t.Errorf("unexpected DATA frame: %v", summarizeFrame(f))
				}
			case *WindowUpdateFrame:
				if !sawGoAway {
					t.Errorf("unexpected WINDOW_UPDATE frame: %v", summarizeFrame(f))
					return
				}
				if f.StreamID != 0 {
					st.t.Fatalf("WindowUpdate StreamID = %d; want 5", f.FrameHeader.StreamID)
					return
				}
				unblockHandler <- true
			default:
				t.Logf("unexpected frame: %v", summarizeFrame(f))
			}
		}
		if !sawGoAway {
			t.Errorf("didn't see GOAWAY")
		}
		if !sawRes {
			t.Errorf("didn't see response")
		}
	})
}

func TestServer_Headers_HalfCloseRemote(t *testing.T) {
	var st *hertzServerTester
	writeData := make(chan bool)
	writeHeaders := make(chan bool)
	leaveHandler := make(chan bool)
	st = newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		if st.stream(1) == nil {
			t.Errorf("nil stream 1 in handler")
		}
		if got, want := st.streamState(1), stateOpen; got != want {
			t.Errorf("in handler, state is %v; want %v", got, want)
		}
		writeData <- true
		if n, err := ctx.Request.BodyStream().Read(make([]byte, 1)); n != 0 || err != io.EOF {
			t.Errorf("body read = %d, %v; want 0, EOF", n, err)
		}
		if got, want := st.streamState(1), stateHalfClosedRemote; got != want {
			t.Errorf("in handler, state is %v; want %v", got, want)
		}
		writeHeaders <- true

		<-leaveHandler
	})
	st.greet()

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(),
		EndStream:     false, // keep it open
		EndHeaders:    true,
	})
	<-writeData
	st.writeData(1, true, nil)

	<-writeHeaders

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(),
		EndStream:     false, // keep it open
		EndHeaders:    true,
	})

	defer close(leaveHandler)

	st.wantRSTStream(1, ErrCodeStreamClosed)
}

func TestServerWindowUpdateOnBodyClose(t *testing.T) {
	const content = "12345678"
	blockCh := make(chan bool)
	errc := make(chan error, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		buf := make([]byte, 4)
		n, err := io.ReadFull(ctx.Request.BodyStream(), buf)
		if err != nil {
			errc <- err
			return
		}
		if n != len(buf) {
			errc <- fmt.Errorf("too few bytes read: %d", n)
			return
		}
		blockCh <- true
		<-blockCh
		errc <- nil
	})
	defer st.Close()

	st.greet()
	st.writeHeaders(HeadersFrameParam{
		StreamID: 1, // clients send odd numbers
		BlockFragment: st.encodeHeader(
			":method", "POST",
			"content-length", strconv.Itoa(len(content)),
		),
		EndStream:  false, // to say DATA frames are coming
		EndHeaders: true,
	})
	st.writeData(1, false, []byte(content[:5]))
	<-blockCh
	st.stream(1).body.CloseWithError(io.EOF)
	st.writeData(1, false, []byte(content[5:]))
	blockCh <- true

	increments := len(content)
	for {
		f, err := st.readFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if wu, ok := f.(*WindowUpdateFrame); ok && wu.StreamID == 0 {
			increments -= int(wu.Increment)
			if increments == 0 {
				break
			}
		}
	}

	if err := <-errc; err != nil {
		t.Error(err)
	}
}

func TestNoErrorLoggedOnPostAfterGOAWAY(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {})
	defer st.Close()

	st.greet()

	content := "some content"
	st.writeHeaders(HeadersFrameParam{
		StreamID: 1,
		BlockFragment: st.encodeHeader(
			":method", "POST",
			"content-length", strconv.Itoa(len(content)),
		),
		EndStream:  false,
		EndHeaders: true,
	})
	st.wantHeaders()

	st.sc.startGracefulShutdown()
	for {
		f, err := st.readFrame()
		if err == io.EOF {
			st.t.Fatal("got a EOF; want *GoAwayFrame")
		}
		if err != nil {
			t.Fatal(err)
		}
		if gf, ok := f.(*GoAwayFrame); ok && gf.StreamID == 0 {
			break
		}
	}

	st.writeData(1, true, []byte(content))
	time.Sleep(200 * time.Millisecond)
	st.Close()

	if bytes.Contains(st.serverLogBuf.Bytes(), []byte("PROTOCOL_ERROR")) {
		t.Error("got protocol error")
	}
}

func TestServerInitialFlowControlWindow(t *testing.T) {
	for _, want := range []int32{
		65535,
		1 << 19,
		1 << 21,
		// For MaxUploadBufferPerConnection values in the range
		// (65535, 65535*2), we don't send an initial WINDOW_UPDATE
		// because we only send flow control when the window drops
		// below half of the maximum. Perhaps it would be nice to
		// test this case, but we currently do not.
		65535 * 2,
	} {
		t.Run(fmt.Sprint(want), func(t *testing.T) {
			st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
			},
				config.WithMaxUploadBufferPerConnection(want),
			)
			defer st.Close()
			st.writePreface()
			st.writeInitialSettings()
			st.writeSettingsAck()
			st.writeHeaders(HeadersFrameParam{
				StreamID:      1,
				BlockFragment: st.encodeHeader(),
				EndStream:     true,
				EndHeaders:    true,
			})
			window := 65535
		Frames:
			for {
				f, err := st.readFrame()
				if err != nil {
					st.t.Fatal(err)
				}
				switch f := f.(type) {
				case *WindowUpdateFrame:
					if f.FrameHeader.StreamID != 0 {
						t.Errorf("WindowUpdate StreamID = %d; want 0", f.FrameHeader.StreamID)
						return
					}
					window += int(f.Increment)
				case *HeadersFrame:
					break Frames
				default:
				}
			}
			if window != int(want) {
				t.Errorf("got initial flow control window = %v, want %v", window, want)
			}
		})
	}
}

type handlerPuppet struct {
	ch chan puppetCommand
}

func newHandlerPuppet() *handlerPuppet {
	return &handlerPuppet{
		ch: make(chan puppetCommand),
	}
}

func (p *handlerPuppet) act(c context.Context, ctx *app.RequestContext) {
	for cmd := range p.ch {
		cmd.fn(c, ctx)
		cmd.done <- true
	}
}

func (p *handlerPuppet) done() { close(p.ch) }
func (p *handlerPuppet) do(fn func(c context.Context, ctx *app.RequestContext)) {
	done := make(chan bool)
	p.ch <- puppetCommand{fn, done}
	<-done
}

type puppetCommand struct {
	fn   func(c context.Context, ctx *app.RequestContext)
	done chan<- bool
}

// like encodeHeader, but don't add implicit pseudo headers.
func encodeHeaderNoImplicit(t *testing.T, headers ...string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for len(headers) > 0 {
		k, v := headers[0], headers[1]
		headers = headers[2:]
		if err := enc.WriteField(hpack.HeaderField{Name: k, Value: v}); err != nil {
			t.Fatalf("HPACK encoding error for %q/%q: %v", k, v, err)
		}
	}
	return buf.Bytes()
}

func equalError(a, b error) bool {
	if a == nil {
		return b == nil
	}
	if b == nil {
		return a == nil
	}
	return a.Error() == b.Error()
}

func TestProtocolErrorAfterGoAway(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Request.Body()
	})
	defer st.Close()

	st.greet()
	content := "some content"
	st.writeHeaders(HeadersFrameParam{
		StreamID: 1,
		BlockFragment: st.encodeHeader(
			":method", "POST",
			"content-length", strconv.Itoa(len(content)),
		),
		EndStream:  false,
		EndHeaders: true,
	})
	st.writeData(1, false, []byte(content[:5]))

	_, err := st.readFrame()
	if err != nil {
		st.t.Fatal(err)
	}

	// Send a GOAWAY with ErrCodeNo, followed by a bogus window update.
	// The server should close the connection.
	if err := st.fr.WriteGoAway(1, ErrCodeNo, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.fr.WriteWindowUpdate(0, 1<<31-1); err != nil {
		t.Fatal(err)
	}

	for {
		if _, err := st.readFrame(); err != nil {
			if err != io.EOF {
				t.Errorf("unexpected readFrame error: %v", err)
			}
			break
		}
	}
}

func TestServer_HijackWriter(t *testing.T) {
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		writer, _ := NewResponseWriter(ctx.GetConn())
		ctx.Response.HijackWriter(writer)
		ctx.Write([]byte("Hello"))
		ctx.Flush()
		ctx.Write([]byte("World"))
		ctx.Flush()
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}

		df := st.wantData()
		if !df.valid {
			t.Fatal("data Frame is invalid")
		}

		if string(df.data) != "Hello" {
			t.Fatalf("Got %v; want %v", string(df.data), "Hello")
		}

		df = st.wantData()
		if !df.valid {
			t.Fatal("data Frame is invalid")
		}

		if string(df.data) != "World" {
			t.Fatalf("Got %v; want %v", string(df.data), "World")
		}

		df = st.wantData()
		if !df.StreamEnded() {
			t.Fatal("want STREAM_ENDED flag")
		}
	})
}

func TestServer_HijackWriter_Flush(t *testing.T) {
	ch := make(chan struct{})
	testServerResponse(t, func(c context.Context, ctx *app.RequestContext) error {
		writer, _ := NewResponseWriter(ctx.GetConn())
		ctx.Response.HijackWriter(writer)
		ctx.Write([]byte("Hello"))
		ctx.Flush()

		ch <- struct{}{}

		ctx.Write([]byte("World"))
		ctx.Flush()

		ch <- struct{}{}
		return nil
	}, func(st *hertzServerTester) {
		getSlash(st)
		hf := st.wantHeaders()
		if !hf.HeadersEnded() {
			t.Fatal("want END_HEADERS flag")
		}

		<-ch
		df := st.wantData()
		if !df.valid {
			t.Fatal("data Frame is invalid")
		}

		if string(df.data) != "Hello" {
			t.Fatalf("Got %v; want %v", string(df.data), "Hello")
		}

		<-ch
		df = st.wantData()
		if !df.valid {
			t.Fatal("data Frame is invalid")
		}

		if string(df.data) != "World" {
			t.Fatalf("Got %v; want %v", string(df.data), "World")
		}

		df = st.wantData()
		if !df.StreamEnded() {
			t.Fatal("want STREAM_ENDED flag")
		}
	})
}

func TestServer_Request_Te_Header_Check(t *testing.T) {
	testServerRequest(t, func(st *hertzServerTester) {
		st.writeHeaders(HeadersFrameParam{
			StreamID:      1, // clients send odd numbers
			BlockFragment: st.encodeHeader("te", "trailers"),
			EndStream:     true, // no DATA frames
			EndHeaders:    true,
		})
	}, func(ctx *app.RequestContext) {
		err := checkValidHTTP2RequestHeaders(&ctx.Request.Header)
		if err != nil {
			t.Errorf("http2 header check failed")
		}
	})
}

func TestServerContinuationFlood(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	})

	defer st.Close()
	st.writePreface()
	st.writeInitialSettings()
	st.writeSettingsAck()
	framer := NewFramer(st.cc, newMockTLSConn(st.cc))
	framer.MaxHeaderListSize = uint32(2368)
	st.fr = framer
	// st.fr.MaxHeaderListSize = uint32(2368)

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(),
		EndStream:     true,
	})
	for i := 0; i < 22000; i++ {
		st.fr.WriteContinuation(1, false, st.encodeHeaderRaw(
			fmt.Sprintf("x-%v", i), "1234567890",
		))
	}
	st.fr.WriteContinuation(1, true, st.encodeHeaderRaw(
		"x-last-header", "1",
	))

	var sawGoAway bool
	for {
		f, err := st.readFrame()
		if err != nil {
			break
		}
		switch f.(type) {
		case *GoAwayFrame:
			sawGoAway = true
		case *HeadersFrame:
			t.Fatalf("received HEADERS frame; want GOAWAY")
		}
	}
	if !sawGoAway {
		t.Errorf("connection closed with no GOAWAY frame; want one")
	}
}

func TestServerContinuationAfterInvalidHeader(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	})

	defer st.Close()

	st.writePreface()
	st.writeInitialSettings()
	st.writeSettingsAck()

	st.writeHeaders(HeadersFrameParam{
		StreamID:      1,
		BlockFragment: st.encodeHeader(),
		EndStream:     true,
	})
	st.fr.WriteContinuation(1, false, st.encodeHeaderRaw(
		"x-invalid-header", "\x00",
	))
	st.fr.WriteContinuation(1, true, st.encodeHeaderRaw(
		"x-valid-header", "1",
	))

	var sawGoAway bool
	for {
		f, err := st.readFrame()
		if err != nil {
			break
		}
		switch f.(type) {
		case *GoAwayFrame:
			sawGoAway = true
		case *HeadersFrame:
			t.Fatalf("received HEADERS frame; want GOAWAY")
		}
	}
	if !sawGoAway {
		t.Errorf("connection closed with no GOAWAY frame; want one")
	}
}
