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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	config1 "github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
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

type serverTesterOpt string

var (
	optOnlyServer        = serverTesterOpt("only_server")
	optQuiet             = serverTesterOpt("quiet_logging")
	optFramerReuseFrames = serverTesterOpt("frame_reuse_frames")

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
	//h2server := new(Server)
	for _, opt := range opts {
		switch v := opt.(type) {
		case func(*tls.Config):
			v(tlsConfig)
		case config.Option:
			h2Opts = append(h2Opts, v)
		case config1.Option:
			server_opts = append(server_opts, v)
		case serverTesterOpt:
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

	testHookGetServerConn = func(v *serverConn) {
		st.scMu.Lock()
		defer st.scMu.Unlock()
		st.sc = v
	}
	hlog.SetOutput(io.MultiWriter(stderrv(), twriter{t: t, filter: st}))

	go h.Spin()
	time.Sleep(time.Second)

	if !onlyServer {
		cc, err := tls.Dial("tcp", "127.0.0.1:8080", tlsConfig)
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

func (st *hertzServerTester) onHeaderField(f hpack.HeaderField) {
	if f.Name == "date" {
		return
	}
	st.decodedHeaders = append(st.decodedHeaders, [2]string{f.Name, f.Value})
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
		case serverTesterOpt:
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
			t.Fatalf("unknown newServerTester option type %T", v)
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
