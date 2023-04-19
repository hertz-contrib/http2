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
 * Copyright 2017 The Go Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package http2

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client/retry"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/network/dialer"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/hertz-contrib/http2/config"
	"github.com/hertz-contrib/http2/hpack"
	"golang.org/x/net/http2"
)

var tlsConfigInsecure = &tls.Config{InsecureSkipVerify: true}

var canceledCtx context.Context

func init() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledCtx = ctx
}

type mockNetworkConn struct {
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (c *mockNetworkConn) SetWriteTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

type mockTLSConn struct {
	*mockNetworkConn
}

func (c *mockTLSConn) SetWriteTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

func (c *mockTLSConn) Handshake() error {
	return c.conn.(network.ConnTLSer).Handshake()
}

func (c *mockTLSConn) ConnectionState() tls.ConnectionState {
	return c.conn.(network.ConnTLSer).ConnectionState()
}

func (c *mockNetworkConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *mockNetworkConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *mockNetworkConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *mockNetworkConn) Peek(i int) ([]byte, error) {
	return c.rw.Peek(i)
}

func (c *mockNetworkConn) Skip(n int) error {
	_, err := c.rw.Discard(n)
	return err
}

func (c *mockNetworkConn) Release() error {
	return nil
}

func (c *mockNetworkConn) Len() int {
	panic("implement me")
}

func (c *mockNetworkConn) ReadByte() (byte, error) {
	panic("implement me")
}

func (c *mockNetworkConn) ReadBinary(n int) ([]byte, error) {
	var out, b []byte
	var err error
	remain := n

	for {
		b, err = c.rw.Peek(remain)
		if len(b) == 0 {
			return b, err
		}
		out = append(out, b...)
		if err != nil {
			if !errors.Is(err, bufio.ErrBufferFull) {
				return out, err
			}
		}
		c.Skip(len(b))
		remain -= len(b)
		if remain == 0 {
			break
		}
	}
	return out, nil
}

func (c *mockNetworkConn) Malloc(n int) (buf []byte, err error) {
	panic("implement me")
}

func (c *mockNetworkConn) WriteBinary(b []byte) (n int, err error) {
	panic("implement me")
}

func (c *mockNetworkConn) Flush() error {
	panic("implement me")
}

func (c *mockNetworkConn) SetReadTimeout(t time.Duration) error {
	return c.conn.SetReadDeadline(time.Now().Add(t))
}

func (c *mockNetworkConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *mockNetworkConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *mockNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *mockNetworkConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *mockNetworkConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func newMockNetworkConn(c net.Conn) *mockNetworkConn {
	return &mockNetworkConn{
		conn: c,
		rw:   bufio.NewReadWriter(bufio.NewReaderSize(c, 4096), bufio.NewWriter(c)),
	}
}

func newMockTLSConn(c net.Conn) *mockTLSConn {
	return &mockTLSConn{
		newMockNetworkConn(c),
	}
}

type fakeTLSConn struct {
	net.Conn
}

func (c *fakeTLSConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: cipher_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

func startH2cServer(t *testing.T) net.Listener {
	h2Server := &http2.Server{}
	l := newLocalListener(t)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		h2Server.ServeConn(&fakeTLSConn{conn}, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, %v, http: %v", r.URL.Path, r.TLS == nil)
		})})
	}()
	return l
}

func TestHostClientH2c(t *testing.T) {
	l := startH2cServer(t)
	defer l.Close()
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI("http://" + l.Addr().String() + "/foobar")

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			AllowHTTP: true,
			Dialer: newMockDialerWithCustomFunc(dialer.DefaultDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				return dialer.DefaultDialer().DialConnection("tcp", address, 1*time.Second, nil)
			}),
		},
		Addr: l.Addr().String(),
	}
	err := tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}

	body, err := ioutil.ReadAll(rsp.BodyStream())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "Hello, /foobar, http: true"; got != want {
		t.Fatalf("response got %v, want %v", got, want)
	}
}

func TestHostClient(t *testing.T) {
	const body = "sup"
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.WriteString(body)
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	// FIXME: standard dialer may panic because client may read and close connection concurrently.
	// defer tr.CloseIdleConnections()

	for i, m := range []string{"GET", ""} {
		req := protocol.AcquireRequest()
		res := protocol.AcquireResponse()
		req.SetMethod(m)
		req.SetRequestURI(u.String())
		err = tr.Do(context.Background(), req, res)
		if err != nil {
			t.Fatalf("%d: %s", i, err)
		}

		if g, w := res.StatusCode(), 200; g != w {
			t.Errorf("%d: StatusCode = %v; want %v", i, g, w)
		}

		wantHeader := http.Header{
			"Content-Length": []string{"3"},
			"Content-Type":   []string{"text/plain; charset=utf-8"},
			// FIXME: Date Header does not exist temporarily.
			//"Date":           []string{"XXX"}, // see cleanDate
		}
		cleanDate(res)

		isEqual := true
		for k, v := range wantHeader {
			isExisted := false
			res.Header.VisitAll(func(key, value []byte) {
				if string(key) == k {
					isExisted = true
					if v[0] != string(value) {
						isEqual = false
					}
				}
			})
			if !isExisted {
				isEqual = false
			}
			if !isEqual {
				break
			}
		}
		if !isEqual {
			t.Error("res header doesn't equal to wantHeader")
		}
		slurp, err := ioutil.ReadAll(res.BodyStream())
		if err != nil {
			t.Errorf("%d: Body read: %v", i, err)
		} else if string(slurp) != body {
			t.Errorf("%d: Body = %q; want %q", i, slurp, body)
		}
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(res)
	}
}

func testHostClientReusesConns(t *testing.T, wantSame bool, modReq func(*protocol.Request)) {
	st := newHertzServerTester(t, func(ctx context.Context, c *app.RequestContext) {
		c.WriteString(c.RemoteAddr().String())
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

	get := func() string {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		modReq(req)
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatal(err)
		}

		slurp, err := ioutil.ReadAll(rsp.BodyStream())
		if err != nil {
			t.Fatalf("Body read: %v", err)
		}
		addr := strings.TrimSpace(string(slurp))
		if addr == "" {
			t.Fatalf("didn't get an addr in response")
		}
		return addr
	}
	first := get()
	second := get()
	if got := first == second; got != wantSame {
		t.Errorf("first and second responses on same connection: %v; want %v", got, wantSame)
	}
}

func TestHostClientReusesConns(t *testing.T) {
	for _, test := range []struct {
		name     string
		modReq   func(*protocol.Request)
		wantSame bool
	}{{
		name:     "ReuseConn",
		modReq:   func(*protocol.Request) {},
		wantSame: true,
	}, {
		name:     "ConnClose",
		modReq:   func(r *protocol.Request) { r.Header.Set("Connection", "close") },
		wantSame: false,
	}} {
		t.Run("Transport", func(t *testing.T) {
			testHostClientReusesConns(t, test.wantSame, test.modReq)
		})
	}
}

type testNetConn struct {
	net.Conn
	closed  bool
	onClose func()
}

func (c *testNetConn) SetWriteTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Peek(n int) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Skip(n int) error {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Release() error {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Len() int {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) ReadByte() (byte, error) {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) ReadBinary(n int) (p []byte, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Malloc(n int) (buf []byte, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) WriteBinary(b []byte) (n int, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Flush() error {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) SetReadTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

func (c *testNetConn) Close() error {
	if !c.closed {
		// We can call Close multiple times on the same net.Conn.
		if c.onClose != nil {
			c.onClose()
		} else {
			return c.Conn.Close()
		}
	}
	c.closed = true

	return c.Conn.Close()
}

// Tests that the Transport only keeps one pending dial open per destination address.
// https://golang.org/issue/13397
func TestHostClientGroupsPendingDials(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	}, optOnlyServer)
	defer st.Close()
	var (
		mu         sync.Mutex
		dialCount  int
		closeCount int
	)

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				mu.Lock()
				dialCount++
				mu.Unlock()
				cfg := newClientTLSConfig(&tls.Config{}, address)
				cfg.InsecureSkipVerify = true
				c, err := standard.NewDialer().DialConnection("tcp", address, time.Second, cfg)
				return &testNetConn{
					Conn: c,
					onClose: func() {
						mu.Lock()
						closeCount++
						mu.Unlock()
					},
				}, err
			}),
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
			req.SetRequestURI(u.String())
			err := tr.Do(context.Background(), req, rsp)
			if err != nil {
				t.Error(err)
				return
			}
		}()
	}
	wg.Wait()
	tr.CloseIdleConnections()
	if dialCount != 1 {
		t.Errorf("saw %d dials; want 1", dialCount)
	}
	if closeCount != 1 {
		t.Errorf("saw %d closes; want 1", closeCount)
	}
}

func TestHostClientAbortClosesPipes(t *testing.T) {
	shutdown := make(chan struct{})
	st := newStandardServerTester(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			<-shutdown
		},
		optOnlyServer,
	)
	defer st.Close()
	defer close(shutdown) // we must shutdown before st.Close() to avoid hanging

	errCh := make(chan error)
	go func() {
		defer close(errCh)

		u, err := url.Parse(st.ts.URL)
		if err != nil {
			errCh <- err
		}
		tr := &HostClient{
			ClientConfig: &config.ClientConfig{
				TLSConfig: tlsConfigInsecure,
				Dialer:    standard.NewDialer(),
			},
			IsTLS: true,
			Addr:  u.Host,
		}

		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			errCh <- err
			return
		}
		// because we can't close server conn here, so close the client conn instead.
		// st.closeConn()
		tr.conns.Front().Value.(*clientConn).tconn.Close()
		_, err = ioutil.ReadAll(rsp.BodyStream())
		if err == nil {
			errCh <- errors.New("expected error from res.Body.Read")
			return
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	// deadlock? that's a bug.
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// TODO: merge this with TestHostClientBody to make TestHostClientRequest? This
// could be a table-driven test with extra goodies.
func TestHostClientPath(t *testing.T) {
	gotc := make(chan *protocol.URI, 1)
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			url := new(protocol.URI)
			ctx.Request.URI().CopyTo(url)
			gotc <- url
		},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer:    standard.NewDialer(),
		},
		IsTLS: true,
		Addr:  u.Host,
	}
	defer tr.CloseIdleConnections()

	const (
		path  = "/testpath"
		query = "q=1"
	)
	surl := "https://" + st.url + path + "?" + query
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod(consts.MethodPost)
	req.SetRequestURI(surl)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	got := <-gotc
	if string(got.Path()) != path {
		t.Errorf("Read Path = %q; want %q", string(got.Path()), path)
	}
	if string(got.QueryString()) != query {
		t.Errorf("Read RawQuery = %q; want %q", string(got.QueryString()), query)
	}
}

func randString(n int) string {
	rnd := rand.New(rand.NewSource(int64(n)))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rnd.Intn(256))
	}
	return string(b)
}

func TestHostClientBody(t *testing.T) {
	bodyTests := []struct {
		body string
	}{
		{body: "some message"},
		{body: strings.Repeat("a", 1<<20)},
		{body: randString(16<<10 - 1)},
		{body: randString(16 << 10)},
		{body: randString(16<<10 + 1)},
		{body: randString(512<<10 - 1)},
		{body: randString(512 << 10)},
		{body: randString(512<<10 + 1)},
		{body: randString(1<<20 - 1)},
		{body: randString(1 << 20)},
		{body: randString(1<<20 + 2)},
	}

	type reqInfo struct {
		contentLength int
		slurp         []byte
		err           error
	}
	gotc := make(chan reqInfo, 1)
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			slurp, err := ctx.Request.BodyE()
			if err != nil {
				gotc <- reqInfo{err: err}
			} else {
				gotc <- reqInfo{contentLength: ctx.Request.Header.ContentLength(), slurp: slurp}
			}
		},
		optOnlyServer,
	)
	defer st.Close()

	for i, tt := range bodyTests {
		u, err := url.Parse("https://" + st.url)
		if err != nil {
			t.Fatal(err)
		}

		tr := &HostClient{
			ClientConfig: &config.ClientConfig{
				TLSConfig: tlsConfigInsecure,
				Dialer:    standard.NewDialer(),
			},
			IsTLS: true,
			Addr:  u.Host,
		}
		defer tr.CloseIdleConnections()

		var body io.Reader = strings.NewReader(tt.body)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		req.SetMethod(consts.MethodPost)
		req.SetBodyStream(body, len(tt.body))
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		ri := <-gotc
		if ri.err != nil {
			t.Errorf("#%d: read error: %v", i, ri.err)
			continue
		}
		if got := string(ri.slurp); got != tt.body {
			t.Errorf("#%d: Read body mismatch.\n got: %q (len %d)\nwant: %q (len %d)", i, shortString(got), len(got), shortString(tt.body), len(tt.body))
		}
		wantLen := int(len(tt.body))
		if ri.contentLength != wantLen {
			t.Errorf("#%d. handler got ContentLength = %v; want %v", i, ri.contentLength, wantLen)
		}
	}
}

func shortString(v string) string {
	const maxLen = 100
	if len(v) <= maxLen {
		return v
	}
	return fmt.Sprintf("%v[...%d bytes omitted...]%v", v[:maxLen/2], len(v)-maxLen, v[len(v)-maxLen/2:])
}

func TestHostClientDialTLS(t *testing.T) {
	var mu sync.Mutex // guards following
	var gotReq, didDial bool

	ts := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			mu.Lock()
			gotReq = true
			mu.Unlock()
		},
		optOnlyServer,
	)
	defer ts.Close()

	u, err := url.Parse("https://" + ts.url)
	if err != nil {
		t.Fatal(err)
	}

	cfg := newClientTLSConfig(&tls.Config{}, u.Host)
	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				mu.Lock()
				didDial = true
				mu.Unlock()
				cfg.InsecureSkipVerify = true
				c, err := tls.Dial("tcp", address, cfg)
				if err != nil {
					return nil, err
				}
				return newMockTLSConn(c), c.Handshake()
			}),
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if !gotReq {
		t.Error("didn't get request")
	}
	if !didDial {
		t.Error("didn't use dial hook")
	}
}

type capitalizeReader struct {
	r io.Reader
}

func (cr capitalizeReader) Read(p []byte) (n int, err error) {
	n, err = cr.r.Read(p)
	for i, b := range p[:n] {
		if b >= 'a' && b <= 'z' {
			p[i] = b - ('a' - 'A')
		}
	}
	return
}

type flushWriter struct {
	w io.Writer
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

type clientTester struct {
	t      *testing.T
	tr     *HostClient
	cc, sc network.Conn // server and client conn
	fr     *Framer      // server's framer
	client func() error
	server func() error
}

func newClientTester(t *testing.T) *clientTester {
	var dialOnce struct {
		sync.Mutex
		dialed bool
	}
	ct := &clientTester{
		t: t,
	}
	ct.tr = &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				dialOnce.Lock()
				defer dialOnce.Unlock()
				if dialOnce.dialed {
					return nil, errors.New("only one dial allowed in test mode")
				}
				dialOnce.dialed = true
				return &testNetConn{Conn: ct.cc}, nil
			}),
			MaxHeaderListSize: 10 << 20,
			PingTimeout:       15 * time.Second,
			RetryConfig:       &retry.Config{MaxAttemptTimes: 3},
		},
	}

	ln := newLocalListener(t)
	cc, err := standard.NewDialer().DialConnection("tcp", ln.Addr().String(), time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	ct.cc = cc
	// ct.sc = standard.NewConn(sc, 4096)
	ct.sc = newMockNetworkConn(sc)
	ct.fr = NewFramer(ct.sc, ct.sc)
	ct.tr.Addr = ct.cc.RemoteAddr().String()
	return ct
}

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		return ln
	}
	ln, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func (ct *clientTester) greet(settings ...Setting) {
	buf := make([]byte, len(ClientPreface))
	_, err := io.ReadFull(ct.sc, buf)
	if err != nil {
		ct.t.Fatalf("reading client preface: %v", err)
	}
	f, err := ct.fr.ReadFrame()
	if err != nil {
		ct.t.Fatalf("Reading client settings frame: %v", err)
	}
	if _, ok := f.(*SettingsFrame); !ok {
		ct.t.Fatalf("Wanted client settings frame; got %v", f)
	}
	if err := ct.fr.WriteSettings(settings...); err != nil {
		ct.t.Fatal(err)
	}
	if err := ct.fr.WriteSettingsAck(); err != nil {
		ct.t.Fatal(err)
	}
}

func (ct *clientTester) readNonSettingsFrame() (Frame, error) {
	for {
		f, err := ct.fr.ReadFrame()
		if err != nil {
			return nil, err
		}
		if _, ok := f.(*SettingsFrame); ok {
			continue
		}
		return f, nil
	}
}

func (ct *clientTester) cleanup() {
	ct.tr.CloseIdleConnections()

	// close both connections, ignore the error if its already closed
	ct.sc.Close()
	ct.cc.Close()
}

func (ct *clientTester) run() {
	var errOnce sync.Once
	var wg sync.WaitGroup

	run := func(which string, fn func() error) {
		defer wg.Done()
		if err := fn(); err != nil {
			errOnce.Do(func() {
				ct.t.Errorf("%s: %v", which, err)
				ct.cleanup()
			})
		}
	}

	wg.Add(2)
	go run("client", ct.client)
	go run("server", ct.server)
	wg.Wait()

	errOnce.Do(ct.cleanup) // clean up if no error
}

func (ct *clientTester) readFrame() (Frame, error) {
	return readFrameTimeout(ct.fr, 2*time.Second)
}

func (ct *clientTester) firstHeaders() (*HeadersFrame, error) {
	for {
		f, err := ct.readFrame()
		if err != nil {
			return nil, fmt.Errorf("ReadFrame while waiting for Headers: %v", err)
		}
		switch f.(type) {
		case *WindowUpdateFrame, *SettingsFrame:
			continue
		}
		hf, ok := f.(*HeadersFrame)
		if !ok {
			return nil, fmt.Errorf("Got %T; want HeadersFrame", f)
		}
		return hf, nil
	}
}

func TestHostClientReqBodyAfterResponse_200(t *testing.T) { testHostClientReqBodyAfterResponse(t, 200) }
func TestHostClientReqBodyAfterResponse_403(t *testing.T) { testHostClientReqBodyAfterResponse(t, 403) }

func testHostClientReqBodyAfterResponse(t *testing.T, status int) {
	const bodySize = 10 << 20
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	recvLen := make(chan int64, 1)
	ct.client = func() error {
		defer ct.cc.Close()
		defer close(clientDone)

		body := &pipe{b: new(bytes.Buffer)}
		io.Copy(body, io.LimitReader(neverEnding('A'), bodySize/2))
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodPut)
		req.SetRequestURI("https://dummy.tld/")
		req.SetBodyStream(body, -1)
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip: %v", err)
		}
		if rsp.StatusCode() != status {
			return fmt.Errorf("status code = %v; want %v", rsp.StatusCode(), status)
		}
		io.Copy(body, io.LimitReader(neverEnding('A'), bodySize/2))
		body.CloseWithError(io.EOF)
		slurp, err := ioutil.ReadAll(rsp.BodyStream())
		if err != nil {
			return fmt.Errorf("Slurp: %v", err)
		}
		if len(slurp) > 0 {
			return fmt.Errorf("unexpected body: %q", slurp)
		}
		if status == 200 {
			if got := <-recvLen; got != bodySize {
				return fmt.Errorf("For 200 response, Transport wrote %d bytes; want %d", got, bodySize)
			}
		} else {
			if got := <-recvLen; got == 0 || got >= bodySize {
				return fmt.Errorf("For %d response, Transport wrote %d bytes; want (0,%d) exclusive", status, got, bodySize)
			}
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		defer close(recvLen)
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		var dataRecv int64
		var closed bool
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-clientDone:
					// If the client's done, it
					// will have reported any
					// errors on its side.
					return nil
				default:
					return err
				}
			}
			// println(fmt.Sprintf("server got frame: %v", f))
			ended := false
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
				if !f.HeadersEnded() {
					return fmt.Errorf("headers should have END_HEADERS be ended: %v", f)
				}
				if f.StreamEnded() {
					return fmt.Errorf("headers contains END_STREAM unexpectedly: %v", f)
				}
			case *DataFrame:
				dataLen := len(f.Data())
				if dataLen > 0 {
					if dataRecv == 0 {
						enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
						ct.fr.WriteHeaders(HeadersFrameParam{
							StreamID:      f.StreamID,
							EndHeaders:    true,
							EndStream:     false,
							BlockFragment: buf.Bytes(),
						})
					}
					if err := ct.fr.WriteWindowUpdate(0, uint32(dataLen)); err != nil {
						return err
					}
					if err := ct.fr.WriteWindowUpdate(f.StreamID, uint32(dataLen)); err != nil {
						return err
					}
				}
				dataRecv += int64(dataLen)

				if !closed && ((status != 200 && dataRecv > 0) ||
					(status == 200 && f.StreamEnded())) {
					closed = true
					if err := ct.fr.WriteData(f.StreamID, true, nil); err != nil {
						return err
					}
				}

				if f.StreamEnded() {
					ended = true
				}
			case *RSTStreamFrame:
				if status == 200 {
					return fmt.Errorf("Unexpected client frame %v", f)
				}
				ended = true
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}

			if ended {
				select {
				case recvLen <- dataRecv:
				default:
				}
			}
		}
	}
	ct.run()
}

// See golang.org/issue/13444
func TestHostClientFullDuplex(t *testing.T) {
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // redundant but for clarity
		w.(http.Flusher).Flush()
		io.Copy(flushWriter{w}, capitalizeReader{r.Body})
		fmt.Fprintf(w, "bye.\n")
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer:    standard.NewDialer(),
		},
		IsTLS: true,
		Addr:  u.Host,
	}
	defer tr.CloseIdleConnections()

	pr, pw := io.Pipe()
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	req.SetMethod(consts.MethodPut)
	req.SetBodyStream(pr, -1)

	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}

	if rsp.StatusCode() != 200 {
		t.Fatalf("StatusCode = %v; want %v", rsp.StatusCode(), 200)
	}
	bs := bufio.NewScanner(rsp.BodyStream())
	want := func(v string) {
		if !bs.Scan() {
			t.Fatalf("wanted to read %q but Scan() = false, err = %v", v, bs.Err())
		}
	}
	write := func(v string) {
		_, err := io.WriteString(pw, v)
		if err != nil {
			t.Fatalf("pipe write: %v", err)
		}
	}
	write("foo\n")
	want("FOO")
	write("bar\n")
	want("BAR")
	pw.Close()
	want("bye.")
	if err := bs.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestHostClientConnectRequest(t *testing.T) {
	gotc := make(chan *protocol.Request, 1)
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		req := protocol.AcquireRequest()
		ctx.Request.CopyTo(req)
		gotc <- req
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer:    standard.NewDialer(),
		},
		IsTLS: true,
		Addr:  u.Host,
	}
	defer tr.CloseIdleConnections()

	tests := []struct {
		modReq func(*protocol.Request)
		want   string
	}{
		{
			modReq: func(r *protocol.Request) {
				r.SetRequestURI(u.String())
				r.SetMethod(consts.MethodConnect)
			},
			want: u.Host,
		},
		{
			modReq: func(r *protocol.Request) {
				r.SetRequestURI(u.String())
				r.SetMethod(consts.MethodConnect)
				r.SetHost("example.com:123")
			},
			want: "example.com:123",
		},
	}

	for i, tt := range tests {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		tt.modReq(req)
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Errorf("%d. RoundTrip = %v", i, err)
			continue
		}
		result := <-gotc
		if string(result.Method()) != "CONNECT" {
			t.Errorf("method = %q; want CONNECT", string(result.Method()))
		}
		if string(result.Host()) != tt.want {
			t.Errorf("Host = %q; want %q", string(result.Host()), tt.want)
		}
		if string(result.URI().Host()) != tt.want {
			t.Errorf("URL.Host = %q; want %q", string(result.URI().Host()), tt.want)
		}
	}
}

type headerType int

const (
	noHeader headerType = iota // omitted
	oneHeader
	splitHeader // broken into continuation on purpose
)

const (
	f0 = noHeader
	f1 = oneHeader
	f2 = splitHeader
	d0 = false
	d1 = true
)

// Test all 36 combinations of response frame orders:
//
//	(3 ways of 100-continue) * (2 ways of headers) * (2 ways of data) * (3 ways of trailers):func TestHostClientResponsePattern_00f0(t *testing.T) { TestHostClientResponsePattern(h0, h1, false, h0) }
//
// Generated by http://play.golang.org/p/SScqYKJYXd
func TestHostClientResPattern_c0h1d0t0(t *testing.T) { testHostClientResPattern(t, f0, f1, d0) }

func TestHostClientResPattern_c0h1d1t0(t *testing.T) { testHostClientResPattern(t, f0, f1, d1) }

func TestHostClientResPattern_c0h2d0t0(t *testing.T) { testHostClientResPattern(t, f0, f2, d0) }

func TestHostClientResPattern_c0h2d1t0(t *testing.T) { testHostClientResPattern(t, f0, f2, d1) }

func TestHostClientResPattern_c1h1d0t0(t *testing.T) { testHostClientResPattern(t, f1, f1, d0) }

func TestHostClientResPattern_c1h1d1t0(t *testing.T) { testHostClientResPattern(t, f1, f1, d1) }

func TestHostClientResPattern_c1h2d0t0(t *testing.T) { testHostClientResPattern(t, f1, f2, d0) }

func TestHostClientResPattern_c1h2d1t0(t *testing.T) { testHostClientResPattern(t, f1, f2, d1) }

func TestHostClientResPattern_c2h1d0t0(t *testing.T) { testHostClientResPattern(t, f2, f1, d0) }

func TestHostClientResPattern_c2h1d1t0(t *testing.T) { testHostClientResPattern(t, f2, f1, d1) }

func TestHostClientResPattern_c2h2d0t0(t *testing.T) { testHostClientResPattern(t, f2, f2, d0) }

func TestHostClientResPattern_c2h2d1t0(t *testing.T) { testHostClientResPattern(t, f2, f2, d1) }

func testHostClientResPattern(t *testing.T, expect100Continue, resHeader headerType, withData bool) {
	const reqBody = "some request body"
	const resBody = "some response body"

	if resHeader == noHeader {
		// TODO: test 100-continue followed by immediate
		// server stream reset, without headers in the middle?
		panic("invalid combination")
	}

	ct := newClientTester(t)
	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodPost)
		req.SetRequestURI("https://dummy.tld/")
		req.SetBodyStream(strings.NewReader(reqBody), len(reqBody))
		if expect100Continue != noHeader {
			req.Header.Set("Expect", "100-continue")
		}
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip: %v", err)
		}
		if rsp.StatusCode() != 200 {
			return fmt.Errorf("status code = %v; want 200", rsp.StatusCode())
		}
		slurp, err := ioutil.ReadAll(rsp.BodyStream())
		if err != nil {
			return fmt.Errorf("Slurp: %v", err)
		}
		wantBody := resBody
		if !withData {
			wantBody = ""
		}
		if string(slurp) != wantBody {
			return fmt.Errorf("body = %q; want %q", slurp, wantBody)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			endStream := false
			send := func(mode headerType) {
				hbf := buf.Bytes()
				switch mode {
				case oneHeader:
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.Header().StreamID,
						EndHeaders:    true,
						EndStream:     endStream,
						BlockFragment: hbf,
					})
				case splitHeader:
					if len(hbf) < 2 {
						panic("too small")
					}
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.Header().StreamID,
						EndHeaders:    false,
						EndStream:     endStream,
						BlockFragment: hbf[:1],
					})
					ct.fr.WriteContinuation(f.Header().StreamID, true, hbf[1:])
				default:
					panic("bogus mode")
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *DataFrame:
				if !f.StreamEnded() {
					// No need to send flow control tokens. The test request body is tiny.
					continue
				}
				// Response headers (1+ frames; 1 or 2 in this test, but never 0)
				{
					buf.Reset()
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					enc.WriteField(hpack.HeaderField{Name: "x-foo", Value: "blah"})
					enc.WriteField(hpack.HeaderField{Name: "x-bar", Value: "more"})
					endStream = withData == false
					send(resHeader)
				}
				if withData {
					endStream = true
					ct.fr.WriteData(f.StreamID, endStream, []byte(resBody))
				}
				if endStream {
					return nil
				}
			case *HeadersFrame:
				if expect100Continue != noHeader {
					buf.Reset()
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: "100"})
					send(expect100Continue)
				}
			}
		}
	}
	ct.run()
}

// Issue 26189, Issue 17739: ignore unknown 1xx responses
func TestHostClientUnknown1xx(t *testing.T) {
	var buf bytes.Buffer
	defer func() { got1xxFuncForTests = nil }()
	got1xxFuncForTests = func(code int, header *protocol.ResponseHeader) error {
		fmt.Fprintf(&buf, "code=%d header=%v\n", code, header.Get("foo-bar"))
		return nil
	}

	ct := newClientTester(t)
	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")

		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip: %v", err)
		}
		if rsp.StatusCode() != 204 {
			return fmt.Errorf("status code = %v; want 204", rsp.StatusCode())
		}
		want := `code=110 header=110
code=111 header=111
code=112 header=112
code=113 header=113
code=114 header=114
`
		if got := buf.String(); got != want {
			t.Errorf("Got trace:\n%s\nWant:\n%s", got, want)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
				for i := 110; i <= 114; i++ {
					buf.Reset()
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: fmt.Sprint(i)})
					enc.WriteField(hpack.HeaderField{Name: "foo-bar", Value: fmt.Sprint(i)})
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.StreamID,
						EndHeaders:    true,
						EndStream:     false,
						BlockFragment: buf.Bytes(),
					})
				}
				buf.Reset()
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					EndHeaders:    true,
					EndStream:     false,
					BlockFragment: buf.Bytes(),
				})
				return nil
			}
		}
	}
	ct.run()
}

// headerListSize returns the HTTP2 header list size of h.
//
//	http://httpwg.org/specs/rfc7540.html#SETTINGS_MAX_HEADER_LIST_SIZE
//	http://httpwg.org/specs/rfc7540.html#MaxHeaderBlock

func headerListSize(h *protocol.RequestHeader) (size uint32) {
	h.VisitAll(func(k, v []byte) {
		hf := hpack.HeaderField{Name: string(k), Value: string(v)}
		size += hf.Size()
	})
	return size
}

// padHeaders adds data to an http.Header until headerListSize(h) ==
// limit. Due to the way header list sizes are calculated, padHeaders
// cannot add fewer than len("Pad-Headers") + 32 bytes to h, and will
// call t.Fatal if asked to do so. PadHeaders first reserves enough
// space for an empty "Pad-Headers" key, then adds as many copies of
// filler as possible. Any remaining bytes necessary to push the
// header list size up to limit are added to h["Pad-Headers"].
func padHeaders(t *testing.T, h *protocol.RequestHeader, limit uint64, filler string) {
	if limit > 0xffffffff {
		t.Fatalf("padHeaders: refusing to pad to more than 2^32-1 bytes. limit = %v", limit)
	}
	hf := hpack.HeaderField{Name: "Pad-Headers", Value: ""}
	minPadding := uint64(hf.Size())
	size := uint64(headerListSize(h))

	minlimit := size + minPadding
	if limit < minlimit {
		t.Fatalf("padHeaders: limit %v < %v", limit, minlimit)
	}

	// Use a fixed-width format for name so that fieldSize
	// remains constant.
	nameFmt := "Pad-Headers-%06d"
	hf = hpack.HeaderField{Name: fmt.Sprintf(nameFmt, 1), Value: filler}
	fieldSize := uint64(hf.Size())

	// Add as many complete filler values as possible, leaving
	// room for at least one empty "Pad-Headers" key.
	limit = limit - minPadding
	for i := 0; size+fieldSize < limit; i++ {
		name := fmt.Sprintf(nameFmt, i)
		h.Add(name, filler)
		size += fieldSize
	}

	// Add enough bytes to reach limit.
	remain := limit - size
	lastValue := strings.Repeat("*", int(remain))
	h.Add("Pad-Headers", lastValue)
}

func TestPadHeaders(t *testing.T) {
	check := func(h *protocol.RequestHeader, limit uint32, fillerLen int) {
		if h == nil {
			h = &protocol.RequestHeader{}
		}
		filler := strings.Repeat("f", fillerLen)
		padHeaders(t, h, uint64(limit), filler)
		gotSize := headerListSize(h)
		if gotSize != limit {
			t.Errorf("Got size = %v; want %v", gotSize, limit)
		}
	}
	// Try all possible combinations for small fillerLen and limit.
	hf := hpack.HeaderField{Name: "Pad-Headers", Value: ""}
	minLimit := hf.Size()
	for limit := minLimit; limit <= 128; limit++ {
		for fillerLen := 0; uint32(fillerLen) <= limit; fillerLen++ {
			check(nil, limit, fillerLen)
		}
	}

	// Try a few tests with larger limits, plus cumulative
	// tests. Since these tests are cumulative, tests[i+1].limit
	// must be >= tests[i].limit + minLimit. See the comment on
	// padHeaders for more info on why the limit arg has this
	// restriction.
	tests := []struct {
		fillerLen int
		limit     uint32
	}{
		{
			fillerLen: 64,
			limit:     1024,
		},
		{
			fillerLen: 1024,
			limit:     1286,
		},
		{
			fillerLen: 256,
			limit:     2048,
		},
		{
			fillerLen: 1024,
			limit:     10 * 1024,
		},
		{
			fillerLen: 1023,
			limit:     11 * 1024,
		},
	}
	h := &protocol.RequestHeader{}
	for _, tc := range tests {
		check(nil, tc.limit, tc.fillerLen)
		check(h, tc.limit, tc.fillerLen)
	}
}

func TestHostClientChecksRequestHeaderListSize(t *testing.T) {
	st := newStandardServerTester(t,
		func(w http.ResponseWriter, r *http.Request) {
			// Consume body & force client to send
			// trailers before writing response.
			// ioutil.ReadAll returns non-nil err for
			// requests that attempt to send greater than
			// maxHeaderListSize bytes of trailers, since
			// those requests generate a stream reset.
			ioutil.ReadAll(r.Body)
			r.Body.Close()
		},
		func(ts *httptest.Server) {
			ts.Config.MaxHeaderBytes = 16 << 10
		},
		optOnlyServer,
		optQuiet,
	)
	defer st.Close()

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig:         tlsConfigInsecure,
			MaxHeaderListSize: 10 << 20,
			Dialer:            standard.NewDialer(),
		},
		IsTLS: true,
	}
	defer tr.CloseIdleConnections()

	checkRoundTrip := func(req *protocol.Request, wantErr error, desc string) {
		rsp := protocol.AcquireResponse()
		err := tr.Do(context.Background(), req, rsp)
		if err != wantErr {
			t.Errorf("%v: RoundTrip err = %v; want %v", desc, err, wantErr)
			return
		}
		if err == nil {
			if rsp == nil {
				t.Errorf("%v: response nil; want non-nil.", desc)
				return
			}
			if rsp.StatusCode() != http.StatusOK {
				t.Errorf("%v: response status = %v; want %v", desc, rsp.StatusCode(), http.StatusOK)
			}
			return
		}
	}
	headerListSizeForRequest := func(req *protocol.Request) (size uint64) {
		contentLen := int64(req.Header.ContentLength())
		cc := &clientConn{peerMaxHeaderListSize: 0xffffffffffffffff}
		cc.henc = hpack.NewEncoder(&cc.hbuf)
		cc.mu.Lock()
		hdrs, err := cc.encodeHeaders(req, true, contentLen)
		cc.mu.Unlock()
		if err != nil {
			t.Fatalf("headerListSizeForRequest: %v", err)
		}
		hpackDec := hpack.NewDecoder(initialHeaderTableSize, func(hf hpack.HeaderField) {
			size += uint64(hf.Size())
		})
		if len(hdrs) > 0 {
			if _, err := hpackDec.Write(hdrs); err != nil {
				t.Fatalf("headerListSizeForRequest: %v", err)
			}
		}
		return size
	}
	// Create a new Request for each test, rather than reusing the
	// same Request, to avoid a race when modifying req.Headers.
	// See https://github.com/golang/go/issues/21316
	newRequest := func() *protocol.Request {
		// Body must be non-nil to enable writing trailers.
		body := strings.NewReader("hello")
		req := protocol.AcquireRequest()
		req.SetMethod(consts.MethodPost)
		req.SetRequestURI(st.ts.URL)
		req.SetBodyStream(body, 5)
		return req
	}

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr.Addr = u.Host

	// Make an arbitrary request to ensure we get the server's
	// settings frame and initialize peerMaxHeaderListSize.
	req := newRequest()
	checkRoundTrip(req, nil, "Initial request")

	// Get the ClientConn associated with the request and validate
	// peerMaxHeaderListSize.
	tr.IsTLS = true
	cc, err := tr.acquireConn()
	if err != nil {
		t.Fatalf("GetClientConn: %v", err)
	}
	cc.mu.Lock()
	peerSize := cc.peerMaxHeaderListSize
	cc.mu.Unlock()
	st.scMu.Lock()

	// http2's count is in a slightly different unit and includes 32 bytes per pair.
	// So, take the net/http.Server value and pad it up a bit, assuming 10 headers.
	const perFieldOverhead = 32 // per http2 spec
	const typicalHeaders = 10   // conservative
	wantSize := uint64(st.ts.Config.MaxHeaderBytes + typicalHeaders*perFieldOverhead)
	st.scMu.Unlock()
	if peerSize != wantSize {
		t.Errorf("peerMaxHeaderListSize = %v; want %v", peerSize, wantSize)
	}

	// Sanity check peerSize. (*serverConn) maxHeaderListSize adds
	// 320 bytes of padding.
	wantHeaderBytes := uint64(st.ts.Config.MaxHeaderBytes) + 320
	if peerSize != wantHeaderBytes {
		t.Errorf("peerMaxHeaderListSize = %v; want %v.", peerSize, wantHeaderBytes)
	}

	filler := strings.Repeat("*", 1024)

	// Pad headers , but stay under peerSize.
	req = newRequest()
	// cc.encodeHeaders adds some default headers to the request,
	// so we need to leave room for those.
	defaultBytes := headerListSizeForRequest(req)
	padHeaders(t, &req.Header, peerSize-defaultBytes, filler)
	checkRoundTrip(req, nil, "Headers under limit")

	// Add enough header bytes to push us over peerSize.
	req = newRequest()
	padHeaders(t, &req.Header, peerSize, filler)
	checkRoundTrip(req, errRequestHeaderListSize, "Headers over limit")

	// Send headers with a single large value.
	req = newRequest()
	filler = strings.Repeat("*", int(peerSize))
	req.Header.Set("Big", filler)
	checkRoundTrip(req, errRequestHeaderListSize, "Single large header")
}

func TestHostClientChecksResponseHeaderListSize(t *testing.T) {
	ct := newClientTester(t)
	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if e, ok := err.(StreamError); ok {
			err = e.Cause
		}
		if err != errResponseHeaderListSize {
			size := int64(0)
			rsp.Header.VisitAll(func(key, value []byte) {
				size += int64(len(key)) + int64(len(value)) + 32
			})
			return fmt.Errorf("RoundTrip Error = %v (and %d bytes of response headers); want errResponseHeaderListSize", err, size)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			switch f := f.(type) {
			case *HeadersFrame:
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				large := strings.Repeat("a", 1<<10)
				for i := 0; i < 5042; i++ {
					enc.WriteField(hpack.HeaderField{Name: large, Value: large})
				}
				if size, want := buf.Len(), 6329; size != want {
					// Note: this number might change if
					// our hpack implementation
					// changes. That's fine. This is
					// just a sanity check that our
					// response can fit in a single
					// header block fragment frame.
					return fmt.Errorf("encoding over 10MB of duplicate keypairs took %d bytes; expected %d", size, want)
				}
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					EndHeaders:    true,
					EndStream:     true,
					BlockFragment: buf.Bytes(),
				})
				return nil
			}
		}
	}
	ct.run()
}

func TestHostClientCookieHeaderSplit(t *testing.T) {
	ct := newClientTester(t)
	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		req.SetCookies(map[string]string{
			"a": "b",
			"c": "d",
			"e": "f",
			"g": "h",
			"i": "j",
		})
		err := ct.tr.Do(context.Background(), req, rsp)
		return err
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			switch f := f.(type) {
			case *HeadersFrame:
				dec := hpack.NewDecoder(initialHeaderTableSize, nil)
				hfs, err := dec.DecodeFull(f.HeaderBlockFragment())
				if err != nil {
					return err
				}
				got := []string{}
				want := []string{"a=b", "c=d", "e=f", "g=h", "i=j"}
				for _, hf := range hfs {
					if hf.Name == "cookie" {
						got = append(got, hf.Value)
					}
				}
				sort.Strings(got)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("Cookies = %#v, want %#v", got, want)
				}

				var buf bytes.Buffer
				enc := hpack.NewEncoder(&buf)
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					EndHeaders:    true,
					EndStream:     true,
					BlockFragment: buf.Bytes(),
				})
				return nil
			}
		}
	}
	ct.run()
}

// Test that the Transport returns a typed error from Response.Body.Read calls
// when the server sends an error. (here we use a panic, since that should generate
// a stream error, but others like cancel should be similar)
func TestHostClientBodyReadErrorType(t *testing.T) {
	doPanic := make(chan bool, 1)
	st := newStandardServerTester(t,
		func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush() // force headers out
			<-doPanic
			panic("boom")
		},
		optOnlyServer,
		optQuiet,
	)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(st.ts.URL)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	doPanic <- true
	buf := make([]byte, 100)
	n, err := rsp.BodyStream().Read(buf)
	got, ok := err.(StreamError)
	want := StreamError{StreamID: 0x1, Code: 0x2}
	if !ok || got.StreamID != want.StreamID || got.Code != want.Code {
		t.Errorf("Read = %v, %#v; want error %#v", n, err, want)
	}
}

// golang.org/issue/13924
// This used to fail after many iterations, especially with -race:
// go test -v -run=TestHostClientDoubleCloseOnWriteError -count=500 -race
func TestHostClientDoubleCloseOnWriteError(t *testing.T) {
	var (
		mu   sync.Mutex
		conn network.Conn // to close if set
	)

	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			mu.Lock()
			defer mu.Unlock()
			if conn != nil {
				conn.Close()
			}
		},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	cfg := newClientTLSConfig(&tls.Config{}, u.Host)
	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			DisableKeepAlive: false,
			TLSConfig:        tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				cfg.InsecureSkipVerify = true
				tc, err := tls.Dial("tcp", address, cfg)
				if err != nil {
					return nil, err
				}
				mu.Lock()
				defer mu.Unlock()
				tconn := newMockTLSConn(tc)
				conn = tconn
				return tconn, nil
			}),
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	tr.Do(context.Background(), req, rsp)
}

// Test that the http1 Transport.DisableKeepAlives option is respected
// and connections are closed as soon as idle.
// See golang.org/issue/14008
func TestTransportDisableKeepAlives(t *testing.T) {
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			ctx.WriteString("hi")
		},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	connClosed := make(chan struct{}) // closed on tls.Conn.Close
	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			DisableKeepAlive: true,
			TLSConfig:        tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				tc, err := standard.NewDialer().DialConnection("tcp", address, time.Second, newClientTLSConfig(tlsConfigInsecure, address))
				if err != nil {
					return nil, err
				}
				return &noteCloseConn{Conn: tc, closefn: func() { close(connClosed) }}, nil
			}),
		},
		Addr: u.Host,
	}
	_, _, err = tr.Get(context.Background(), nil, u.String())
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-connClosed:
	case <-time.After(1 * time.Second):
		t.Errorf("timeout")
	}
}

// Test concurrent requests with Transport.DisableKeepAlives. We can share connections,
// but when things are totally idle, it still needs to close.
func TestTransportDisableKeepAlives_Concurrency(t *testing.T) {
	const D = 25 * time.Millisecond
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {
			time.Sleep(D)
			ctx.WriteString("hi")
		},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	var dials int32
	var conns sync.WaitGroup
	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, addr string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				tc, err := standard.NewDialer().DialConnection("tcp", addr, time.Second, newClientTLSConfig(tlsConfigInsecure, addr))
				if err != nil {
					return nil, err
				}
				atomic.AddInt32(&dials, 1)
				conns.Add(1)
				return &noteCloseConn{Conn: tc, closefn: func() { conns.Done() }}, nil
			}),
			DisableKeepAlive: true,
		},
		Addr: u.Host,
	}
	var reqs sync.WaitGroup
	const N = 20
	for i := 0; i < N; i++ {
		reqs.Add(1)
		if i == N-1 {
			// For the final request, try to make all the
			// others close. This isn't verified in the
			// count, other than the Log statement, since
			// it's so timing dependent. This test is
			// really to make sure we don't interrupt a
			// valid request.
			time.Sleep(D * 2)
		}
		go func() {
			defer reqs.Done()
			_, _, err := tr.Get(context.Background(), nil, u.String())
			if err != nil {
				t.Error(err)
				return
			}
		}()
	}
	reqs.Wait()
	conns.Wait()
	t.Logf("did %d dials, %d requests", atomic.LoadInt32(&dials), N)
}

type noteCloseConn struct {
	net.Conn
	onceClose sync.Once
	closefn   func()
}

func (c *noteCloseConn) SetWriteTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Peek(n int) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Skip(n int) error {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Release() error {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Len() int {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) ReadByte() (byte, error) {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) ReadBinary(n int) (p []byte, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Malloc(n int) (buf []byte, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) WriteBinary(b []byte) (n int, err error) {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Flush() error {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) SetReadTimeout(t time.Duration) error {
	// TODO implement me
	panic("implement me")
}

func (c *noteCloseConn) Close() error {
	c.onceClose.Do(c.closefn)
	return c.Conn.Close()
}

// RFC 7540 section 8.1.2.2
func TestHostClientRejectsConnHeaders(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		var got []string
		ctx.Request.Header.VisitAll(func(key, _ []byte) {
			got = append(got, string(key))
		})
		sort.Strings(got)
		ctx.Response.Header.Set("Got-Header", strings.Join(got, ","))
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	tests := []struct {
		key   string
		value []string
		want  string
	}{
		{
			key:   "Upgrade",
			value: []string{"anything"},
			want:  "ERROR: http2: invalid Upgrade request header: \"anything\"",
		},
		{
			key:   "Connection",
			value: []string{"foo"},
			want:  "ERROR: http2: invalid Connection request header: \"foo\"",
		},
		{
			key:   "Connection",
			value: []string{"close"},
			want:  "User-Agent",
		},
		{
			key:   "Connection",
			value: []string{"CLoSe"},
			want:  "User-Agent",
		},
		{
			key:   "Connection",
			value: []string{"keep-alive"},
			want:  "User-Agent",
		},
		{
			key:   "Connection",
			value: []string{"Keep-ALIVE"},
			want:  "User-Agent",
		},
		{
			key:   "Proxy-Connection", // just deleted and ignored
			value: []string{"keep-alive"},
			want:  "User-Agent",
		},
		{
			key:   "Content-Length",
			value: []string{"123"},
			want:  "User-Agent",
		},
		{
			key:   "Keep-Alive",
			value: []string{"doop"},
			want:  "User-Agent",
		},
	}

	for _, tt := range tests {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		for _, v := range tt.value {
			req.Header.Add(tt.key, v)
		}
		err = tr.Do(context.Background(), req, rsp)
		var got string
		if err != nil {
			got = fmt.Sprintf("ERROR: %v", err)
		} else {
			got = rsp.Header.Get("Got-Header")
		}
		if got != tt.want {
			t.Errorf("For key %q, value %q, got = %q; want %q", tt.key, tt.value, got, tt.want)
		}
	}
}

// Reject content-length headers containing a sign.
// See https://golang.org/issue/39017
func TestHostClientRejectsContentLengthWithSign(t *testing.T) {
	tests := []struct {
		name   string
		cl     []string
		wantCL string
	}{
		{
			name:   "proper content-length",
			cl:     []string{"3"},
			wantCL: "3",
		},
		{
			name:   "ignore cl with plus sign",
			cl:     []string{"+3"},
			wantCL: "-1",
		},
		{
			name:   "ignore cl with minus sign",
			cl:     []string{"-3"},
			wantCL: "-1",
		},
		{
			name:   "max int64, for safe uint64->int64 conversion",
			cl:     []string{"9223372036854775807"},
			wantCL: "9223372036854775807",
		},
		{
			name:   "overflows int64, so ignored",
			cl:     []string{"9223372036854775808"},
			wantCL: "-1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
				ctx.Response.Header.Set("Content-Length", tt.cl[0])
			}, optOnlyServer)
			defer st.Close()
			u, err := url.Parse("https://" + st.url)
			if err != nil {
				t.Fatal(err)
			}

			tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
			defer tr.CloseIdleConnections()

			req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
			req.SetRequestURI(u.String())
			req.SetMethod(consts.MethodHead)

			err = tr.Do(context.Background(), req, rsp)

			var got string
			if err != nil {
				got = fmt.Sprintf("ERROR: %v", err)
			} else {
				got = strconv.Itoa(rsp.Header.ContentLength())
			}

			if got != tt.wantCL {
				t.Fatalf("Got: %q\nWant: %q", got, tt.wantCL)
			}
		})
	}
}

// golang.org/issue/14048
func TestHostClientFailsOnInvalidHeaders(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		var got []string
		ctx.Request.Header.VisitAll(func(key, _ []byte) {
			got = append(got, string(key))
		})
		sort.Strings(got)
		ctx.Response.Header.Set("Got-Header", strings.Join(got, ","))
	}, optOnlyServer)
	defer st.Close()

	tests := [...]struct {
		h       http.Header
		wantErr string
	}{
		0: {
			h:       http.Header{"With space": {"foo"}},
			wantErr: `invalid HTTP header name "With space"`,
		},
		1: {
			h:       http.Header{"name": {"Брэд"}},
			wantErr: "", // okay
		},
		2: {
			h:       http.Header{"имя": {"Brad"}},
			wantErr: `invalid HTTP header name "имя"`,
		},
		3: {
			h:       http.Header{"Foo": {"foo\x01bar"}},
			wantErr: `invalid HTTP header value "foo\x01bar" for header "Foo"`,
		},
	}

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	for i, tt := range tests {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		for k, vv := range tt.h {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
		err = tr.Do(context.Background(), req, rsp)
		var bad bool
		if tt.wantErr == "" {
			if err != nil {
				bad = true
				t.Errorf("case %d: error = %v; want no error", i, err)
			}
		} else {
			if !strings.Contains(fmt.Sprint(err), tt.wantErr) {
				bad = true
				t.Errorf("case %d: error = %v; want error %q", i, err, tt.wantErr)
			}
		}
		if err == nil {
			if bad {
				t.Logf("case %d: server got headers %q", i, rsp.Header.Get("Got-Header"))
			}
		}
	}
}

func TestHostClientNewTLSConfig(t *testing.T) {
	tests := [...]struct {
		conf *tls.Config
		host string
		want *tls.Config
	}{
		// Normal case.
		0: {
			conf: nil,
			host: "foo.com",
			want: &tls.Config{
				ServerName: "foo.com",
				NextProtos: []string{NextProtoTLS},
				MinVersion: tls.VersionTLS12,
			},
		},

		// User-provided name (bar.com) takes precedence:
		1: {
			conf: &tls.Config{
				ServerName: "bar.com",
			},
			host: "foo.com",
			want: &tls.Config{
				ServerName: "bar.com",
				NextProtos: []string{NextProtoTLS},
			},
		},

		// NextProto is prepended:
		2: {
			conf: &tls.Config{
				NextProtos: []string{"foo", "bar"},
			},
			host: "example.com",
			want: &tls.Config{
				ServerName: "example.com",
				NextProtos: []string{NextProtoTLS, "foo", "bar"},
			},
		},

		// NextProto is not duplicated:
		3: {
			conf: &tls.Config{
				NextProtos: []string{"foo", "bar", NextProtoTLS},
			},
			host: "example.com",
			want: &tls.Config{
				ServerName: "example.com",
				NextProtos: []string{"foo", "bar", NextProtoTLS},
			},
		},
	}
	for i, tt := range tests {
		// Ignore the session ticket keys part, which ends up populating
		// unexported fields in the Config:
		if tt.conf != nil {
			tt.conf.SessionTicketsDisabled = true
		}

		got := newClientTLSConfig(tt.conf, tt.host)
		got.SessionTicketsDisabled = false

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d\n. got %#v\n; want %#v", i, got, tt.want)
		}
	}
}

// The Google GFE responds to HEAD requests with a HEADERS frame
// without END_STREAM, followed by a 0-length DATA frame with
// END_STREAM. Make sure we don't get confused by that. (We did.)
func TestHostClientReadHeadResponse(t *testing.T) {
	ct := newClientTester(t)
	clientDone := make(chan struct{})
	ct.client = func() error {
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodHead)
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}
		if rsp.Header.ContentLength() != 123 {
			return fmt.Errorf("Content-Length = %d; want 123", rsp.Header.ContentLength())
		}
		slurp, err := ioutil.ReadAll(rsp.BodyStream())
		if err != nil {
			return fmt.Errorf("ReadAll: %v", err)
		}
		if len(slurp) > 0 {
			return fmt.Errorf("Unexpected non-empty ReadAll body: %q", slurp)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				t.Logf("ReadFrame: %v", err)
				return nil
			}
			hf, ok := f.(*HeadersFrame)
			if !ok {
				continue
			}
			var buf bytes.Buffer
			enc := hpack.NewEncoder(&buf)
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "123"})
			ct.fr.WriteHeaders(HeadersFrameParam{
				StreamID:      hf.StreamID,
				EndHeaders:    true,
				EndStream:     false, // as the GFE does
				BlockFragment: buf.Bytes(),
			})
			ct.fr.WriteData(hf.StreamID, true, nil)

			<-clientDone
			return nil
		}
	}
	ct.run()
}

func TestHostClientReadHeadResponseWithBody(t *testing.T) {
	// This test use not valid response format.
	// Discarding logger output to not spam tests output.
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	response := "redirecting to /elsewhere"
	ct := newClientTester(t)
	clientDone := make(chan struct{})
	ct.client = func() error {
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodHead)
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}
		if rsp.Header.ContentLength() != len(response) {
			return fmt.Errorf("Content-Length = %d; want %d", rsp.Header.ContentLength(), len(response))
		}
		slurp, err := ioutil.ReadAll(rsp.BodyStream())
		if err != nil {
			return fmt.Errorf("ReadAll: %v", err)
		}
		if len(slurp) > 0 {
			return fmt.Errorf("Unexpected non-empty ReadAll body: %q", slurp)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				t.Logf("ReadFrame: %v", err)
				return nil
			}
			hf, ok := f.(*HeadersFrame)
			if !ok {
				continue
			}
			var buf bytes.Buffer
			enc := hpack.NewEncoder(&buf)
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			enc.WriteField(hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(response))})
			ct.fr.WriteHeaders(HeadersFrameParam{
				StreamID:      hf.StreamID,
				EndHeaders:    true,
				EndStream:     false,
				BlockFragment: buf.Bytes(),
			})
			ct.fr.WriteData(hf.StreamID, true, []byte(response))

			<-clientDone
			return nil
		}
	}
	ct.run()
}

type neverEnding byte

func (b neverEnding) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// golang.org/issue/15425: test that a handler closing the request
// body doesn't terminate the stream to the peer. (It just stops
// readability from the handler's side, and eventually the client
// runs out of flow control tokens)
func TestHostClientHandlerBodyClose(t *testing.T) {
	const bodySize = 10 << 20
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Request.BodyStream().(io.Closer).Close()
		ctx.Response.SetBodyStream(struct{ io.Reader }{io.LimitReader(neverEnding('A'), bodySize)}, -1)
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	g0 := runtime.NumGoroutine()

	const numReq = 10
	for i := 0; i < numReq; i++ {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodPost)
		req.SetRequestURI(u.String())
		req.SetBodyStream(struct{ io.Reader }{io.LimitReader(neverEnding('A'), bodySize)}, -1)
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatal(err)
		}
		n, err := io.Copy(ioutil.Discard, rsp.BodyStream())
		if n != bodySize || err != nil {
			t.Fatalf("req#%d: Copy = %d, %v; want %d, nil", i, n, err, bodySize)
		}
	}
	tr.CloseIdleConnections()

	if !waitCondition(5*time.Second, 100*time.Millisecond, func() bool {
		gd := runtime.NumGoroutine() - g0
		return gd < numReq/2
	}) {
		t.Errorf("appeared to leak goroutines")
	}
}

// https://golang.org/issue/15930
func TestHostClientFlowControl(t *testing.T) {
	const bufLen = 64 << 10
	var total int64 = 100 << 20 // 100MB
	if testing.Short() {
		total = 10 << 20
	}

	var wrote int64 // updated atomically
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, bufLen)
		for wrote < total {
			n, err := w.Write(b)
			atomic.AddInt64(&wrote, int64(n))
			if err != nil {
				t.Errorf("ResponseWriter.Write error: %v", err)
				break
			}
			w.(http.Flusher).Flush()
		}
	}, optOnlyServer)

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(st.ts.URL)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal("RoundTrip error:", err)
	}

	var read int64
	b := make([]byte, bufLen)
	for {
		n, err := rsp.BodyStream().Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("Read error:", err)
		}
		read += int64(n)

		const max = transportDefaultStreamFlow
		if w := atomic.LoadInt64(&wrote); -max > read-w || read-w > max {
			t.Fatalf("Too much data inflight: server wrote %v bytes but client only received %v", w, read)
		}

		// Let the server get ahead of the client.
		time.Sleep(1 * time.Millisecond)
	}
}

// golang.org/issue/14627 -- if the server sends a GOAWAY frame, make
// the Transport remember it and return it back to users (via
// RoundTrip or request body reads) if needed (e.g. if the server
// proceeds to close the TCP connection before the client gets its
// response)
func TestHostClientUsesGoAwayDebugError_RoundTrip(t *testing.T) {
	testHostClientUsesGoAwayDebugError(t, false)
}

func TestHostClientUsesGoAwayDebugError_Body(t *testing.T) {
	testHostClientUsesGoAwayDebugError(t, true)
}

func testHostClientUsesGoAwayDebugError(t *testing.T, failMidBody bool) {
	ct := newClientTester(t)
	clientDone := make(chan struct{})

	const goAwayErrCode = ErrCodeHTTP11Required // arbitrary
	const goAwayDebugData = "some debug data"

	ct.client = func() error {
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if failMidBody {
			if err != nil {
				return fmt.Errorf("unexpected client RoundTrip error: %v", err)
			}
			_, err = io.Copy(ioutil.Discard, rsp.BodyStream())
		}
		want := GoAwayError{
			LastStreamID: 5,
			ErrCode:      goAwayErrCode,
			DebugData:    goAwayDebugData,
		}
		if !reflect.DeepEqual(err, want) {
			t.Errorf("RoundTrip error = %T: %#v, want %T (%#v)", err, err, want, want)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				t.Logf("ReadFrame: %v", err)
				return nil
			}
			hf, ok := f.(*HeadersFrame)
			if !ok {
				continue
			}
			if failMidBody {
				var buf bytes.Buffer
				enc := hpack.NewEncoder(&buf)
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "123"})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      hf.StreamID,
					EndHeaders:    true,
					EndStream:     false,
					BlockFragment: buf.Bytes(),
				})
			}
			// Write two GOAWAY frames, to test that the Transport takes
			// the interesting parts of both.
			ct.fr.WriteGoAway(5, ErrCodeNo, []byte(goAwayDebugData))
			ct.fr.WriteGoAway(5, goAwayErrCode, nil)
			ct.sc.Close()
			if runtime.GOOS == "plan9" {
				// CloseWrite not supported on Plan 9; Issue 17906
				ct.sc.Close()
			}
			<-clientDone
			return nil
		}
	}
	ct.run()
}

func testHostClientReturnsUnusedFlowControl(t *testing.T, oneDataFrame bool) {
	ct := newClientTester(t)

	clientClosed := make(chan struct{})
	serverWroteFirstByte := make(chan struct{})

	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}
		<-serverWroteFirstByte

		if n, err := rsp.BodyStream().Read(make([]byte, 1)); err != nil || n != 1 {
			return fmt.Errorf("body read = %v, %v; want 1, nil", n, err)
		}
		rsp.CloseBodyStream()

		close(clientClosed)
		return nil
	}
	ct.server = func() error {
		ct.greet()

		var hf *HeadersFrame
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return fmt.Errorf("ReadFrame while waiting for Headers: %v", err)
			}
			switch f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
				continue
			}
			var ok bool
			hf, ok = f.(*HeadersFrame)
			if !ok {
				return fmt.Errorf("Got %T; want HeadersFrame", f)
			}
			break
		}

		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "5000"})
		ct.fr.WriteHeaders(HeadersFrameParam{
			StreamID:      hf.StreamID,
			EndHeaders:    true,
			EndStream:     false,
			BlockFragment: buf.Bytes(),
		})

		// Two cases:
		// - Send one DATA frame with 5000 bytes.
		// - Send two DATA frames with 1 and 4999 bytes each.
		//
		// In both cases, the client should consume one byte of data,
		// refund that byte, then refund the following 4999 bytes.
		//
		// In the second case, the server waits for the client connection to
		// close before seconding the second DATA frame. This tests the case
		// where the client receives a DATA frame after it has reset the stream.
		if oneDataFrame {
			ct.fr.WriteData(hf.StreamID, false /* don't end stream */, make([]byte, 5000))
			close(serverWroteFirstByte)
			<-clientClosed
		} else {
			ct.fr.WriteData(hf.StreamID, false /* don't end stream */, make([]byte, 1))
			close(serverWroteFirstByte)
			<-clientClosed
			ct.fr.WriteData(hf.StreamID, false /* don't end stream */, make([]byte, 4999))
		}

		waitingFor := "RSTStreamFrame"
		sawRST := false
		sawWUF := false
		for !sawRST && !sawWUF {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return fmt.Errorf("ReadFrame while waiting for %s: %v", waitingFor, err)
			}
			switch f := f.(type) {
			case *SettingsFrame:
			case *RSTStreamFrame:
				if sawRST {
					return fmt.Errorf("saw second RSTStreamFrame: %v", summarizeFrame(f))
				}
				if f.ErrCode != ErrCodeCancel {
					return fmt.Errorf("Expected a RSTStreamFrame with code cancel; got %v", summarizeFrame(f))
				}
				sawRST = true
			case *WindowUpdateFrame:
				if sawWUF {
					return fmt.Errorf("saw second WindowUpdateFrame: %v", summarizeFrame(f))
				}
				if f.Increment != 4999 {
					return fmt.Errorf("Expected WindowUpdateFrames for 5000 bytes; got %v", summarizeFrame(f))
				}
				sawWUF = true
			default:
				return fmt.Errorf("Unexpected frame: %v", summarizeFrame(f))
			}
		}
		return nil
	}
	ct.run()
}

// See golang.org/issue/16481
func TestHostClientReturnsUnusedFlowControlSingleWrite(t *testing.T) {
	testHostClientReturnsUnusedFlowControl(t, true)
}

// See golang.org/issue/20469
func TestHostClientReturnsUnusedFlowControlMultipleWrites(t *testing.T) {
	testHostClientReturnsUnusedFlowControl(t, false)
}

// Issue 16612: adjust flow control on open streams when transport
// receives SETTINGS with INITIAL_WINDOW_SIZE from server.
func TestHostClientAdjustsFlowControl(t *testing.T) {
	ct := newClientTester(t)
	clientDone := make(chan struct{})

	const bodySize = 1 << 20

	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod(consts.MethodPost)
		req.SetBodyStream(struct{ io.Reader }{io.LimitReader(neverEnding('A'), bodySize)}, -1)
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}
		return nil
	}
	ct.server = func() error {
		_, err := io.ReadFull(ct.sc, make([]byte, len(ClientPreface)))
		if err != nil {
			return fmt.Errorf("reading client preface: %v", err)
		}

		var gotBytes int64
		var sentSettings bool
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-clientDone:
					return nil
				default:
					return fmt.Errorf("ReadFrame while waiting for Headers: %v", err)
				}
			}
			switch f := f.(type) {
			case *DataFrame:
				gotBytes += int64(len(f.Data()))
				// After we've got half the client's
				// initial flow control window's worth
				// of request body data, give it just
				// enough flow control to finish.
				if gotBytes >= initialWindowSize/2 && !sentSettings {
					sentSettings = true

					ct.fr.WriteSettings(Setting{ID: SettingInitialWindowSize, Val: bodySize})
					ct.fr.WriteWindowUpdate(0, bodySize)
					ct.fr.WriteSettingsAck()
				}

				if f.StreamEnded() {
					var buf bytes.Buffer
					enc := hpack.NewEncoder(&buf)
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.StreamID,
						EndHeaders:    true,
						EndStream:     true,
						BlockFragment: buf.Bytes(),
					})
				}
			}
		}
	}
	ct.run()
}

// See golang.org/issue/16556
func TestHostClientReturnsDataPaddingFlowControl(t *testing.T) {
	ct := newClientTester(t)

	unblockClient := make(chan bool, 1)

	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}

		<-unblockClient
		return nil
	}
	ct.server = func() error {
		ct.greet()

		var hf *HeadersFrame
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return fmt.Errorf("ReadFrame while waiting for Headers: %v", err)
			}
			switch f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
				continue
			}
			var ok bool
			hf, ok = f.(*HeadersFrame)
			if !ok {
				return fmt.Errorf("Got %T; want HeadersFrame", f)
			}
			break
		}

		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "5000"})
		ct.fr.WriteHeaders(HeadersFrameParam{
			StreamID:      hf.StreamID,
			EndHeaders:    true,
			EndStream:     false,
			BlockFragment: buf.Bytes(),
		})
		pad := make([]byte, 5)
		ct.fr.WriteDataPadded(hf.StreamID, false, make([]byte, 5000), pad) // without ending stream

		f, err := ct.readNonSettingsFrame()
		if err != nil {
			return fmt.Errorf("ReadFrame while waiting for first WindowUpdateFrame: %v", err)
		}
		wantBack := uint32(len(pad)) + 1 // one byte for the length of the padding
		if wuf, ok := f.(*WindowUpdateFrame); !ok || wuf.Increment != wantBack || wuf.StreamID != 0 {
			return fmt.Errorf("Expected conn WindowUpdateFrame for %d bytes; got %v", wantBack, summarizeFrame(f))
		}

		f, err = ct.readNonSettingsFrame()
		if err != nil {
			return fmt.Errorf("ReadFrame while waiting for second WindowUpdateFrame: %v", err)
		}
		if wuf, ok := f.(*WindowUpdateFrame); !ok || wuf.Increment != wantBack || wuf.StreamID == 0 {
			return fmt.Errorf("Expected stream WindowUpdateFrame for %d bytes; got %v", wantBack, summarizeFrame(f))
		}
		unblockClient <- true
		return nil
	}
	ct.run()
}

// golang.org/issue/16572 -- RoundTrip shouldn't hang when it gets a
// StreamError as a result of the response HEADERS
func TestHostClientReturnsErrorOnBadResponseHeaders(t *testing.T) {
	ct := newClientTester(t)

	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err == nil {
			return errors.New("unexpected successful GET")
		}
		want := StreamError{1, ErrCodeProtocol, headerFieldNameError("  content-type")}
		if !reflect.DeepEqual(want, err) {
			t.Errorf("RoundTrip error = %#v; want %#v", err, want)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()

		hf, err := ct.firstHeaders()
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "  content-type", Value: "bogus"}) // bogus spaces
		ct.fr.WriteHeaders(HeadersFrameParam{
			StreamID:      hf.StreamID,
			EndHeaders:    true,
			EndStream:     false,
			BlockFragment: buf.Bytes(),
		})

		for {
			fr, err := ct.readFrame()
			if err != nil {
				return fmt.Errorf("error waiting for RST_STREAM from client: %v", err)
			}
			if _, ok := fr.(*SettingsFrame); ok {
				continue
			}
			if rst, ok := fr.(*RSTStreamFrame); !ok || rst.StreamID != 1 || rst.ErrCode != ErrCodeProtocol {
				t.Errorf("Frame = %v; want RST_STREAM for stream 1 with ErrCodeProtocol", summarizeFrame(fr))
			}
			break
		}

		return nil
	}
	ct.run()
}

// byteAndEOFReader returns is in an io.Reader which reads one byte
// (the underlying byte) and io.EOF at once in its Read call.
type byteAndEOFReader byte

func (b byteAndEOFReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		panic("unexpected useless call")
	}
	p[0] = byte(b)
	return 1, io.EOF
}

// Issue 16788: the Transport had a regression where it started
// sending a spurious DATA frame with a duplicate END_STREAM bit after
// the request body writer goroutine had already read an EOF from the
// Request.Body and included the END_STREAM on a data-carrying DATA
// frame.
//
// Notably, to trigger this, the requests need to use a Request.Body
// which returns (non-0, io.EOF) and also needs to set the ContentLength
// explicitly.
func TestHostClientBodyDoubleEndStream(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		// Nothing.
	}, optOnlyServer)
	defer st.Close()
	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	for i := 0; i < 2; i++ {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		req.SetMethod(consts.MethodPost)
		req.SetBodyStream(byteAndEOFReader('a'), 1)
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatalf("failure on req %d: %v", i+1, err)
		}
	}
}

// golang.org/issue/16847, golang.org/issue/19103
func TestHostClientRequestPathPseudo(t *testing.T) {
	type result struct {
		path string
		err  string
	}
	tests := []struct {
		reqFunc func(req *protocol.Request)
		want    result
	}{
		0: {
			reqFunc: func(req *protocol.Request) {
				req.SetHost("foo.com")
				req.URI().SetPath("/foo")
			},
			want: result{path: "/foo"},
		},
		// A CONNECT request:
		1: {
			reqFunc: func(req *protocol.Request) {
				req.SetMethod(consts.MethodConnect)
				req.SetHost("foo.com")
			},
			want: result{},
		},
	}
	for i, tt := range tests {
		cc := &clientConn{peerMaxHeaderListSize: 0xffffffffffffffff}
		cc.henc = hpack.NewEncoder(&cc.hbuf)
		cc.mu.Lock()
		req := protocol.AcquireRequest()
		tt.reqFunc(req)
		hdrs, err := cc.encodeHeaders(req, false, -1)
		cc.mu.Unlock()
		var got result
		hpackDec := hpack.NewDecoder(initialHeaderTableSize, func(f hpack.HeaderField) {
			if f.Name == ":path" {
				got.path = f.Value
			}
		})
		if err != nil {
			got.err = err.Error()
		} else if len(hdrs) > 0 {
			if _, err := hpackDec.Write(hdrs); err != nil {
				t.Errorf("%d. bogus hpack: %v", i, err)
				continue
			}
		}
		if got != tt.want {
			t.Errorf("%d. got %+v; want %+v", i, got, tt.want)
		}
	}
}

// golang.org/issue/17071 -- don't sniff the first byte of the request body
// before we've determined that the ClientConn is usable.
func TestRoundTripDoesntConsumeRequestBodyEarly(t *testing.T) {
	const body = "foo"
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod(consts.MethodPost)
	req.SetRequestURI("http://foo.com/")
	req.SetBodyStream(strings.NewReader(body), len(body))
	cc := &clientConn{
		closed:      true,
		reqHeaderMu: make(chan struct{}, 1),
	}
	err := cc.RoundTrip(context.Background(), req, rsp)
	if err != errClientConnUnusable {
		t.Fatalf("RoundTrip = %v; want errClientConnUnusable", err)
	}
	slurp, err := ioutil.ReadAll(req.BodyStream())
	if err != nil {
		t.Errorf("ReadAll = %v", err)
	}
	if string(slurp) != body {
		t.Errorf("Body = %q; want %q", slurp, body)
	}
}

func TestClientConnPing(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	cc, err := tr.acquireConn()
	if err != nil {
		t.Fatal(err)
	}
	if err = cc.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Issue 16974: if the server sent a DATA frame after the user
// canceled the Transport's Request, the Transport previously wrote to a
// closed pipe, got an error, and ended up closing the whole TCP
// connection.
func TestHostClientCancelDataResponseRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clientGotError := make(chan bool, 1)

	const msg = "Hello."
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/hello") {
			time.Sleep(50 * time.Millisecond)
			io.WriteString(w, msg)
			return
		}
		for i := 0; i < 50; i++ {
			io.WriteString(w, "Some data.")
			w.(http.Flusher).Flush()
			if i == 2 {
				cancel()
				<-clientGotError
			}
			time.Sleep(10 * time.Millisecond)
		}
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(st.ts.URL)
	err = tr.Do(ctx, req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(ioutil.Discard, rsp.BodyStream()); err == nil {
		t.Fatal("unexpected success")
	}
	clientGotError <- true

	req.Reset()
	rsp.Reset()
	req.SetRequestURI(st.ts.URL + "/hello")
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	slurp, err := ioutil.ReadAll(rsp.BodyStream())
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != msg {
		t.Errorf("Got = %q; want %q", slurp, msg)
	}
}

// Issue 21316: It should be safe to reuse an http.Request after the
// request has completed.

func TestHostClientNoRaceOnRequestObjectAfterRequestComplete(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.WriteString("body")
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(ioutil.Discard, rsp.BodyStream()); err != nil {
		t.Fatalf("error reading response body: %v", err)
	}

	// This access of req.Header should not race with code in the transport.
	req.Header = protocol.RequestHeader{}
}

func TestHostClientCloseAfterLostPing(t *testing.T) {
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	ct.tr.PingTimeout = 1 * time.Second
	ct.tr.ReadIdleTimeout = 1 * time.Second
	ct.client = func() error {
		defer ct.cc.Close()
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err == nil || !strings.Contains(err.Error(), "client connection lost") {
			return fmt.Errorf("expected to get error about \"connection lost\", got %v", err)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		<-clientDone
		return nil
	}
	ct.run()
}

func TestHostClientPingWriteBlocks(t *testing.T) {
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig:       tlsConfigInsecure,
			PingTimeout:     1 * time.Millisecond,
			ReadIdleTimeout: 1 * time.Millisecond,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				s, c := net.Pipe() // unbuffered, unlike a TCP conn
				go func() {
					// Read initial handshake frames.
					// Without this, we block indefinitely in newClientConn,
					// and never get to the point of sending a PING.
					var buf [1024]byte
					s.Read(buf[:])
				}()
				return newMockNetworkConn(c), nil
			}),
		},
		Addr: u.Host,
	}

	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if err == nil {
		t.Fatalf("Get = nil, want error")
	}
}

func TestHostClientPingWhenReading(t *testing.T) {
	testCases := []struct {
		name              string
		readIdleTimeout   time.Duration
		deadline          time.Duration
		expectedPingCount int
	}{
		{
			name:              "two pings",
			readIdleTimeout:   100 * time.Millisecond,
			deadline:          time.Second,
			expectedPingCount: 2,
		},
		{
			name:              "zero ping",
			readIdleTimeout:   time.Second,
			deadline:          200 * time.Millisecond,
			expectedPingCount: 0,
		},
		{
			name:              "0 readIdleTimeout means no ping",
			readIdleTimeout:   0 * time.Millisecond,
			deadline:          500 * time.Millisecond,
			expectedPingCount: 0,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			testHostClientPingWhenReading(t, tc.readIdleTimeout, tc.deadline, tc.expectedPingCount)
		})
	}
}

func testHostClientPingWhenReading(t *testing.T, readIdleTimeout, deadline time.Duration, expectedPingCount int) {
	var pingCount int
	ct := newClientTester(t)
	ct.tr.ReadIdleTimeout = readIdleTimeout

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(ctx, req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip: %v", err)
		}

		if rsp.StatusCode() != 200 {
			return fmt.Errorf("status code = %v; want %v", rsp.StatusCode(), 200)
		}
		_, err = ioutil.ReadAll(rsp.BodyStream())
		if expectedPingCount == 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil
		}

		cancel()
		return err
	}

	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		var streamID uint32
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-ctx.Done():
					// If the client's done, it
					// will have reported any
					// errors on its side.
					return nil
				default:
					return err
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
				if !f.HeadersEnded() {
					return fmt.Errorf("headers should have END_HEADERS be ended: %v", f)
				}
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(200)})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					EndHeaders:    true,
					EndStream:     false,
					BlockFragment: buf.Bytes(),
				})
				streamID = f.StreamID
			case *PingFrame:
				pingCount++
				if pingCount == expectedPingCount {
					if err := ct.fr.WriteData(streamID, true, []byte("hello, this is last server data frame")); err != nil {
						return err
					}
				}
				if err := ct.fr.WritePing(true, f.Data); err != nil {
					return err
				}
			case *RSTStreamFrame:
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

func TestHostClientRetryAfterGOAWAY(t *testing.T) {
	var dialer struct {
		sync.Mutex
		count int
	}
	ct1 := make(chan *clientTester)
	ct2 := make(chan *clientTester)

	ln := newLocalListener(t)
	defer ln.Close()

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig:        tlsConfigInsecure,
			RetryConfig:      &retry.Config{MaxAttemptTimes: 3},
			DisableKeepAlive: true,
		},
	}
	tr.Dialer = newMockDialerWithCustomFunc(standard.NewDialer(), func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
		dialer.Lock()
		defer dialer.Unlock()
		dialer.count++
		if dialer.count == 3 {
			return nil, errors.New("unexpected number of dials")
		}

		cc, err := standard.NewDialer().DialConnection("tcp", ln.Addr().String(), time.Second, nil)
		if err != nil {
			return nil, fmt.Errorf("dial error: %v", err)
		}

		sc, err := ln.Accept()
		if err != nil {
			return nil, fmt.Errorf("accept error: %v", err)
		}
		ct := &clientTester{
			t:  t,
			tr: tr,
			cc: cc,
			sc: newMockNetworkConn(sc),
		}
		ct.fr = NewFramer(sc, ct.sc)
		switch dialer.count {
		case 1:
			ct1 <- ct
		case 2:
			ct2 <- ct
		}
		return &testNetConn{Conn: cc}, nil
	})

	errs := make(chan error, 3)

	// Client.
	go func() {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := tr.Do(context.Background(), req, rsp)
		if got := rsp.Header.Get("Foo"); got != "bar" {
			err = fmt.Errorf("foo header = %q; want bar", got)
		}
		if err != nil {
			err = fmt.Errorf("RoundTrip: %v", err)
		}
		errs <- err
	}()

	connToClose := make(chan io.Closer, 2)

	// Server for the first request.
	go func() {
		ct := <-ct1

		connToClose <- ct.cc
		ct.greet()
		hf, err := ct.firstHeaders()
		if err != nil {
			errs <- fmt.Errorf("server1 failed reading HEADERS: %v", err)
			return
		}
		t.Logf("server1 got %v", hf)
		if err := ct.fr.WriteGoAway(0 /*max id*/, ErrCodeNo, nil); err != nil {
			errs <- fmt.Errorf("server1 failed writing GOAWAY: %v", err)
			return
		}
		errs <- nil
	}()

	// Server for the second request.
	go func() {
		ct := <-ct2

		connToClose <- ct.cc
		ct.greet()
		hf, err := ct.firstHeaders()
		if err != nil {
			errs <- fmt.Errorf("server2 failed reading HEADERS: %v", err)
			return
		}
		t.Logf("server2 got %v", hf)

		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "foo", Value: "bar"})
		err = ct.fr.WriteHeaders(HeadersFrameParam{
			StreamID:      hf.StreamID,
			EndHeaders:    true,
			EndStream:     false,
			BlockFragment: buf.Bytes(),
		})
		if err != nil {
			errs <- fmt.Errorf("server2 failed writing response HEADERS: %v", err)
		} else {
			errs <- nil
		}
	}()

	for k := 0; k < 3; k++ {
		err := <-errs
		if err != nil {
			t.Error(err)
		}
	}

	close(connToClose)
	for c := range connToClose {
		c.Close()
	}
}

func TestHostClientRetryAfterRefusedStream(t *testing.T) {
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip: %v", err)
		}
		rsp.CloseBodyStream()
		if rsp.StatusCode() != 204 {
			return fmt.Errorf("Status = %v; want 204", rsp.StatusCode())
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		nreq := 0

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-clientDone:
					// If the client's done, it
					// will have reported any
					// errors on its side.
					return nil
				default:
					return err
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
				if !f.HeadersEnded() {
					return fmt.Errorf("headers should have END_HEADERS be ended: %v", f)
				}
				nreq++
				if nreq == 1 {
					ct.fr.WriteRSTStream(f.StreamID, ErrCodeRefusedStream)
				} else {
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.StreamID,
						EndHeaders:    true,
						EndStream:     true,
						BlockFragment: buf.Bytes(),
					})
				}
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

func TestHostClientRetryHasLimit(t *testing.T) {
	// Skip in short mode because the total expected delay is 1s+2s+4s+8s+16s=29s.
	if testing.Short() {
		t.Skip("skipping long test in short mode")
	}
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		defer close(clientDone)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		if err == nil {
			return fmt.Errorf("RoundTrip expected error, got response: %+v", rsp)
		}
		t.Logf("expected error, got: %v", err)
		return nil
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-clientDone:
					// If the client's done, it
					// will have reported any
					// errors on its side.
					return nil
				default:
					return err
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
				if !f.HeadersEnded() {
					return fmt.Errorf("headers should have END_HEADERS be ended: %v", f)
				}
				ct.fr.WriteRSTStream(f.StreamID, ErrCodeRefusedStream)
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

func TestHostClientResponseDataBeforeHeaders(t *testing.T) {
	// This test use not valid response format.
	// Discarding logger output to not spam tests output.
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)

	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		// First request is normal to ensure the check is per stream and not per connection.
		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return fmt.Errorf("RoundTrip expected no error, got: %v", err)
		}
		// Second request returns a DATA frame with no HEADERS.
		err = ct.tr.Do(context.Background(), req, rsp)
		if err == nil {
			return fmt.Errorf("RoundTrip expected error, got response: %+v", rsp)
		}
		if err, ok := err.(StreamError); !ok || err.Code != ErrCodeProtocol {
			return fmt.Errorf("expected stream PROTOCOL_ERROR, got: %v", err)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		for {
			f, err := ct.fr.ReadFrame()
			if err == io.EOF {
				return nil
			} else if err != nil {
				return err
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame, *RSTStreamFrame:
			case *HeadersFrame:
				switch f.StreamID {
				case 1:
					// Send a valid response to first request.
					var buf bytes.Buffer
					enc := hpack.NewEncoder(&buf)
					enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
					ct.fr.WriteHeaders(HeadersFrameParam{
						StreamID:      f.StreamID,
						EndHeaders:    true,
						EndStream:     true,
						BlockFragment: buf.Bytes(),
					})
				case 3:
					ct.fr.WriteData(f.StreamID, true, []byte("payload"))
				}
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

func TestHostClientRequestsLowServerLimit(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	}, optOnlyServer)
	defer st.Close()

	var (
		connCountMu sync.Mutex
		connCount   int
	)

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, addr string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				connCountMu.Lock()
				defer connCountMu.Unlock()
				connCount++
				conn, err = standard.NewDialer().DialConnection("tcp", addr, time.Second, newClientTLSConfig(tlsConfigInsecure, addr))
				if err != nil {
					return nil, err
				}

				return &testNetConn{Conn: conn}, nil
			}),
			DisableKeepAlive: false,
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()

	const reqCount = 3
	for i := 0; i < reqCount; i++ {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI(u.String())
		err = tr.Do(context.Background(), req, rsp)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := rsp.StatusCode(), 200; got != want {
			t.Errorf("StatusCode = %v; want %v", got, want)
		}
	}

	if connCount != 1 {
		t.Errorf("created %v connections for %v requests, want 1", connCount, reqCount)
	}
}

// tests Transport.StrictMaxConcurrentStreams
func TestHostClientRequestsStallAtServerLimit(t *testing.T) {
	const maxConcurrent = 2

	greet := make(chan struct{})      // server sends initial SETTINGS frame
	gotRequest := make(chan struct{}) // server received a request
	clientDone := make(chan struct{})

	// Collect errors from goroutines.
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	defer func() {
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	}()

	// We will send maxConcurrent+2 requests. This checker goroutine waits for the
	// following stages:
	//   1. The first maxConcurrent requests are received by the server.
	//   2. The client will cancel the next request
	//   3. The server is unblocked so it can service the first maxConcurrent requests
	//   4. The client will send the final request
	wg.Add(1)
	unblockClient := make(chan struct{})
	clientRequestCancelled := make(chan struct{})
	unblockServer := make(chan struct{})
	go func() {
		defer wg.Done()
		// Stage 1.
		for k := 0; k < maxConcurrent; k++ {
			<-gotRequest
		}
		// Stage 2.
		close(unblockClient)
		<-clientRequestCancelled
		// Stage 3: give some time for the final RoundTrip call to be scheduled and
		// verify that the final request is not sent.
		time.Sleep(50 * time.Millisecond)
		select {
		case <-gotRequest:
			errs <- errors.New("last request did not stall")
			close(unblockServer)
			return
		default:
		}
		close(unblockServer)
		// Stage 4.
		<-gotRequest
	}()

	ct := newClientTester(t)
	ct.tr.StrictMaxConcurrentStreams = true
	ct.client = func() error {
		var wg sync.WaitGroup
		defer func() {
			wg.Wait()
			close(clientDone)
			ct.cc.Close()
			if runtime.GOOS == "plan9" {
				// CloseWrite not supported on Plan 9; Issue 17906
				ct.cc.Close()
			}
		}()
		for k := 0; k < maxConcurrent+2; k++ {
			wg.Add(1)
			go func(k int) {
				defer wg.Done()
				// Don't send the second request until after receiving SETTINGS from the server
				// to avoid a race where we use the default SettingMaxConcurrentStreams, which
				// is much larger than maxConcurrent. We have to send the first request before
				// waiting because the first request triggers the dial and greet.
				if k > 0 {
					<-greet
				}
				// Block until maxConcurrent requests are sent before sending any more.
				if k >= maxConcurrent {
					<-unblockClient
				}
				body := newStaticCloseChecker("")
				//	req, _ := http.NewRequest("GET", fmt.Sprintf("https://dummy.tld/%d", k), body)
				req := protocol.AcquireRequest()
				req.SetRequestURI(fmt.Sprintf("https://dummy.tld/%d", k))
				req.SetBodyStream(body, -1)
				if k == maxConcurrent {
					// This request will be canceled.
					ctx, cancel := context.WithCancel(context.Background())
					cancel()
					rsp := protocol.AcquireResponse()
					err := ct.tr.Do(ctx, req, rsp)
					close(clientRequestCancelled)
					if err == nil {
						errs <- fmt.Errorf("RoundTrip(%d) should have failed due to cancel", k)
						return
					}
				} else {
					rsp := protocol.AcquireResponse()
					err := ct.tr.Do(context.Background(), req, rsp)
					if err != nil {
						errs <- fmt.Errorf("RoundTrip(%d): %v", k, err)
						return
					}
					ioutil.ReadAll(rsp.BodyStream())
					rsp.CloseBodyStream()
					if rsp.StatusCode() != 204 {
						errs <- fmt.Errorf("Status = %v; want 204", rsp.StatusCode())
						return
					}
				}
				if err := body.isClosed(); err != nil {
					errs <- fmt.Errorf("RoundTrip(%d): %v", k, err)
				}
			}(k)
		}
		return nil
	}

	ct.server = func() error {
		var wg sync.WaitGroup
		defer wg.Wait()

		ct.greet(Setting{SettingMaxConcurrentStreams, maxConcurrent})

		// Server write loop.
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		writeResp := make(chan uint32, maxConcurrent+1)

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-unblockServer
			for id := range writeResp {
				buf.Reset()
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      id,
					EndHeaders:    true,
					EndStream:     true,
					BlockFragment: buf.Bytes(),
				})
			}
		}()

		// Server read loop.
		var nreq int
		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				select {
				case <-clientDone:
					// If the client's done, it will have reported any errors on its side.
					return nil
				default:
					return err
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame:
			case *SettingsFrame:
				// Wait for the client SETTINGS ack until ending the greet.
				close(greet)
			case *HeadersFrame:
				if !f.HeadersEnded() {
					return fmt.Errorf("headers should have END_HEADERS be ended: %v", f)
				}
				gotRequest <- struct{}{}
				nreq++
				writeResp <- f.StreamID
				if nreq == maxConcurrent+1 {
					close(writeResp)
				}
			case *DataFrame:
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}

	ct.run()
}

// Issue 20448: stop allocating for DATA frames' payload after
// Response.Body.Close is called.
func TestHostClientAllocationsAfterResponseBodyClose(t *testing.T) {
	megabyteZero := make([]byte, 1<<20)

	writeErr := make(chan error, 1)

	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		var sum int64
		for i := 0; i < 100; i++ {
			n, err := w.Write(megabyteZero)
			sum += int64(n)
			if err != nil {
				writeErr <- err
				return
			}
		}
		t.Logf("wrote all %d bytes", sum)
		writeErr <- nil
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := rsp.BodyStream().Read(buf[:]); err != nil {
		t.Error(err)
	}

	if err := rsp.BodyStream().(io.Closer).Close(); err != nil {
		t.Error(err)
	}

	trb, ok := rsp.BodyStream().(transportResponseBody)
	if !ok {
		t.Fatalf("res.Body = %T; want transportResponseBody", rsp.BodyStream())
	}
	if trb.cs.bufPipe.b != nil {
		t.Errorf("response body pipe is still open")
	}

	gotErr := <-writeErr
	if gotErr == nil {
		t.Errorf("Handler unexpectedly managed to write its entire response without getting an error")
	} else if gotErr.Error() != errStreamClosed.Error() {
		t.Errorf("Handler Write err = %v; want errStreamClosed", gotErr)
	}
}

// Issue 18891: make sure Request.Body == NoBody means no DATA frame
// is ever sent, even if empty.
func TestHostClientNoBodyMeansNoDATA(t *testing.T) {
	ct := newClientTester(t)

	unblockClient := make(chan bool)

	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		req.SetBodyStream(protocol.NoBody, -1)
		ct.tr.Do(context.Background(), req, rsp)
		<-unblockClient
		return nil
	}
	ct.server = func() error {
		defer close(unblockClient)
		defer ct.cc.Close()
		ct.greet()

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return fmt.Errorf("ReadFrame while waiting for Headers: %v", err)
			}
			switch f := f.(type) {
			default:
				return fmt.Errorf("Got %T; want HeadersFrame", f)
			case *WindowUpdateFrame, *SettingsFrame:
				continue
			case *HeadersFrame:
				if !f.StreamEnded() {
					return fmt.Errorf("got headers frame without END_STREAM")
				}
				return nil
			}
		}
	}
	ct.run()
}

type infiniteReader struct{}

func (r infiniteReader) Read(b []byte) (int, error) {
	return len(b), nil
}

// Issue 20521: it is not an error to receive a response and end stream
// from the server without the body being consumed.
func TestHostClientResponseAndResetWithoutConsumingBodyRace(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod(consts.MethodPut)
	req.SetBodyStream(infiniteReader{}, -1)
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}

	if rsp.StatusCode() != consts.StatusOK {
		t.Fatalf("Response code = %v; want %v", rsp.StatusCode(), consts.StatusOK)
	}
}

// Verify transport doesn't crash when receiving bogus response lacking a :status header.
// Issue 22880.
func TestHostClientHandlesInvalidStatuslessResponse(t *testing.T) {
	ct := newClientTester(t)
	ct.client = func() error {
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		err := ct.tr.Do(context.Background(), req, rsp)
		const substr = "malformed response from server: missing status pseudo header"
		if !strings.Contains(fmt.Sprint(err), substr) {
			return fmt.Errorf("RoundTrip error = %v; want substring %q", err, substr)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}
			switch f := f.(type) {
			case *HeadersFrame:
				enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/html"}) // no :status header
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.StreamID,
					EndHeaders:    true,
					EndStream:     false, // we'll send some DATA to try to crash the transport
					BlockFragment: buf.Bytes(),
				})
				ct.fr.WriteData(f.StreamID, true, []byte("payload"))
				return nil
			}
		}
	}
	ct.run()
}

func activeStreams(cc *clientConn) int {
	count := 0
	cc.mu.Lock()
	defer cc.mu.Unlock()
	for _, cs := range cc.streams {
		select {
		case <-cs.abort:
		default:
			count++
		}
	}
	return count
}

type closeMode int

const (
	closeAtHeaders closeMode = iota
	closeAtBody
	shutdown
	shutdownCancel
)

// See golang.org/issue/17292
func testClientConnClose(t *testing.T, closeMode closeMode) {
	clientDone := make(chan struct{})
	defer close(clientDone)
	handlerDone := make(chan struct{})
	closeDone := make(chan struct{})
	beforeHeader := func() {}
	bodyWrite := func(w http.ResponseWriter) {}
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		beforeHeader()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		bodyWrite(w)

		select {
		case <-r.Context().Done():
			// client closed connection before completion
			if closeMode == shutdown || closeMode == shutdownCancel {
				t.Error("expected request to complete")
			}
		case <-clientDone:
			if closeMode == closeAtHeaders || closeMode == closeAtBody {
				t.Error("expected connection closed by client")
			}
		}
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	ctx := context.Background()
	cc, err := tr.acquireConn()
	req := protocol.AcquireRequest()
	req.SetRequestURI(st.ts.URL)

	if err != nil {
		t.Fatal(err)
	}
	if closeMode == closeAtHeaders {
		beforeHeader = func() {
			if err := cc.Close(); err != nil {
				t.Error(err)
			}
			close(closeDone)
		}
	}
	var sendBody chan struct{}
	if closeMode == closeAtBody {
		sendBody = make(chan struct{})
		bodyWrite = func(w http.ResponseWriter) {
			<-sendBody
			b := make([]byte, 32)
			w.Write(b)
			w.(http.Flusher).Flush()
			if err := cc.Close(); err != nil {
				t.Errorf("unexpected ClientConn close error: %v", err)
			}
			close(closeDone)
			w.Write(b)
			w.(http.Flusher).Flush()
		}
	}
	rsp := protocol.AcquireResponse()
	err = tr.Do(ctx, req, rsp)

	if closeMode == closeAtHeaders {
		got := fmt.Sprint(err)
		want := "http2: client connection force closed via ClientConn.Close"
		if got != want {
			t.Fatalf("RoundTrip error = %v, want %v", got, want)
		}
	} else {
		if err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if got, want := activeStreams(cc), 1; got != want {
			t.Errorf("got %d active streams, want %d", got, want)
		}
	}
	switch closeMode {
	case shutdownCancel:
		if err = cc.Shutdown(canceledCtx); err != context.Canceled {
			t.Errorf("got %v, want %v", err, context.Canceled)
		}
		if cc.closing == false {
			t.Error("expected closing to be true")
		}
		if cc.CanTakeNewRequest() == true {
			t.Error("CanTakeNewRequest to return false")
		}
		if v, want := len(cc.streams), 1; v != want {
			t.Errorf("expected %d active streams, got %d", want, v)
		}
		clientDone <- struct{}{}
		<-handlerDone
	case shutdown:
		wait := make(chan struct{})
		shutdownEnterWaitStateHook = func() {
			close(wait)
			shutdownEnterWaitStateHook = func() {}
		}
		defer func() { shutdownEnterWaitStateHook = func() {} }()
		shutdown := make(chan struct{}, 1)
		go func() {
			if err = cc.Shutdown(context.Background()); err != nil {
				t.Error(err)
			}
			close(shutdown)
		}()
		// Let the shutdown to enter wait state
		<-wait
		cc.mu.Lock()
		if cc.closing == false {
			t.Error("expected closing to be true")
		}
		cc.mu.Unlock()
		if cc.CanTakeNewRequest() == true {
			t.Error("CanTakeNewRequest to return false")
		}
		if got, want := activeStreams(cc), 1; got != want {
			t.Errorf("got %d active streams, want %d", got, want)
		}
		// Let the active request finish
		clientDone <- struct{}{}
		// Wait for the shutdown to end
		select {
		case <-shutdown:
		case <-time.After(2 * time.Second):
			t.Fatal("expected server connection to close")
		}
	case closeAtHeaders, closeAtBody:
		if closeMode == closeAtBody {
			go close(sendBody)
			if _, err := io.Copy(ioutil.Discard, rsp.BodyStream()); err == nil {
				t.Error("expected a Copy error, got nil")
			}
		}
		<-closeDone
		if got, want := activeStreams(cc), 0; got != want {
			t.Errorf("got %d active streams, want %d", got, want)
		}
		// wait for server to get the connection close notice
		select {
		case <-handlerDone:
		case <-time.After(2 * time.Second):
			t.Fatal("expected server connection to close")
		}
	}
}

// The client closes the connection just after the server got the client's HEADERS
// frame, but before the server sends its HEADERS response back. The expected
// result is an error on RoundTrip explaining the client closed the connection.
func TestClientConnCloseAtHeaders(t *testing.T) {
	testClientConnClose(t, closeAtHeaders)
}

// The client closes the connection between two server's response DATA frames.
// The expected behavior is a response body io read error on the client.
func TestClientConnCloseAtBody(t *testing.T) {
	testClientConnClose(t, closeAtBody)
}

// The client sends a GOAWAY frame before the server finished processing a request.
// We expect the connection not to close until the request is completed.
func TestClientConnShutdown(t *testing.T) {
	testClientConnClose(t, shutdown)
}

// The client sends a GOAWAY frame before the server finishes processing a request,
// but cancels the passed context before the request is completed. The expected
// behavior is the client closing the connection after the context is canceled.
func TestClientConnShutdownCancel(t *testing.T) {
	testClientConnClose(t, shutdownCancel)
}

type errReader struct {
	body []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.body) > 0 {
		n := copy(p, r.body)
		r.body = r.body[n:]
		return n, nil
	}
	return 0, r.err
}

func testHostClientBodyReadError(t *testing.T, body []byte) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		// So far we've only seen this be flaky on Windows and Plan 9,
		// perhaps due to TCP behavior on shutdowns while
		// unread data is in flight. This test should be
		// fixed, but a skip is better than annoying people
		// for now.
		t.Skipf("skipping flaky test on %s; https://golang.org/issue/31260", runtime.GOOS)
	}
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		defer close(clientDone)

		checkNoStreams := func() error {
			ct.tr.lck.Lock()
			defer ct.tr.lck.Unlock()
			conns := ct.tr.conns
			if conns.Len() != 1 {
				return fmt.Errorf("conn pool size: %v; expect 1", conns.Len())
			}
			if activeStreams(conns.Front().Value.(*clientConn)) != 0 {
				return fmt.Errorf("active streams count: %v; want 0", activeStreams(conns.Front().Value.(*clientConn)))
			}
			return nil
		}
		bodyReadError := errors.New("body read error")
		body := &errReader{body, bodyReadError}
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		req.SetBodyStream(body, -1)
		req.SetMethod(consts.MethodPut)

		err := ct.tr.Do(context.Background(), req, rsp)
		if err != bodyReadError {
			return fmt.Errorf("err = %v; want %v", err, bodyReadError)
		}
		if err = checkNoStreams(); err != nil {
			return err
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		var receivedBody []byte
		var resetCount int
		for {
			f, err := ct.fr.ReadFrame()
			t.Logf("server: ReadFrame = %v, %v", f, err)
			if err != nil {
				select {
				case <-clientDone:
					// If the client's done, it
					// will have reported any
					// errors on its side.
					if !bytes.Equal(receivedBody, body) {
						return fmt.Errorf("body: %q; expected %q", receivedBody, body)
					}
					if resetCount != 1 {
						return fmt.Errorf("stream reset count: %v; expected: 1", resetCount)
					}
					return nil
				default:
					return err
				}
			}
			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
			case *DataFrame:
				receivedBody = append(receivedBody, f.Data()...)
			case *RSTStreamFrame:
				resetCount++
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

func TestHostClientBodyReadError_Immediately(t *testing.T) {
	testHostClientBodyReadError(t, nil)
}

func TestHostClientBodyReadError_Some(t *testing.T) {
	testHostClientBodyReadError(t, []byte("123"))
}

// Issue 32254: verify that the client sends END_STREAM flag eagerly with the last
// (or in this test-case the only one) request body data frame, and does not send
// extra zero-len data frames.
func TestHostClientBodyEagerEndStream(t *testing.T) {
	const reqBody = "some request body"
	const resBody = "some response body"

	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		if runtime.GOOS == "plan9" {
			// CloseWrite not supported on Plan 9; Issue 17906
			defer ct.cc.Close()
		}
		body := strings.NewReader(reqBody)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		req.SetBodyStream(body, len(reqBody))
		req.SetMethod(consts.MethodPut)

		err := ct.tr.Do(context.Background(), req, rsp)
		if err != nil {
			return err
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()

		for {
			f, err := ct.fr.ReadFrame()
			if err != nil {
				return err
			}

			switch f := f.(type) {
			case *WindowUpdateFrame, *SettingsFrame:
			case *HeadersFrame:
			case *DataFrame:
				if !f.StreamEnded() {
					ct.fr.WriteRSTStream(f.StreamID, ErrCodeRefusedStream)
					return fmt.Errorf("data frame without END_STREAM %v", f)
				}
				var buf bytes.Buffer
				enc := hpack.NewEncoder(&buf)
				enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				ct.fr.WriteHeaders(HeadersFrameParam{
					StreamID:      f.Header().StreamID,
					EndHeaders:    true,
					EndStream:     false,
					BlockFragment: buf.Bytes(),
				})
				ct.fr.WriteData(f.StreamID, true, []byte(resBody))
				return nil
			case *RSTStreamFrame:
			default:
				return fmt.Errorf("Unexpected client frame %v", f)
			}
		}
	}
	ct.run()
}

type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) > 0 {
		n := copy(p, r.chunks[0])
		r.chunks = r.chunks[1:]
		return n, nil
	}
	panic("shouldn't read this many times")
}

// Issue 32254: if the request body is larger than the specified
// content length, the client should refuse to send the extra part
// and abort the stream.
//
// In _len3 case, the first Read() matches the expected content length
// but the second read returns more data.
//
// In _len2 case, the first Read() exceeds the expected content length.
func TestHostClientBodyLargerThanSpecifiedContentLength_len3(t *testing.T) {
	body := &chunkReader{[][]byte{
		[]byte("123"),
		[]byte("456"),
	}}
	testHostClientBodyLargerThanSpecifiedContentLength(t, body, 3)
}

func TestHostClientBodyLargerThanSpecifiedContentLength_len2(t *testing.T) {
	body := &chunkReader{[][]byte{
		[]byte("123"),
	}}
	testHostClientBodyLargerThanSpecifiedContentLength(t, body, 2)
}

func testHostClientBodyLargerThanSpecifiedContentLength(t *testing.T, body *chunkReader, contentLen int64) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Request.BodyStream().Read(make([]byte, 6))
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod(consts.MethodPost)
	req.SetRequestURI(u.String())
	req.SetBodyStream(body, int(contentLen))
	err = tr.Do(context.Background(), req, rsp)
	if err != errReqBodyTooLong {
		t.Fatalf("expected %v, got %v", errReqBodyTooLong, err)
	}
}

func TestClientConnTooIdle(t *testing.T) {
	tests := []struct {
		cc   func() *clientConn
		want bool
	}{
		{
			func() *clientConn {
				return &clientConn{idleTimeout: 5 * time.Second, lastIdle: time.Now().Add(-10 * time.Second)}
			},
			true,
		},
		{
			func() *clientConn {
				return &clientConn{idleTimeout: 5 * time.Second, lastIdle: time.Time{}}
			},
			false,
		},
		{
			func() *clientConn {
				return &clientConn{idleTimeout: 60 * time.Second, lastIdle: time.Now().Add(-10 * time.Second)}
			},
			false,
		},
		{
			func() *clientConn {
				return &clientConn{idleTimeout: 0, lastIdle: time.Now().Add(-10 * time.Second)}
			},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.cc().tooIdleLocked()
		if got != tt.want {
			t.Errorf("%d. got %v; want %v", i, got, tt.want)
		}
	}
}

type fakeConnErr struct {
	network.Conn
	writeErr error
	closed   bool
}

func (fce *fakeConnErr) Write(b []byte) (n int, err error) {
	return 0, fce.writeErr
}

func (fce *fakeConnErr) Close() error {
	fce.closed = true
	return nil
}

func (fce *fakeConnErr) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("126.0.0.5"),
		Port: 8888,
		Zone: "",
	}
}

// issue 39337: close the connection on a failed write
func TestHostClientNewClientConnCloseOnWriteError(t *testing.T) {
	tr := &HostClient{ClientConfig: &config.ClientConfig{DisableKeepAlive: true}}
	writeErr := errors.New("write error")
	fakeConn := &fakeConnErr{writeErr: writeErr}
	_, err := tr.newClientConn(fakeConn, false)
	if err != writeErr {
		t.Fatalf("expected %v, got %v", writeErr, err)
	}
	if !fakeConn.closed {
		t.Error("expected closed conn")
	}
}

func TestHostClientRoundtripCloseOnWriteError(t *testing.T) {
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI("https://dummy.tld/")

	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	ctx := context.Background()
	cc, err := tr.acquireConn()
	if err != nil {
		t.Fatal(err)
	}

	writeErr := errors.New("write error")
	cc.wmu.Lock()
	cc.werr = writeErr
	cc.wmu.Unlock()

	err = cc.RoundTrip(ctx, req, rsp)
	if err != writeErr {
		t.Fatalf("expected %v, got %v", writeErr, err)
	}

	cc.mu.Lock()
	closed := cc.closed
	cc.mu.Unlock()
	if !closed {
		t.Fatal("expected closed")
	}
}

type errorReader struct{ err error }

func (r errorReader) Read(p []byte) (int, error) { return 0, r.err }

// Issue 42498: A request with a body will never be sent if the stream is
// reset prior to sending any data.
func TestHostClientServerResetStreamAtHeaders(t *testing.T) {
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Status(http.StatusUnauthorized)
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,

			Dialer: standard.NewDialer(),
		},
		IsTLS: true,
		Addr:  u.Host,
	}

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod(consts.MethodPost)
	req.SetRequestURI(u.String())
	req.SetBodyStream(errorReader{io.EOF}, 0)
	req.Header.Set("Expect", "100-continue")
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
}

type closeChecker struct {
	io.ReadCloser
	closed chan struct{}
}

func newCloseChecker(r io.ReadCloser) *closeChecker {
	return &closeChecker{r, make(chan struct{})}
}

func newStaticCloseChecker(body string) *closeChecker {
	return newCloseChecker(ioutil.NopCloser(strings.NewReader("body")))
}

func (rc *closeChecker) Read(b []byte) (n int, err error) {
	select {
	default:
	case <-rc.closed:
		// TODO: Consider restructuring the request write to avoid reading
		// from the request body after closing it, and check for read-after-close here.
		// Currently, abortRequestBodyWrite races with writeRequestBody.
		return 0, errors.New("read after Body.Close")
	}
	return rc.ReadCloser.Read(b)
}

func (rc *closeChecker) Close() error {
	close(rc.closed)
	return rc.ReadCloser.Close()
}

func (rc *closeChecker) isClosed() error {
	// The RoundTrip contract says that it will close the request body,
	// but that it may do so in a separate goroutine. Wait a reasonable
	// amount of time before concluding that the body isn't being closed.
	timeout := time.Duration(10 * time.Second)
	select {
	case <-rc.closed:
	case <-time.After(timeout):
		return fmt.Errorf("body not closed after %v", timeout)
	}
	return nil
}

// A blockingWriteConn is a net.Conn that blocks in Write after some number of bytes are written.

type blockingWriteConn struct {
	network.Conn
	writeOnce    sync.Once
	writec       chan struct{} // closed after the write limit is reached
	unblockc     chan struct{} // closed to unblock writes
	count, limit int
}

func newBlockingWriteConn(conn network.Conn, limit int) *blockingWriteConn {
	return &blockingWriteConn{
		Conn:     conn,
		limit:    limit,
		writec:   make(chan struct{}),
		unblockc: make(chan struct{}),
	}
}

// wait waits until the conn blocks writing the limit+1st byte.

func (c *blockingWriteConn) wait() {
	<-c.writec
}

// unblock unblocks writes to the conn.

func (c *blockingWriteConn) unblock() {
	close(c.unblockc)
}

func (c *blockingWriteConn) Write(b []byte) (n int, err error) {
	if c.count+len(b) > c.limit {
		c.writeOnce.Do(func() {
			close(c.writec)
		})
		<-c.unblockc
	}
	n, err = c.Conn.Write(b)
	c.count += n
	return n, err
}

// Write several requests to a ClientConn at the same time, looking for race conditions.
// See golang.org/issue/48340
func TestHostClientFrameBufferReuse(t *testing.T) {
	filler := hex.EncodeToString([]byte(randString(2048)))

	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		if got, want := ctx.Request.Header.Get("Big"), filler; got != want {
			t.Errorf(`r.Header.Get("Big") = %q, want %q`, got, want)
		}
		b, err := ctx.Body()
		if err != nil {
			t.Errorf("error reading request body: %v", err)
		}
		if got, want := string(b), filler; got != want {
			t.Errorf("request body = %q, want %q", got, want)
		}
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()
	errs := make(chan error, 1)
	var wg sync.WaitGroup
	defer wg.Wait()
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
			req.SetRequestURI(u.String())
			req.SetMethod(consts.MethodPost)
			req.SetBodyStream(strings.NewReader(filler), len(filler))
			req.Header.Set("Big", filler)
			err := tr.Do(context.Background(), req, rsp)
			if err != nil {
				errs <- err
			}

			if got, want := rsp.StatusCode(), 200; got != want {
				t.Errorf("StatusCode = %v; want %v", got, want)
			}
		}()
	}
	select {
	case err = <-errs:
		if err != nil {
			t.Fatal(err)
		}
	// deadlock? that's a bug.
	case <-time.After(3 * time.Second):
		return
	}
}

// Ensure that a request blocking while being written to the underlying net.Conn doesn't
// block access to the ClientConn pool. Test requests blocking while writing headers, the body,
// and trailers.
// See golang.org/issue/32388
func TestHostClientBlockingRequestWrite(t *testing.T) {
	filler := hex.EncodeToString([]byte(randString(2048)))
	for _, test := range []struct {
		name string
		req  func(url string) (*protocol.Request, error)
	}{{
		name: "headers",
		req: func(url string) (*protocol.Request, error) {
			req := protocol.AcquireRequest()
			req.SetMethod(consts.MethodPost)
			req.SetRequestURI(url)
			req.Header.Set("Big", filler)
			return req, nil
		},
	}, {
		name: "body",
		req: func(url string) (*protocol.Request, error) {
			req := protocol.AcquireRequest()
			req.SetMethod(consts.MethodPost)
			req.SetRequestURI(url)
			req.SetBodyStream(strings.NewReader(filler), len(filler))
			return req, nil
		},
	}} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
				if v := ctx.Request.Header.Get("Big"); v != "" && v != filler {
					t.Errorf("request header mismatch")
				}
				if v, _ := ctx.Body(); len(v) != 0 && string(v) != "body" && string(v) != filler {
					t.Errorf("request body mismatch\ngot:  %q\nwant: %q", string(v), filler)
				}
				if v := ctx.Request.Header.Trailer().Get("Big"); v != "" && v != filler {
					t.Errorf("request trailer mismatch\ngot:  %q\nwant: %q", string(v), filler)
				}
			}, optOnlyServer, config.WithMaxConcurrentStreams(1))
			defer st.Close()

			// This Transport creates connections that block on writes after 1024 bytes.
			connc := make(chan *blockingWriteConn, 1)
			connCount := 0

			u, err := url.Parse("https://" + st.url)
			if err != nil {
				t.Fatal(err)
			}

			tr := &HostClient{
				ClientConfig: &config.ClientConfig{
					TLSConfig: tlsConfigInsecure,
					Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, addr string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
						connCount++
						conn, err = standard.NewDialer().DialConnection("tcp", addr, time.Second, newClientTLSConfig(tlsConfigInsecure, addr))
						if err != nil {
							return nil, err
						}
						wc := newBlockingWriteConn(&testNetConn{Conn: conn}, 1024)
						select {
						case connc <- wc:
						default:
						}
						return wc, err
					}),
				},
				Addr: u.Host,
			}
			defer tr.CloseIdleConnections()

			// Request 1: A small request to ensure we read the server MaxConcurrentStreams.
			{
				req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
				req.SetRequestURI(u.String())
				req.SetMethod(consts.MethodPost)
				err = tr.Do(context.Background(), req, rsp)
				if err != nil {
					t.Fatal(err)
				}

				if got, want := rsp.StatusCode(), 200; got != want {
					t.Errorf("StatusCode = %v; want %v", got, want)
				}
			}

			// Request 2: A large request that blocks while being written.
			reqc := make(chan struct{})
			go func() {
				defer close(reqc)
				req, err := test.req(u.String())
				if err != nil {
					t.Error(err)
					return
				}
				rsp := protocol.AcquireResponse()
				tr.Do(context.Background(), req, rsp)
			}()
			conn := <-connc
			conn.wait() // wait for the request to block

			// Request 3: A small request that is sent on a new connection, since request 2
			// is hogging the only available stream on the previous connection.
			{

				req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
				req.SetRequestURI(u.String())
				req.SetMethod(consts.MethodPost)
				err = tr.Do(context.Background(), req, rsp)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := rsp.StatusCode(), 200; got != want {
					t.Errorf("StatusCode = %v; want %v", got, want)
				}
			}

			// Request 2 should still be blocking at this point.
			select {
			case <-reqc:
				t.Errorf("request 2 unexpectedly completed")
			default:
			}

			conn.unblock()
			<-reqc

			if connCount != 2 {
				t.Errorf("created %v connections, want 1", connCount)
			}
		})
	}
}

func TestClientConnReservations(t *testing.T) {
	cc := &clientConn{
		reqHeaderMu:          make(chan struct{}, 1),
		streams:              make(map[uint32]*clientStream),
		maxConcurrentStreams: initialMaxConcurrentStreams,
		nextStreamID:         1,
		hc:                   &HostClient{ClientConfig: &config.ClientConfig{}},
	}
	cc.cond = sync.NewCond(&cc.mu)
	n := 0
	for n <= initialMaxConcurrentStreams && cc.ReserveNewRequest() {
		n++
	}
	if n != initialMaxConcurrentStreams {
		t.Errorf("did %v reservations; want %v", n, initialMaxConcurrentStreams)
	}
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	if err := cc.RoundTrip(context.Background(), req, rsp); !errors.Is(err, errNilRequestURL) {
		t.Fatalf("RoundTrip error = %v; want errNilRequestURL", err)
	}
	n2 := 0
	for n2 <= 5 && cc.ReserveNewRequest() {
		n2++
	}
	if n2 != 1 {
		t.Fatalf("after one RoundTrip, did %v reservations; want 1", n2)
	}

	// Use up all the reservations
	for i := 0; i < n; i++ {
		req, rsp = protocol.AcquireRequest(), protocol.AcquireResponse()
		cc.RoundTrip(context.Background(), req, rsp)
	}

	n2 = 0
	for n2 <= initialMaxConcurrentStreams && cc.ReserveNewRequest() {
		n2++
	}
	if n2 != n {
		t.Errorf("after reset, reservations = %v; want %v", n2, n)
	}
}

func TestHostClientTimeoutServerHangs(t *testing.T) {
	clientDone := make(chan struct{})
	ct := newClientTester(t)
	ct.client = func() error {
		defer ct.cc.Close()
		defer close(clientDone)

		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetRequestURI("https://dummy.tld/")
		req.SetMethod(consts.MethodPut)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		req.Header.Add("Big", strings.Repeat("a", 1<<20))
		err := ct.tr.Do(ctx, req, rsp)
		if err == nil {
			return errors.New("error should not be nil")
		}
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			return fmt.Errorf("error should be a net error timeout: %v", err)
		}
		return nil
	}
	ct.server = func() error {
		ct.greet()
		select {
		case <-time.After(5 * time.Second):
		case <-clientDone:
		}
		return nil
	}
	ct.run()
}

func TestHostClientContentLengthWithoutBody(t *testing.T) {
	contentLength := ""
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		ctx.Response.Header.Set("Content-Length", contentLength)
	}, optOnlyServer)
	defer st.Close()
	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	for _, test := range []struct {
		name              string
		contentLength     string
		wantBody          string
		wantErr           error
		wantContentLength int64
	}{
		{
			name:              "non-zero content length",
			contentLength:     "42",
			wantErr:           io.ErrUnexpectedEOF,
			wantContentLength: 42,
		},
		{
			name:              "zero content length",
			contentLength:     "0",
			wantErr:           nil,
			wantContentLength: 0,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			contentLength = test.contentLength

			req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
			req.SetRequestURI(u.String())
			err = tr.Do(context.Background(), req, rsp)
			if err != nil {
				t.Fatal(err)
			}
			body, err := ioutil.ReadAll(rsp.BodyStream())

			if err != test.wantErr {
				t.Errorf("Expected error %v, got: %v", test.wantErr, err)
			}
			if len(body) > 0 {
				t.Errorf("Expected empty body, got: %v", body)
			}
			if int64(rsp.Header.ContentLength()) != test.wantContentLength {
				t.Errorf("Expected content length %d, got: %d", test.wantContentLength, int64(rsp.Header.ContentLength()))
			}
		})
	}
}

func TestHostClientCloseResponseBodyWhileRequestBodyHangs(t *testing.T) {
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		io.Copy(ioutil.Discard, r.Body)
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	pr, pw := net.Pipe()
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(st.ts.URL)
	req.SetBodyStream(pr, -1)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}

	pw.Close()
}

func TestHostClient300ResponseBody(t *testing.T) {
	reqc := make(chan struct{})
	body := []byte("response body")
	st := newStandardServerTester(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(300)
		w.(http.Flusher).Flush()
		<-reqc
		w.Write(body)
	}, optOnlyServer)
	defer st.Close()

	u, err := url.Parse(st.ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	pr, pw := net.Pipe()
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(st.ts.URL)
	req.SetBodyStream(pr, -1)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	close(reqc)
	got, err := ioutil.ReadAll(rsp.BodyStream())
	if err != nil {
		t.Fatalf("error reading response body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("got response body %q, want %q", string(got), string(body))
	}
	pw.Close()
}

func TestHostClientWriteByteTimeout(t *testing.T) {
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, addr string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				_, c := net.Pipe()
				return newMockNetworkConn(c), nil
			}),
			WriteByteTimeout: 1 * time.Millisecond,
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	err = tr.Do(context.Background(), req, rsp)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Get on unresponsive connection: got %q; want ErrDeadlineExceeded", err)
	}
}

type slowWriteConn struct {
	network.Conn
	hasWriteDeadline bool
}

func (c *slowWriteConn) SetWriteDeadline(t time.Time) error {
	c.hasWriteDeadline = !t.IsZero()
	return nil
}

func (c *slowWriteConn) Write(b []byte) (n int, err error) {
	if c.hasWriteDeadline && len(b) > 1 {
		n, err = c.Conn.Write(b[:1])
		if err != nil {
			return n, err
		}
		return n, fmt.Errorf("slow write: %w", os.ErrDeadlineExceeded)
	}
	return c.Conn.Write(b)
}

func TestHostClientSlowWrites(t *testing.T) {
	st := newHertzServerTester(t,
		func(c context.Context, ctx *app.RequestContext) {},
		optOnlyServer,
	)
	defer st.Close()

	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{
		ClientConfig: &config.ClientConfig{
			TLSConfig: tlsConfigInsecure,
			Dialer: newMockDialerWithCustomFunc(standard.NewDialer(), func(network, addr string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
				conn, err = standard.NewDialer().DialConnection("tcp", addr, time.Second, newClientTLSConfig(tlsConfigInsecure, addr))
				if err != nil {
					return nil, err
				}
				return &slowWriteConn{Conn: &testNetConn{Conn: conn}}, err
			}),
			WriteByteTimeout: 1 * time.Millisecond,
		},
		Addr: u.Host,
	}
	defer tr.CloseIdleConnections()

	const bodySize = 1 << 20

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetBodyStream(io.LimitReader(neverEnding('A'), bodySize), -1)
	req.Header.SetContentTypeBytes([]byte("test/foo"))
	req.SetRequestURI(u.String())
	req.SetMethod(consts.MethodPost)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}
	rsp.CloseBodyStream()
}

func TestHostClientWithTrailerHeader(t *testing.T) {
	wantTrailerHeader := map[string]string{
		"Hertz": "test",
		"foo":   "bar",
	}
	st := newHertzServerTester(t, func(c context.Context, ctx *app.RequestContext) {
		for k, v := range wantTrailerHeader {
			ctx.Response.Header.Trailer().Set(k, v)
		}
	}, optOnlyServer)
	defer st.Close()
	u, err := url.Parse("https://" + st.url)
	if err != nil {
		t.Fatal(err)
	}

	tr := &HostClient{ClientConfig: &config.ClientConfig{TLSConfig: tlsConfigInsecure, Dialer: standard.NewDialer()}, Addr: u.Host, IsTLS: true}
	defer tr.CloseIdleConnections()

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetRequestURI(u.String())
	req.SetMethod(consts.MethodGet)
	err = tr.Do(context.Background(), req, rsp)
	if err != nil {
		t.Fatal(err)
	}

	for k := range wantTrailerHeader {
		actual_value := rsp.Header.Trailer().Get(k)
		if actual_value != "" {
			t.Errorf("Expected empty Header, got: %s", actual_value)
		}
	}

	_ = rsp.Body() // read all body

	for k, v := range wantTrailerHeader {
		actual_value := rsp.Header.Trailer().Get(k)
		if actual_value != v {
			t.Errorf("Expected Header %s: %s, got: %s", k, v, actual_value)
		}
	}

	actual_value := rsp.Header.Get("NoDeclare")
	if actual_value != "" {
		t.Errorf("Expected empty Header, got: %s", actual_value)
	}
}

type mockDialer struct {
	network.Dialer
	customDialerFunc func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error)
}

func newMockDialerWithCustomFunc(dialer network.Dialer, f func(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error)) network.Dialer {
	return &mockDialer{
		Dialer:           dialer,
		customDialerFunc: f,
	}
}

func (m *mockDialer) DialConnection(network, address string, timeout time.Duration, tlsConfig *tls.Config) (conn network.Conn, err error) {
	if m.customDialerFunc != nil {
		return m.customDialerFunc(network, address, timeout, tlsConfig)
	}
	return m.Dialer.DialConnection(network, address, timeout, tlsConfig)
}
