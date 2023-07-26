/*
 * Copyright 2022 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package factory

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/test/mock"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/hertz-contrib/http2"
	"github.com/hertz-contrib/http2/config"
)

func TestClientIP(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	cert, err := tls.LoadX509KeyPair("../testdata/certificate/server.crt", "../testdata/certificate/server.key")
	assert.Nil(t, err)
	cfg.Certificates = append(cfg.Certificates, cert)
	h := server.New(server.WithHostPorts(":8888"), server.WithALPN(true), server.WithTLS(cfg))

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory(
		config.WithReadTimeout(time.Minute),
		config.WithDisableKeepAlive(false)))
	cfg.NextProtos = append(cfg.NextProtos, "h2")

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		assert.DeepEqual(t, "127.0.0.1", ctx.ClientIP())
		ctx.JSON(http.StatusOK, map[string]interface{}{"ping": "pong"})
	})

	go h.Spin()

	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(
		config.WithDialer(standard.NewDialer()),
		config.WithTLSConfig(&tls.Config{InsecureSkipVerify: true})))

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("https://127.0.0.1:8888")
	c.Do(context.Background(), req, rsp)
}

func TestContentEncoding(t *testing.T) {
	h := server.New(server.WithHostPorts(":8889"), server.WithH2C(true))

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		ctx.Response.Header.SetContentEncoding("gzip")
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8889")
	c.Do(context.Background(), req, rsp)
	assert.DeepEqual(t, "gzip", string(rsp.Header.ContentEncoding()))
	assert.DeepEqual(t, "", string(rsp.Header.Server()))
}

func TestServerIdleTimeout(t *testing.T) {
	var acceptCount int32 = 0
	h := server.New(
		server.WithHostPorts(":8890"),
		server.WithH2C(true),
		server.WithOnAccept(func(conn net.Conn) context.Context {
			atomic.AddInt32(&acceptCount, 1)
			return context.Background()
		}))

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		ctx.SetBodyString("pong")
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8890")

	// first request, acceptCount + 1
	c.Do(context.Background(), req, rsp)
	assert.DeepEqual(t, int32(1), atomic.LoadInt32(&acceptCount))

	time.Sleep(time.Second)

	// second request, the connection is alive
	rsp.Reset()
	c.Do(context.Background(), req, rsp)
	assert.DeepEqual(t, int32(1), atomic.LoadInt32(&acceptCount))

	time.Sleep(time.Second * 10)

	// third request, the connection is released, acceptCount + 1
	rsp.Reset()
	c.Do(context.Background(), req, rsp)
	assert.DeepEqual(t, int32(2), atomic.LoadInt32(&acceptCount))
}

func getStream(data []byte) io.Reader {
	reader, writer := io.Pipe()

	go func() {
		time.Sleep(100 * time.Millisecond)
		if len(data) != 0 {
			writer.Write(data)
		}
		writer.Close()
	}()

	return reader
}

func getBadStream(data []byte) io.Reader {
	reader, writer := io.Pipe()

	go func() {
		time.Sleep(100 * time.Millisecond)
		if len(data) != 0 {
			writer.Write(data)
		}
		writer.CloseWithError(errors.New("test error"))
	}()

	return reader
}

func testSendStreamBody(t *testing.T, bodySize int) {
	h := server.New(server.WithHostPorts(":8891"), server.WithH2C(true))

	data := mock.CreateFixedBody(bodySize)
	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		ctx.SetBodyStream(getStream(data), -1)
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8891")
	c.Do(context.Background(), req, rsp)
	assert.DeepEqual(t, string(data), string(rsp.Body()))

	h.Close()
}

func TestSendStreamBody(t *testing.T) {
	// zero-size body
	testSendStreamBody(t, 0)

	// small-size body
	testSendStreamBody(t, 5)

	// medium-size body
	testSendStreamBody(t, 43488)

	// big body
	testSendStreamBody(t, 3*1024*1024)

	// smaller body after big one
	testSendStreamBody(t, 12343)
}

func testSendBadStreamBody(t *testing.T, bodySize int) {
	h := server.New(server.WithHostPorts(":8892"), server.WithH2C(true))

	data := mock.CreateFixedBody(bodySize)
	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		ctx.SetBodyStream(getBadStream(data), -1)
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8892")
	err := c.Do(context.Background(), req, rsp)
	if err == nil {
		_, err = rsp.BodyE()
	}

	streamErr, ok := err.(http2.StreamError)
	if !ok {
		t.Error("the error should be http2.StreamError")
	}
	assert.DeepEqual(t, http2.ErrCodeInternal, streamErr.Code)

	h.Close()
}

func TestSendBadStreamBody(t *testing.T) {
	// zero-size body
	testSendBadStreamBody(t, 0)

	// small-size body
	testSendBadStreamBody(t, 5)

	// medium-size body
	testSendBadStreamBody(t, 43488)

	// big body
	testSendBadStreamBody(t, 3*1024*1024)

	// smaller body after big one
	testSendBadStreamBody(t, 12343)
}

func TestTrailer(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	cert, err := tls.LoadX509KeyPair("../testdata/certificate/server.crt", "../testdata/certificate/server.key")
	assert.Nil(t, err)
	cfg.Certificates = append(cfg.Certificates, cert)
	h := server.New(server.WithHostPorts(":8893"), server.WithALPN(true), server.WithTLS(cfg))

	wantTrailerHeader := map[string]string{
		"Hertz": "test",
		"foo":   "bar",
	}

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory(
		config.WithReadTimeout(time.Minute),
		config.WithDisableKeepAlive(false)))
	cfg.NextProtos = append(cfg.NextProtos, "h2")

	h.GET("/", func(c context.Context, ctx *app.RequestContext) {
		for k := range wantTrailerHeader {
			actual_value := ctx.Request.Header.Trailer().Get(k)
			if actual_value != "" {
				t.Errorf("Expected empty Header, got: %s", actual_value)
			}
		}

		_ = ctx.Request.Body()

		for k, v := range wantTrailerHeader {
			actual_value := ctx.Request.Header.Trailer().Get(k)
			if actual_value != v {
				t.Errorf("Expected Header %s: %s, got: %s", k, v, actual_value)
			}
		}

		ctx.String(http.StatusOK, "pong")

		for k, v := range wantTrailerHeader {
			ctx.Response.Header.Trailer().Set(k, v)
		}
	})

	go h.Spin()

	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(
		config.WithDialer(standard.NewDialer()),
		config.WithTLSConfig(&tls.Config{InsecureSkipVerify: true})))

	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("GET")
	req.SetRequestURI("https://127.0.0.1:8893")
	req.AppendBodyString("ping")

	for k, v := range wantTrailerHeader {
		req.Header.Trailer().Set(k, v)
	}

	c.Do(context.Background(), req, rsp)

	for k := range wantTrailerHeader {
		actual_value := rsp.Header.Trailer().Get(k)
		if actual_value != "" {
			t.Errorf("Expected empty Header, got: %s", actual_value)
		}
	}

	_ = rsp.Body()

	for k, v := range wantTrailerHeader {
		actual_value := rsp.Header.Trailer().Get(k)
		if actual_value != v {
			t.Errorf("Expected Header %s: %s, got: %s", k, v, actual_value)
		}
	}
}

func TestBodyNotAllowedStatus(t *testing.T) {
	var acceptCount int32 = 0
	h := server.New(
		server.WithHostPorts(":8894"),
		server.WithH2C(true),
		server.WithOnAccept(func(conn net.Conn) context.Context {
			atomic.AddInt32(&acceptCount, 1)
			return context.Background()
		}))

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		ctx.Data(304, "application/json", []byte("test data"))
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8894")

	err := c.Do(context.Background(), req, rsp)
	assert.Nil(t, err)
	assert.DeepEqual(t, rsp.StatusCode(), 304)
	assert.DeepEqual(t, len(rsp.Body()), 0)
}

func TestNoDefaultUserAgent(t *testing.T) {
	var acceptCount int32 = 0
	h := server.New(
		server.WithHostPorts(":8895"),
		server.WithH2C(true),
		server.WithOnAccept(func(conn net.Conn) context.Context {
			atomic.AddInt32(&acceptCount, 1)
			return context.Background()
		}))

	// register http2 server factory
	h.AddProtocol("h2", NewServerFactory())

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		assert.DeepEqual(t, "", string(ctx.UserAgent()))
		ctx.Data(304, "application/json", []byte("test data"))
	})
	go h.Spin()
	time.Sleep(time.Second)

	c, _ := client.NewClient()
	c.SetClientFactory(NewClientFactory(config.WithAllowHTTP(true), config.WithNoDefaultUserAgent(true)))
	req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
	req.SetMethod("POST")
	req.SetRequestURI("http://127.0.0.1:8895")

	err := c.Do(context.Background(), req, rsp)
	assert.Nil(t, err)
	assert.DeepEqual(t, rsp.StatusCode(), 304)
	assert.DeepEqual(t, len(rsp.Body()), 0)
}
