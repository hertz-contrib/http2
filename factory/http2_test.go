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
	"net/http"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
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
