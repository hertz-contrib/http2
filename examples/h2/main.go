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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/hertz-contrib/http2/config"
	"github.com/hertz-contrib/http2/factory"
)

func runClient() {
	c, _ := client.NewClient()
	c.SetClientFactory(factory.NewClientFactory(
		config.WithDialer(standard.NewDialer()),
		config.WithTLSConfig(&tls.Config{InsecureSkipVerify: true})))

	v, _ := json.Marshal(map[string]string{
		"hello":    "world",
		"protocol": "h2",
	})

	for {
		time.Sleep(time.Second * 1)
		req, rsp := protocol.AcquireRequest(), protocol.AcquireResponse()
		req.SetMethod("POST")
		req.SetRequestURI("https://127.0.0.1:8888")
		req.SetBody(v)
		err := c.Do(context.Background(), req, rsp)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("client received body: %s\n", string(rsp.Body()))
	}
}

func main() {
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
	cfg.Certificates = append(cfg.Certificates, cert)
	h := server.New(server.WithHostPorts(":8888"), server.WithALPN(true), server.WithTLS(cfg))

	// register http2 server factory
	h.AddProtocol("h2", factory.NewServerFactory(
		config.WithReadTimeout(time.Minute),
		config.WithDisableKeepAlive(false)))
	cfg.NextProtos = append(cfg.NextProtos, "h2")

	h.POST("/", func(c context.Context, ctx *app.RequestContext) {
		var j map[string]string
		_ = json.Unmarshal(ctx.Request.Body(), &j)
		fmt.Printf("server received request: %+v\n", j)

		r := map[string]string{
			"msg": "hello world",
		}
		for k, v := range j {
			r[k] = v
		}
		ctx.JSON(http.StatusOK, r)
	})

	go runClient()

	h.Spin()
}
