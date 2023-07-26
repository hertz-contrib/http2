/*
 * Copyright 2022 CloudWeGo Authors
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
 */

package config

import (
	"crypto/tls"
	"time"

	"github.com/cloudwego/hertz/pkg/app/client/retry"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/network/netpoll"
	"github.com/cloudwego/hertz/pkg/protocol/client"
	hertz_consts "github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/hertz-contrib/http2/internal/consts"
)

// ClientOption is the only struct that can be used to set HTTP2 ClientConfig.
type ClientOption struct {
	F func(o *ClientConfig)
}

// ClientConfig All configurations related to retry
type ClientConfig struct {
	// MaxHeaderListSize is the http2 SETTINGS_MAX_HEADER_LIST_SIZE to
	// send in the initial settings frame. It is how many bytes
	// of response headers are allowed. Unlike the http2 spec, zero here
	// means to use a default limit (currently 10MB). If you actually
	// want to advertise an unlimited value to the peer, Transport
	// interprets the highest possible value here (0xffffffff or 1<<32-1)
	// to mean no limit.
	MaxHeaderListSize uint32

	// AllowHTTP, if true, permits HTTP/2 requests using the insecure,
	// plain-text "http" scheme. Note that this does not enable h2c support.
	AllowHTTP bool

	// ReadIdleTimeout is the timeout after which a health check using ping
	// frame will be carried out if no frame is received on the connection.
	// Note that a ping response will is considered a received frame, so if
	// there is no other traffic on the connection, the health check will
	// be performed every ReadIdleTimeout interval.
	// If zero, no health check is performed.
	ReadIdleTimeout time.Duration

	// PingTimeout is the timeout after which the connection will be closed
	// if a response to Ping is not received.
	// Defaults to 15s.
	PingTimeout time.Duration

	// WriteByteTimeout is the timeout after which the connection will be
	// closed no data can be written to it. The timeout begins when data is
	// available to write, and is extended whenever any bytes are written.
	WriteByteTimeout time.Duration

	// StrictMaxConcurrentStreams controls whether the server's
	// SETTINGS_MAX_CONCURRENT_STREAMS should be respected
	// globally. If false, new TCP connections are created to the
	// server as needed to keep each under the per-connection
	// SETTINGS_MAX_CONCURRENT_STREAMS limit. If true, the
	// server's SETTINGS_MAX_CONCURRENT_STREAMS is interpreted as
	// a global limit and callers of RoundTrip block when needed,
	// waiting for their turn.
	StrictMaxConcurrentStreams bool

	// Default Dialer is used if not set.
	Dialer network.Dialer

	// Timeout for establishing new connections to hosts.
	//
	// Default DialTimeout is used if not set.
	DialTimeout time.Duration

	// Whether to use TLS (aka SSL or HTTPS) for host connections.
	// Optional TLS config.
	TLSConfig *tls.Config

	// Idle keep-alive connections are closed after this duration.
	//
	// By default idle connections are closed
	// after DefaultMaxIdleConnDuration.
	MaxIdleConnDuration time.Duration

	// All configurations related to retry
	RetryConfig *retry.Config

	// RetryIf controls whether a retry should be attempted after an error.
	//
	// By default will use isIdempotent function
	RetryIf client.RetryIfFunc

	// Connection will close after each request when set this to true.
	DisableKeepAlive bool

	// If true, h2 client won't add default user-agent
	NoDefaultUserAgent bool
}

func (o *ClientConfig) Apply(opts []ClientOption) {
	for _, op := range opts {
		op.F(o)
	}
}

// WithMaxHeaderListSize sets max header list size.
func WithMaxHeaderListSize(maxHeaderListSize uint32) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.MaxHeaderListSize = maxHeaderListSize
	}}
}

// WithReadIdleTimeout is used to set the timeout after which a health check using ping
// frame will be carried out if no frame is received on the connection.
func WithReadIdleTimeout(readIdleTimeout time.Duration) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.ReadIdleTimeout = readIdleTimeout
	}}
}

// WithWriteByteTimeout is used to set the timeout after which the connection will be
// closed no data can be written to it.
func WithWriteByteTimeout(writeByteTimeout time.Duration) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.WriteByteTimeout = writeByteTimeout
	}}
}

// WithStrictMaxConcurrentStreams is used to controls whether the server's
// SETTINGS_MAX_CONCURRENT_STREAMS should be respected globally.
func WithStrictMaxConcurrentStreams(strictMaxConcurrentStreams bool) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.StrictMaxConcurrentStreams = strictMaxConcurrentStreams
	}}
}

// WithPingTimeout is used to set the timeout after which the connection will be closed
// if a response to Ping is not received.
func WithPingTimeout(pt time.Duration) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.PingTimeout = pt
	}}
}

// WithAllowHTTP is used to set whether to allow http.
//
// If enabled, client will use h2c mode.
func WithAllowHTTP(allow bool) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.AllowHTTP = allow
	}}
}

// WithDialer is used to set dialer.
func WithDialer(d network.Dialer) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.Dialer = d
	}}
}

// WithDialTimeout is used to set dial timeout.
func WithDialTimeout(timeout time.Duration) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.DialTimeout = timeout
	}}
}

// WithTLSConfig is used to set tls config.
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.TLSConfig = tlsConfig
	}}
}

// WithNoDefaultUserAgent is used to set NoDefaultUserAgent.
func WithNoDefaultUserAgent(noDefaultUserAgent bool) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.NoDefaultUserAgent = noDefaultUserAgent
	}}
}

// WithMaxIdleConnDuration is used to set max idle connection duration.
func WithMaxIdleConnDuration(d time.Duration) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.MaxIdleConnDuration = d
	}}
}

// WithMaxIdempotentCallAttempts sets maximum number of attempts for idempotent calls.
func WithMaxIdempotentCallAttempts(n int) ClientOption {
	return WithRetryConfig(retry.WithMaxAttemptTimes(uint(n)))
}

// WithRetryConfig sets client retry config
func WithRetryConfig(opts ...retry.Option) ClientOption {
	retryCfg := &retry.Config{
		MaxAttemptTimes: 0,
		Delay:           1 * time.Millisecond,
		MaxDelay:        100 * time.Millisecond,
		MaxJitter:       20 * time.Millisecond,
		DelayPolicy:     retry.CombineDelay(retry.DefaultDelayPolicy),
	}
	retryCfg.Apply(opts)

	return ClientOption{F: func(o *ClientConfig) {
		o.RetryConfig = retryCfg
	}}
}

// WithClientDisableKeepAlive is used to set whether to disable keep alive.
func WithClientDisableKeepAlive(disable bool) ClientOption {
	return ClientOption{F: func(o *ClientConfig) {
		o.DisableKeepAlive = disable
	}}
}

func NewClientConfig(opts ...ClientOption) *ClientConfig {
	cfg := &ClientConfig{
		PingTimeout:         consts.DefaultPingTimeout,
		Dialer:              netpoll.NewDialer(),
		DialTimeout:         time.Second,
		MaxIdleConnDuration: hertz_consts.DefaultMaxIdleConnDuration,
	}
	cfg.Apply(opts)
	return cfg
}
