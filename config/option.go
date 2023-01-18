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

package config

import (
	"time"

	"github.com/cloudwego/hertz/pkg/protocol/consts"
)

type Config struct {
	DisableKeepalive bool
	ReadTimeout      time.Duration

	// MaxHandlers limits the number of http.Handler ServeHTTP goroutines
	// which may run at a time over all connections.
	// Negative or zero no limit.
	// TODO: implement
	MaxHandlers int

	// MaxConcurrentStreams optionally specifies the number of
	// concurrent streams that each client may have open at a
	// time. This is unrelated to the number of http.Handler goroutines
	// which may be active globally, which is MaxHandlers.
	// If zero, MaxConcurrentStreams defaults to at least 100, per
	// the HTTP/2 spec's recommendations.
	MaxConcurrentStreams uint32

	// MaxReadFrameSize optionally specifies the largest frame
	// this server is willing to read. A valid value is between
	// 16k and 16M, inclusive. If zero or otherwise invalid, a
	// default value is used.
	MaxReadFrameSize uint32

	// PermitProhibitedCipherSuites, if true, permits the use of
	// cipher suites prohibited by the HTTP/2 spec.
	PermitProhibitedCipherSuites bool

	// IdleTimeout specifies how long until idle clients should be
	// closed with a GOAWAY frame. PING frames are not considered
	// activity for the purposes of IdleTimeout.
	IdleTimeout time.Duration

	// MaxUploadBufferPerConnection is the size of the initial flow
	// control window for each connections. The HTTP/2 spec does not
	// allow this to be smaller than 65535 or larger than 2^32-1.
	// If the value is outside this range, a default value will be
	// used instead.
	MaxUploadBufferPerConnection int32

	// MaxUploadBufferPerStream is the size of the initial flow control
	// window for each stream. The HTTP/2 spec does not allow this to
	// be larger than 2^32-1. If the value is zero or larger than the
	// maximum, a default value will be used instead.
	MaxUploadBufferPerStream int32
}

// Option is the only struct that can be used to set HTTP2 Config.
type Option struct {
	F func(o *Config)
}

func (o *Config) Apply(opts []Option) {
	for _, op := range opts {
		op.F(o)
	}
}

// WithReadTimeout is used to set the read timeout.
func WithReadTimeout(t time.Duration) Option {
	return Option{F: func(o *Config) {
		o.ReadTimeout = t
	}}
}

// WithDisableKeepAlive is used to set whether disableKeepAlive.
func WithDisableKeepAlive(disableKeepAlive bool) Option {
	return Option{F: func(o *Config) {
		o.DisableKeepalive = disableKeepAlive
	}}
}

// WithMaxConcurrentStreams is used to set the max concurrent streams.
func WithMaxConcurrentStreams(n uint32) Option {
	return Option{F: func(o *Config) {
		o.MaxConcurrentStreams = n
	}}
}

// WithMaxReadFrameSize is used to set the max read frame size.
func WithMaxReadFrameSize(n uint32) Option {
	return Option{F: func(o *Config) {
		o.MaxReadFrameSize = n
	}}
}

// WithPermitProhibitedCipherSuites is used to set whether permit prohibited chipher suites.
func WithPermitProhibitedCipherSuites(permitProhibitedChipherSuites bool) Option {
	return Option{F: func(o *Config) {
		o.PermitProhibitedCipherSuites = permitProhibitedChipherSuites
	}}
}

// WithIdleTimeout is used to set idle timeout.
func WithIdleTimeout(t time.Duration) Option {
	return Option{F: func(o *Config) {
		o.IdleTimeout = t
	}}
}

// WithMaxUploadBufferPerConnection is used to set max upload buffer per connection.
func WithMaxUploadBufferPerConnection(n int32) Option {
	return Option{F: func(o *Config) {
		o.MaxUploadBufferPerConnection = n
	}}
}

// WithMaxUploadBufferPerStream is used to set max upload buffer per stream.
func WithMaxUploadBufferPerStream(n int32) Option {
	return Option{F: func(o *Config) {
		o.MaxUploadBufferPerStream = n
	}}
}

func NewConfig(opts ...Option) *Config {
	c := &Config{
		IdleTimeout: consts.DefaultMaxIdleConnDuration,
	}
	c.Apply(opts)
	return c
}
