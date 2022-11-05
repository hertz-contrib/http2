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
)

type Config struct {
	DisableKeepalive bool
	ReadTimeout      time.Duration
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

func NewConfig(opts ...Option) *Config {
	c := &Config{}
	c.Apply(opts)
	return c
}
