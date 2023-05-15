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

package factory

import (
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/suite"
	"github.com/hertz-contrib/http2"
	"github.com/hertz-contrib/http2/config"
)

var _ suite.ServerFactory = &serverFactory{}

type serverFactory struct {
	option *config.Config
}

type tracer interface {
	IsTraceEnable() bool
}

// New is called by Hertz during engine.Run()
func (s *serverFactory) New(core suite.Core) (server protocol.Server, err error) {
	if cc, ok := core.(tracer); ok {
		s.option.EnableTrace = cc.IsTraceEnable()
	}
	return &http2.Server{
		BaseEngine: http2.BaseEngine{
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
