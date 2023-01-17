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
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/common/test/assert"
)

func TestOptions(t *testing.T) {
	options := NewConfig()
	assert.DeepEqual(t, time.Duration(0), options.ReadTimeout)
	assert.DeepEqual(t, false, options.DisableKeepalive)
	assert.DeepEqual(t, uint32(0), options.MaxConcurrentStreams)
	assert.DeepEqual(t, uint32(0), options.MaxReadFrameSize)
	assert.DeepEqual(t, false, options.PermitProhibitedCipherSuites)
	assert.DeepEqual(t, 10*time.Second, options.IdleTimeout) // has default value
	assert.DeepEqual(t, int32(0), options.MaxUploadBufferPerConnection)
	assert.DeepEqual(t, int32(0), options.MaxUploadBufferPerStream)

	options = NewConfig(
		WithReadTimeout(1*time.Second),
		WithDisableKeepAlive(true),
		WithMaxConcurrentStreams(2),
		WithMaxReadFrameSize(3),
		WithPermitProhibitedCipherSuites(true),
		WithIdleTimeout(4*time.Second),
		WithMaxUploadBufferPerConnection(5),
		WithMaxUploadBufferPerStream(6),
	)
	assert.DeepEqual(t, time.Second, options.ReadTimeout)
	assert.DeepEqual(t, true, options.DisableKeepalive)
	assert.DeepEqual(t, uint32(2), options.MaxConcurrentStreams)
	assert.DeepEqual(t, uint32(3), options.MaxReadFrameSize)
	assert.DeepEqual(t, true, options.PermitProhibitedCipherSuites)
	assert.DeepEqual(t, 4*time.Second, options.IdleTimeout) // has default value
	assert.DeepEqual(t, int32(5), options.MaxUploadBufferPerConnection)
	assert.DeepEqual(t, int32(6), options.MaxUploadBufferPerStream)
}
