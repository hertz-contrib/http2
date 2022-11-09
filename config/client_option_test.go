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
	"github.com/hertz-contrib/http2/internal/consts"
)

func TestClientOptions(t *testing.T) {
	options := NewClientConfig()
	assert.DeepEqual(t, false, options.StrictMaxConcurrentStreams)
	assert.DeepEqual(t, time.Duration(0), options.ReadIdleTimeout)
	assert.DeepEqual(t, consts.DefaultPingTimeout, options.PingTimeout)
	assert.DeepEqual(t, time.Duration(0), options.WriteByteTimeout)
	assert.DeepEqual(t, false, options.AllowHTTP)
	assert.DeepEqual(t, uint32(0), options.MaxHeaderListSize)
	assert.DeepEqual(t, false, options.DisableKeepAlive)
	assert.DeepEqual(t, time.Second, options.DialTimeout)
	assert.DeepEqual(t, time.Duration(0), options.MaxIdleConnDuration)

	options = NewClientConfig(
		WithStrictMaxConcurrentStreams(true),
		WithReadIdleTimeout(1*time.Second),
		WithPingTimeout(2*time.Second),
		WithWriteByteTimeout(3*time.Second),
		WithAllowHTTP(true),
		WithMaxHeaderListSize(4),
		WithDialTimeout(time.Second*2),
		WithMaxIdempotentCallAttempts(5),
		WithMaxIdleConnDuration(time.Second*3),
		WithClientDisableKeepAlive(true),
		WithRetryConfig(),
	)
	assert.DeepEqual(t, true, options.StrictMaxConcurrentStreams)
	assert.DeepEqual(t, time.Second, options.ReadIdleTimeout)
	assert.DeepEqual(t, 2*time.Second, options.PingTimeout)
	assert.DeepEqual(t, 3*time.Second, options.WriteByteTimeout)
	assert.DeepEqual(t, true, options.AllowHTTP)
	assert.DeepEqual(t, uint32(4), options.MaxHeaderListSize)
	assert.DeepEqual(t, true, options.DisableKeepAlive)
	assert.DeepEqual(t, time.Second*2, options.DialTimeout)
	assert.DeepEqual(t, time.Second*3, options.MaxIdleConnDuration)
	assert.DeepEqual(t, uint(0), options.RetryConfig.MaxAttemptTimes)
	assert.DeepEqual(t, 1*time.Millisecond, options.RetryConfig.Delay)
	assert.DeepEqual(t, 100*time.Millisecond, options.RetryConfig.MaxDelay)
	assert.DeepEqual(t, 20*time.Millisecond, options.RetryConfig.MaxJitter)
}
