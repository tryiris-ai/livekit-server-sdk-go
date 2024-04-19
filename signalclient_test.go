// Copyright 2023 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lksdk

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalClient_Join(t *testing.T) {
	t.Run("rejects empty URLs", func(t *testing.T) {
		c := NewSignalClient()
		_, err := c.Join("", "", connectParams{})
		require.Equal(t, ErrURLNotProvided, err)
	})

	t.Run("errors on invalid URLs", func(t *testing.T) {
		c := NewSignalClient()
		_, err := c.Join("https://invalid-livekit-url", "", connectParams{})
		require.Error(t, err)
		require.NotEqual(t, ErrURLNotProvided, err)
	})
}
