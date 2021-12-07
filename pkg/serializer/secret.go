/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package serializer

import (
	"encoding/json"
	"errors"
	"fmt"
)

type SecretFormat = int

const (
	JsonBytesSecretFormat SecretFormat = iota
	BytesSecretFormat
)

const (
	errUnknownSerializationFormat = "unknown serialization format"
	errSecretFormat               = "secret data not in expected format"
	errJSONSecretUnmarshal        = "unable to unmarshal secret using json: %w"
)

func UnmarshalJson(in []byte) (map[string]interface{}, error) {
	dst := make(map[string]interface{})
	err := json.Unmarshal(in, &dst)
	if err != nil {
		return nil, fmt.Errorf(errJSONSecretUnmarshal, err)
	}
	return BackwardCompatabilityFix(dst), nil
}

// BackwardCompatabilityFix maps {"a": string("b")} -> {"a": []byte("b")} only first level values.
func BackwardCompatabilityFix(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		switch v.(type) {
		case string:
			out[k] = []byte(v.(string))
		default:
			out[k] = v
		}
	}
	return out
}

// SerialiseSecret marshal map of interfaces to secret data
func SerialiseSecret(src map[string]interface{}, format SecretFormat) (dst map[string][]byte, err error) {
	dst = make(map[string][]byte)

	switch format {
	case JsonBytesSecretFormat:
		for k, v := range src {
			newVal, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("serialise error: %w", err)
			}
			dst[k] = newVal
		}
	case BytesSecretFormat:
		for k, v := range src {
			switch t := v.(type) {
			case string:
				dst[k] = []byte(t)
			case []byte:
				dst[k] = t
			case nil:
				dst[k] = []byte(nil)
			default:
				return nil, errors.New(errSecretFormat)
			}
		}
	}

	return nil, errors.New(errUnknownSerializationFormat)
}
