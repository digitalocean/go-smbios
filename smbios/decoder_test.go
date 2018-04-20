// Copyright 2017-2018 DigitalOcean.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smbios_test

import (
	"bytes"
	"testing"

	"github.com/digitalocean/go-smbios/smbios"
	"github.com/google/go-cmp/cmp"
)

func TestDecoder(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		ss   []*smbios.Structure
		ok   bool
	}{
		{
			name: "short header",
			b:    []byte{0x00},
		},
		{
			name: "length too short",
			b:    []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "length too long",
			b:    []byte{0x00, 0xff, 0x00, 0x00},
		},
		{
			name: "string not terminated",
			b: []byte{
				0x01, 0x04, 0x01, 0x00,
				'a', 'b', 'c', 'd',
			},
		},
		{
			name: "no end of table",
			b: []byte{
				0x01, 0x04, 0x01, 0x00,
				0x00,
				0x00,
			},
		},
		{
			name: "bad second message",
			b: []byte{
				0x01, 0x0c, 0x02, 0x00,
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f', 0x00,
				0x00,

				0xff,
			},
		},
		{
			name: "OK, one, no format, no strings",
			b: []byte{
				127, 0x04, 0x01, 0x00,
				0x00,
				0x00,
			},
			ss: []*smbios.Structure{{
				Header: smbios.Header{
					Type:   127,
					Length: 4,
					Handle: 1,
				},
			}},
			ok: true,
		},
		{
			name: "OK, one, format, no strings",
			b: []byte{
				127, 0x06, 0x01, 0x00,
				0x01, 0x02,
				0x00,
				0x00,
			},
			ss: []*smbios.Structure{{
				Header: smbios.Header{
					Type:   127,
					Length: 6,
					Handle: 1,
				},
				Formatted: []byte{0x01, 0x02},
			}},
			ok: true,
		},
		{
			name: "OK, one, format, strings",
			b: []byte{
				127, 0x06, 0x01, 0x00,
				0x01, 0x02,
				'a', 'b', 'c', 'd', 0x00,
				'1', '2', '3', '4', 0x00,
				0x00,
			},
			ss: []*smbios.Structure{{
				Header: smbios.Header{
					Type:   127,
					Length: 6,
					Handle: 1,
				},
				Formatted: []byte{0x01, 0x02},
				Strings:   []string{"abcd", "1234"},
			}},
			ok: true,
		},
		{
			name: "OK, multiple",
			b: []byte{
				0x00, 0x05, 0x01, 0x00,
				0xff,
				0x00,
				0x00,

				0x01, 0x0c, 0x02, 0x00,
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
				'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f', 0x00,
				0x00,

				127, 0x06, 0x03, 0x00,
				0x01, 0x02,
				'a', 'b', 'c', 'd', 0x00,
				'1', '2', '3', '4', 0x00,
				0x00,
			},
			ss: []*smbios.Structure{
				{
					Header: smbios.Header{
						Type:   0,
						Length: 5,
						Handle: 1,
					},
					Formatted: []byte{0xff},
				},
				{
					Header: smbios.Header{
						Type:   1,
						Length: 12,
						Handle: 2,
					},
					Formatted: []byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef},
					Strings:   []string{"deadbeef"},
				},
				{
					Header: smbios.Header{
						Type:   127,
						Length: 6,
						Handle: 3,
					},
					Formatted: []byte{0x01, 0x02},
					Strings:   []string{"abcd", "1234"},
				},
			},
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := smbios.NewDecoder(bytes.NewReader(tt.b))
			ss, err := d.Decode()

			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected an error, but none occurred: %v", err)
			}

			if diff := cmp.Diff(tt.ss, ss); diff != "" {
				t.Fatalf("unexpected structures (-want +got):\n%s", diff)
			}
		})
	}
}
