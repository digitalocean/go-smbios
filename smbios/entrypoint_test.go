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

func TestParseEntryPoint(t *testing.T) {
	tests := []struct {
		name                   string
		b                      []byte
		ep                     smbios.EntryPoint
		major, minor, revision int
		addr, size             int
		ok                     bool
	}{
		{
			name: "short magic",
			b:    []byte{0x00},
		},
		{
			name: "unknown magic",
			b:    []byte{0xff, 0xff, 0xff, 0xff},
		},
		{
			name: "32, short entry point",
			b: []byte{
				'_', 'S', 'M', '_',
			},
		},
		{
			name: "32, bad length",
			b: []byte{
				'_', 'S', 'M', '_',
				0x00,
				0xff, // 255 length
				0x00,
				0x00,
				0x00, 0x00,
				0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
				'_', 'F', 'O', 'O', '_',
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00,
			},
		},
		{
			name: "32, bad intermediate anchor",
			b: []byte{
				'_', 'S', 'M', '_',
				0x00,
				31,
				0x00,
				0x00,
				0x00, 0x00,
				0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
				'_', 'F', 'O', 'O', '_',
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00,
			},
		},
		{
			name: "32, bad checksum",
			b: []byte{
				'_', 'S', 'M', '_',
				0x00, // 0 checksum
				31,
				0x00,
				0x00,
				0x00, 0x00,
				0x00,
				0x00, 0x00, 0x00, 0x00, 0x00,
				'_', 'D', 'M', 'I', '_',
				0x00,
				0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00,
				0x00,
			},
		},
		{
			name: "32, OK",
			b: []byte{
				'_', 'S', 'M', '_',
				0xa4,
				0x1f,
				0x2,
				0x8,
				0xd4,
				0x1, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0,
				'_', 'D', 'M', 'I', '_',
				0x95,
				0x5f, 0xf,
				0x0, 0x90, 0xf0, 0x7a,
				0x43, 0x0,
				0x28,
			},
			ep: &smbios.EntryPoint32Bit{
				Anchor:                "_SM_",
				Checksum:              0xa4,
				Length:                0x1f,
				Major:                 0x02,
				Minor:                 0x08,
				MaxStructureSize:      0x01d4,
				IntermediateAnchor:    "_DMI_",
				IntermediateChecksum:  0x95,
				StructureTableLength:  0x0f5f,
				StructureTableAddress: 0x7af09000,
				NumberStructures:      0x43,
				BCDRevision:           0x28,
			},
			major: 2, minor: 8, revision: 0,
			addr: 0x7af09000, size: 0x0f5f,
			ok: true,
		},
		{
			name: "32, OK, trailing data",
			b: []byte{
				'_', 'S', 'M', '_',
				0xa4,
				0x20,
				0x2,
				0x8,
				0xd4,
				0x1, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0,
				'_', 'D', 'M', 'I', '_',
				0x95,
				0x5f, 0xf,
				0x0, 0x90, 0xf0, 0x7a,
				0x43, 0x0,
				0x28,
				0xff,
			},
			ep: &smbios.EntryPoint32Bit{
				Anchor:                "_SM_",
				Checksum:              0xa4,
				Length:                0x20,
				Major:                 0x02,
				Minor:                 0x08,
				MaxStructureSize:      0x01d4,
				IntermediateAnchor:    "_DMI_",
				IntermediateChecksum:  0x95,
				StructureTableLength:  0x0f5f,
				StructureTableAddress: 0x7af09000,
				NumberStructures:      0x43,
				BCDRevision:           0x28,
			},
			major: 2, minor: 8, revision: 0,
			addr: 0x7af09000, size: 0x0f5f,
			ok: true,
		},
		{
			name: "64, short entry point",
			b: []byte{
				'_', 'S', 'M', '3', '_',
			},
		},
		{
			name: "64, bad length",
			b: []byte{
				'_', 'S', 'M', '3', '_',
				0x00,
				0xff, // 255 length
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "64, bad checksum",
			b: []byte{
				'_', 'S', 'M', '3', '_',
				0x00, // 0 checksum
				0x18,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "64, OK",
			b: []byte{
				'_', 'S', 'M', '3', '_',
				0x86,
				0x18,
				0x3,
				0x0,
				0x0,
				0x1,
				0x0,
				0x53, 0x9, 0x0, 0x0,
				0xb0, 0xb3, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0,
			},
			ep: &smbios.EntryPoint64Bit{
				Anchor:                "_SM3_",
				Checksum:              0x86,
				Length:                0x18,
				Major:                 0x03,
				EntryPointRevision:    0x01,
				StructureTableMaxSize: 0x0953,
				StructureTableAddress: 0x0eb3b0,
			},
			major: 3, minor: 0, revision: 0,
			addr: 0x0eb3b0, size: 0x0953,
			ok: true,
		},
		{
			name: "64, OK, trailing data",
			b: []byte{
				'_', 'S', 'M', '3', '_',
				0x86,
				0x19,
				0x3,
				0x0,
				0x0,
				0x1,
				0x0,
				0x53, 0x9, 0x0, 0x0,
				0xb0, 0xb3, 0xe, 0x0, 0x0, 0x0, 0x0, 0x0,
				0xff,
			},
			ep: &smbios.EntryPoint64Bit{
				Anchor:                "_SM3_",
				Checksum:              0x86,
				Length:                0x19,
				Major:                 0x03,
				EntryPointRevision:    0x01,
				StructureTableMaxSize: 0x0953,
				StructureTableAddress: 0x0eb3b0,
			},
			major: 3, minor: 0, revision: 0,
			addr: 0x0eb3b0, size: 0x0953,
			ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := smbios.ParseEntryPoint(bytes.NewReader(tt.b))

			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected an error, but none occurred: %v", err)
			}

			if !tt.ok {
				// Don't bother doing comparison if entry point is invalid.
				t.Logf("OK error: %v", err)
				return
			}

			if diff := cmp.Diff(tt.ep, ep); diff != "" {
				t.Fatalf("unexpected entry point (-want +got):\n%s", diff)
			}

			major, minor, revision := ep.Version()
			wantVersion := []int{tt.major, tt.minor, tt.revision}
			gotVersion := []int{major, minor, revision}

			if diff := cmp.Diff(wantVersion, gotVersion); diff != "" {
				t.Fatalf("unexpected SMBIOS version (-want +got):\n%s", diff)
			}

			addr, size := ep.Table()
			wantTable := []int{tt.addr, tt.size}
			gotTable := []int{addr, size}

			if diff := cmp.Diff(wantTable, gotTable); diff != "" {
				t.Fatalf("unexpected SMBIOS table info (-want +got):\n%s", diff)
			}
		})
	}
}
