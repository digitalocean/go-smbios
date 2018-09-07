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

package smbios

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

// makeRawSMBIOSData creates a buffer with a valid RawSMBIOSData struct with the
// given version and stream information.
func makeRawSMBIOSData(major, minor, revision byte, stream []byte) []byte {
	buffer := make([]byte, rawSMBIOSDataHeaderSize+len(stream))
	buffer[0] = 0
	buffer[1] = major
	buffer[2] = minor
	buffer[3] = revision
	nativeEndian().PutUint32(buffer[4:8], uint32(len(stream)))
	copy(buffer[8:], stream)
	return buffer
}

func Test_windowsStream(t *testing.T) {
	const major = byte(2)
	const minor = byte(4)
	const revision = byte(1)

	// Note: buffer will be automatically created from the stream if it is not
	// explicitly set to a non-nil value. This prevents having to duplicate the
	// stream data in the struct definitions below for large test cases.
	//
	// Unlike in Test_memoryStream, we're not worrying about the actual decoding
	// of the structures here. All we care about is whether or not windowsStream
	// gives us back the stream data we expect. Whether or not that is valid can
	// be tested separately.
	tests := []struct {
		name   string
		buffer []byte
		stream []byte
		ok     bool
	}{
		{
			name:   "empty buffer",
			buffer: []byte{}, // purposefully not nil
		},
		{
			name:   "short buffer",
			buffer: []byte{0, 1, 2, 3, 4, 5, 6}, // only 7 bytes
		},
		{
			name:   "valid header, empty table",
			stream: nil,
			ok:     true,
		},
		{
			name: "length too large",
			buffer: func() []byte {
				buf := []byte{
					0, 2, 4, 1, // version
					0, 0, 0, 0, // length placeholder
					1, 2, 3, 4, // stream
				}
				nativeEndian().PutUint32(buf[4:8], 5)
				return buf
			}(),
		},
		{
			name: "valid header and stream",
			stream: []byte{
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
			ok: true,
		},
		{
			name: "buffer larger than needed",
			buffer: func() []byte {
				buf := makeRawSMBIOSData(major, minor, revision, []byte{1, 2, 3, 4})
				buf = append(buf, 5, 6, 7, 8)
				return buf
			}(),
			stream: []byte{1, 2, 3, 4},
			ok:     true,
		},
	}

	for _, tt := range tests {
		// Make buffer if not set explicitly
		if tt.buffer == nil {
			tt.buffer = makeRawSMBIOSData(major, minor, revision, tt.stream)
		}

		t.Run(tt.name, func(t *testing.T) {
			rc, ep, err := windowsStream(tt.buffer)

			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatalf("expected an error, but none occurred: %v", err)
			}

			if !tt.ok {
				// Don't bother doing comparison if entry point is invalid
				t.Logf("OK error: %v", err)
				return
			}
			defer rc.Close()

			_, streamSize := ep.Table()
			if streamSize != len(tt.stream) {
				t.Fatalf("bad stream size: got %d, wanted %d", streamSize, len(tt.stream))
			}
			maj, min, rev := ep.Version()
			if maj != int(major) {
				t.Fatalf("bad major version: got %d, wanted %d", maj, major)
			}
			if min != int(minor) {
				t.Fatalf("bad minor version: got %d, wanted %d", min, minor)
			}
			if rev != int(revision) {
				t.Fatalf("bad revision: got %d, wanted %d", rev, revision)
			}

			streamData, err := ioutil.ReadAll(rc)
			if err != nil {
				t.Fatalf("failed to read stream: %v", err)
			}
			if len(streamData) != len(tt.stream) {
				t.Fatalf("bad stream data: got %d bytes, wanted %d", len(streamData), len(tt.stream))
			}
			if bytes.Compare(tt.stream, streamData) != 0 {
				t.Fatalf(
					"stream data different:\nwant: %s\ngot : %s",
					hex.EncodeToString(tt.stream),
					hex.EncodeToString(streamData),
				)
			}
		})
	}
}
