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
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"syscall"
	"unsafe"
)

const (
	firmwareTableProviderSigRSMB uint32 = 0x52534d42 // 'RSMB' in ASCII
)

var (
	libKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetSystemFirmwareTable = libKernel32.NewProc("GetSystemFirmwareTable")
)

// WindowsEntryPoint contains SMBIOS Table entry point data returned from
// GetSystemFirmwareTable. As raw access to the underlying memory is not given,
// the full bredth of information is not available.
type WindowsEntryPoint struct {
	Size         uint32
	MajorVersion byte
	MinorVersion byte
	Revision     byte
}

// Table implements EntryPoint. The returned address will always be 0, as it
// is not returned by GetSystemFirmwareTable.
func (e *WindowsEntryPoint) Table() (address, size int) {
	return 0, int(e.Size)
}

// Version implements EntryPoint.
func (e *WindowsEntryPoint) Version() (major, minor, revision int) {
	return int(e.MajorVersion), int(e.MinorVersion), int(e.Revision)
}

func stream() (io.ReadCloser, EntryPoint, error) {
	// Call first with empty buffer to get size
	r1, _, err := procGetSystemFirmwareTable.Call(
		uintptr(firmwareTableProviderSigRSMB),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if r1 == 0 {
		return nil, nil, fmt.Errorf("failed to determine size of buffer needed: %v", err)
	}

	bufferSize := uint32(r1)
	buffer := make([]byte, bufferSize)

	r1, _, err = procGetSystemFirmwareTable.Call(
		uintptr(firmwareTableProviderSigRSMB),
		uintptr(0),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
	)
	if uint32(r1) != bufferSize {
		return nil, nil, fmt.Errorf("failed to read SMBIOS data: expected %d bytes, read %d bytes: %v", bufferSize, r1, err)
	}

	// When calling GetSystemFirmwareTable with FirmwareTableProviderSignature = "RSMB",
	// Windows will write a RawSMBIOSData struct into the output buffer.
	//
	//	From windows.h:
	//
	// 	struct RawSMBIOSData {
	//		BYTE 	Used20CallingMethod;
	//		BYTE	SMBIOSMajorVersion;
	//		BYTE 	SMBIOSMinorVersion;
	//		BYTE 	DMIRevision;
	//		DWORD 	Length;	// uint32
	//		BYTE 	SMBIOSTableData[];
	//	}

	//fmt.Fprintf(os.Stderr, "BUFFER: %s\n", hex.EncodeToString(buffer))

	// There should now be a RawSMBIOSData struct located at the beginning of the
	// buffer.
	entryPoint := &WindowsEntryPoint{
		MajorVersion: buffer[1],
		MinorVersion: buffer[2],
		Revision:     buffer[3],
		Size:         binary.LittleEndian.Uint32(buffer[4:8]),
	}

	tableBuff := buffer[8:]

	return ioutil.NopCloser(bytes.NewReader(tableBuff)), entryPoint, nil
}
