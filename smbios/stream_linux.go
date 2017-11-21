// Copyright 2017 DigitalOcean.
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

//+build linux

package smbios

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

const (
	// Linux system memory location used to find SMBIOS information.
	devMem = "/dev/mem"

	// sysfs locations for SMBIOS information.
	sysfsDMI        = "/sys/firmware/dmi/tables/DMI"
	sysfsEntryPoint = "/sys/firmware/dmi/tables/smbios_entry_point"
)

// stream opens the SMBIOS entry point and an SMBIOS structure stream.
func stream() (io.ReadCloser, EntryPoint, error) {
	// First, check for the sysfs location present in modern kernels.
	_, err := os.Stat(sysfsEntryPoint)
	switch {
	case err == nil:
		return sysfsStream(sysfsEntryPoint, sysfsDMI)
	case os.IsNotExist(err):
		return devMemStream()
	default:
		return nil, nil, err
	}
}

// sysfsStream reads the SMBIOS entry point and structure stream from
// two files; usually the modern sysfs locations.
func sysfsStream(entryPoint, dmi string) (io.ReadCloser, EntryPoint, error) {
	epf, err := os.Open(entryPoint)
	if err != nil {
		return nil, nil, err
	}
	defer epf.Close()

	ep, err := ParseEntryPoint(epf)
	if err != nil {
		return nil, nil, err
	}

	sf, err := os.Open(dmi)
	if err != nil {
		return nil, nil, err
	}

	return sf, ep, nil
}

// devMemStream reads the SMBIOS entry point and structure stream from
// the older but more common /dev/mem interface.
func devMemStream() (io.ReadCloser, EntryPoint, error) {
	mem, err := os.Open(devMem)
	if err != nil {
		return nil, nil, err
	}
	defer mem.Close()

	// SMBIOS specification indicates that the entry point should exist
	// between these two memory addresses.
	const (
		startAddr = 0x000f0000
		endAddr   = 0x000fffff
	)

	return memoryStream(mem, startAddr, endAddr)
}

// memoryStream reads the SMBIOS entry point and structure stream from
// an io.ReadSeeker (usually system memory).
//
// memoryStream is an entry point for tests.
//
// TODO(mdlayher): determine if memoryStream is cross platform-compatible.
func memoryStream(rs io.ReadSeeker, startAddr, endAddr int) (io.ReadCloser, EntryPoint, error) {
	// Try to find the entry point.
	addr, err := findEntryPoint(rs, startAddr, endAddr)
	if err != nil {
		return nil, nil, err
	}

	// Found it; seek to the location of the entry point.
	if _, err := rs.Seek(int64(addr), io.SeekStart); err != nil {
		return nil, nil, err
	}

	// Read the entry point and determine where the SMBIOS table is.
	ep, err := ParseEntryPoint(rs)
	if err != nil {
		return nil, nil, err
	}

	// Seek to the start of the SMBIOS table.
	tableAddr, tableSize := ep.Table()
	if _, err := rs.Seek(int64(tableAddr), io.SeekStart); err != nil {
		return nil, nil, err
	}

	// Make a copy of the memory so we don't return a handle to system memeory
	// to the caller.
	out := make([]byte, tableSize)
	if _, err := io.ReadFull(rs, out); err != nil {
		return nil, nil, err
	}

	return ioutil.NopCloser(bytes.NewReader(out)), ep, nil
}

// findEntryPoint attempts to locate the entry point structure in the io.ReadSeeker
// using the start and end bound as hints for its location.
func findEntryPoint(rs io.ReadSeeker, start, end int) (int, error) {
	// Begin searching at the start bound.
	if _, err := rs.Seek(int64(start), io.SeekStart); err != nil {
		return 0, err
	}

	// Iterate one "paragraph" of memory at a time until we either find the entry point
	// or reach the end bound.
	const paragraph = 16
	b := make([]byte, paragraph)

	var (
		addr  int
		found bool
	)

	for addr = start; addr < end; addr += paragraph {
		if _, err := io.ReadFull(rs, b); err != nil {
			return 0, err
		}

		// Both the 32-bit and 64-bit entry point have a similar prefix.
		if bytes.HasPrefix(b, magicPrefix) {
			found = true
			break
		}
	}

	if !found {
		return 0, errors.New("no SMBIOS entry point found in memory")
	}

	// Return the exact memory location of the entry point.
	return addr, nil
}
