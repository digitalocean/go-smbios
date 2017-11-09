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
	"errors"
	"io"
	"os"
)

// sysfs locations for SMBIOS information.
const (
	sysfsDMI        = "/sys/firmware/dmi/tables/DMI"
	sysfsEntryPoint = "/sys/firmware/dmi/tables/smbios_entry_point"
)

// stream opens the SMBIOS entry point and an SMBIOS structure stream.
func stream() (io.ReadCloser, EntryPoint, error) {
	// First, check for the sysfs location present in modern kernels.
	_, err := os.Stat(sysfsEntryPoint)
	switch {
	case err == nil:
		return sysfsStream()
	case os.IsNotExist(err):
		// TODO(mdlayher): try reading /dev/mem and fail if no data present.
		return nil, nil, errors.New("reading from /dev/mem not yet supported on Linux")
	default:
		return nil, nil, err
	}
}

// sysfsStream reads the SMBIOS entry point and structure stream from
// the modern sysfs locations.
func sysfsStream() (io.ReadCloser, EntryPoint, error) {
	epf, err := os.Open(sysfsEntryPoint)
	if err != nil {
		return nil, nil, err
	}
	defer epf.Close()

	ep, err := ParseEntryPoint(epf)
	if err != nil {
		return nil, nil, err
	}

	sf, err := os.Open(sysfsDMI)
	if err != nil {
		return nil, nil, err
	}

	return sf, ep, nil
}
