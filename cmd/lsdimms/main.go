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

// Command lsdimms lists memory DIMM information from SMBIOS.
package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/digitalocean/go-smbios/smbios"
)

func main() {
	// Find SMBIOS data in operating system-specific location.
	rc, ep, err := smbios.Stream()
	if err != nil {
		log.Fatalf("failed to open stream: %v", err)
	}
	// Be sure to close the stream!
	defer rc.Close()

	// Decode SMBIOS structures from the stream.
	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		log.Fatalf("failed to decode structures: %v", err)
	}

	major, minor, rev := ep.Version()
	fmt.Printf("SMBIOS %d.%d.%d\n", major, minor, rev)

	for _, s := range ss {
		// Only look at memory devices.
		if s.Header.Type != 17 {
			continue
		}

		// Code based on: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf.

		// TODO: this should go in a new package in go-smbios for parsing specific structures.

		// Only parse the DIMM size.
		dimmSize := int(binary.LittleEndian.Uint16(s.Formatted[8:10]))

		if dimmSize == 0 {
			fmt.Printf("[% 3s] empty\n", s.Strings[0])
			continue
		}

		//If the DIMM size is 32GB or greater, we need to parse the extended field.
		// Spec says 0x7fff in regular size field means we should parse the extended.
		if dimmSize == 0x7fff {
			dimmSize = int(binary.LittleEndian.Uint32(s.Formatted[24:28]))
		}

		// The granularity in which the value is specified
		// depends on the setting of the most-significant bit (bit
		// 15). If the bit is 0, the value is specified in megabyte
		// units; if the bit is 1, the value is specified in kilobyte
		// units.
		//
		// Little endian MSB for uint16 is in second byte.
		unit := "KB"
		if s.Formatted[9]&0x80 == 0 {
			unit = "MB"
		}

		fmt.Printf("[% 3s] DIMM: %d %s\n", s.Strings[0], dimmSize, unit)
	}
}
