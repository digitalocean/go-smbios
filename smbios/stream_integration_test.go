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
	"os"
	"runtime"
	"testing"

	"github.com/digitalocean/go-smbios/smbios"
)

func TestStreamIntegration(t *testing.T) {
	if goos := runtime.GOOS; goos != "linux" {
		t.Skipf("skipping on non-Linux platform: %q", goos)
	}

	rc, ep, err := smbios.Stream()
	if err != nil {
		if os.IsPermission(err) {
			t.Skipf("skipping, permission denied while reading SMBIOS stream: %v", err)
		}

		return
	}
	defer rc.Close()

	d := smbios.NewDecoder(rc)
	ss, err := d.Decode()
	if err != nil {
		t.Fatalf("failed to decode structures: %v", err)
	}

	major, minor, rev := ep.Version()
	addr, size := ep.Table()

	// Assume SMBIOS version 2+, assume non-zero table address and size.
	if major < 2 {
		t.Fatalf("unexpected major version: %d", major)
	}
	if addr == 0 {
		t.Fatal("expected non-zero table address")
	}
	if size == 0 {
		t.Fatal("expected non-zero table size")
	}

	// Show some info in the test output.
	t.Logf("SMBIOS %d.%d.%d - table: address: %#x, size: %d\n",
		major, minor, rev, addr, size)

	// Assume we find BIOS and end of table types.
	var foundBIOS, foundEOT bool
	for _, s := range ss {
		switch s.Header.Type {
		case 0:
			foundBIOS = true
			t.Logf("BIOS: %#v", s)
		case 127:
			foundEOT = true
			t.Logf(" EOT: %#v", s)
		}
	}

	if !foundBIOS {
		t.Fatal("did not find BIOS information")
	}
	if !foundEOT {
		t.Fatal("did not find end of table")
	}
}
