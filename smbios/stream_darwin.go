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

//go:build darwin
// +build darwin

// Linux intentionally omitted because it has an alternative method that
// is used before attempting /dev/mem access.  See stream_linux.go.

package smbios

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func run(stdout, stderr io.Writer, cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	c.Stdin = os.Stdin
	c.Stdout = stdout
	c.Stderr = stderr
	return c.Run()
}

func d(s string) string {
	result := strings.TrimSpace(s)
	result = strings.TrimLeft(result, "<")
	result = strings.TrimRight(result, ">")
	return result
}

func extractSMBIOS(lines string) (string, string, error) {
	var smbios, smbiosEPS string
	for _, line := range strings.Split(lines, "\n") {
		if strings.Contains(line, "=") {
			parts := strings.Split(line, `=`)
			if len(parts) == 2 {
				if strings.TrimSpace(parts[0]) == `"SMBIOS-EPS"` {
					smbiosEPS = d(parts[1])
				} else if strings.TrimSpace(parts[0]) == `"SMBIOS"` {
					smbios = d(parts[1])
				}
			}
		}
	}
	if smbios == "" || smbiosEPS == "" {
		return "", "", fmt.Errorf("failed to extract 'SMBIOS' value from `ioreg` output.\n%s", lines)
	}
	return smbiosEPS, smbios, nil

}

// stream opens the SMBIOS entry point and an SMBIOS structure stream.
func stream() (io.ReadCloser, EntryPoint, error) {
	buf := &bytes.Buffer{}
	err := run(buf, os.Stderr, "ioreg", "-rd1", "-c", "AppleSMBIOS")
	if err != nil {
		return nil, nil, err
	}
	smbiosEPS, smbios, err := extractSMBIOS(buf.String())
	if err != nil {
		return nil, nil, err
	}
	eps, err := hex.DecodeString(smbiosEPS)
	if err != nil {
		return nil, nil, err
	}
	data, err := hex.DecodeString(smbios)
	if err != nil {
		return nil, nil, err
	}
	ep, err := ParseEntryPoint(bytes.NewReader(eps))
	if err != nil {
		return nil, nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), ep, nil
}
