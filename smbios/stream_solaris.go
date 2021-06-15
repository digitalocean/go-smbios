// +build solaris

package smbios

import (
	"io"
	"os"
)

const devSMBIOS = "/dev/smbios"

func stream() (io.ReadCloser, EntryPoint, error) {
	epf, err := os.Open(devSMBIOS)
	if err != nil {
		return nil, nil, err
	}

	ep, err := ParseEntryPoint(epf)
	if err != nil {
		return nil, nil, err
	}

	return epf, ep, nil
}
