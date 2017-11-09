go-smbios [![Build Status](https://travis-ci.org/digitalocean/go-smbios.svg?branch=master)](https://travis-ci.org/digitalocean/go-smbios) [![GoDoc](https://godoc.org/github.com/digitalocean/go-smbios/smbios?status.svg)](https://godoc.org/github.com/digitalocean/go-smbios/smbios) [![Go Report Card](https://goreportcard.com/badge/github.com/digitalocean/go-smbios)](https://goreportcard.com/report/github.com/digitalocean/go-smbios)
=========

Package `smbios` provides detection and access to System Management BIOS (SMBIOS)
and Desktop Management Interface (DMI) data and structures.  Apache 2.0 Licensed.

Example
-------

See `cmd/lssmbios` for a runnable example.  Here's the gist of it:

```go
// Find SMBIOS data in operating system-specific location.
rc, err := smbios.Stream()
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

for _, s := range ss {
	fmt.Println(s)
}
```