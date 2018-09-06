go-smbios [![Build Status](https://travis-ci.org/digitalocean/go-smbios.svg?branch=master)](https://travis-ci.org/digitalocean/go-smbios) [![GoDoc](https://godoc.org/github.com/digitalocean/go-smbios/smbios?status.svg)](https://godoc.org/github.com/digitalocean/go-smbios/smbios) [![Go Report Card](https://goreportcard.com/badge/github.com/digitalocean/go-smbios)](https://goreportcard.com/report/github.com/digitalocean/go-smbios)
=========

Package `smbios` provides detection and access to System Management BIOS (SMBIOS)
and Desktop Management Interface (DMI) data and structures.  Apache 2.0 Licensed.

Introduction
------------

[SMBIOS](https://en.wikipedia.org/wiki/System_Management_BIOS) is a standard
mechanism for fetching BIOS and hardware information from within an operating
system.  It shares some similarities with the older DMI standard, and the two are
often confused.

To install this package, run:

```
$ go get github.com/digitalocean/go-smbios/smbios
```

This package is based on the [SMBIOS 3.1.1 specification](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.1.1.pdf),
but should work with SMBIOS 2.0 and above.

In general, it's up to hardware manufacturers to properly populate SMBIOS data,
and many structures may not be populated correctly or at all; especially on
consumer hardware.

The `smbios.Structure` types created by this package can be decoded using the
structure information in the SMBIOS specification.  In the future, some common
structures may be parsed and readily available by using this package.

Supported operating systems and their SMBIOS retrieval mechanisms include:

- DragonFlyBSD (/dev/mem)
- FreeBSD (/dev/mem)
- Linux (sysfs and /dev/mem)
- NetBSD (/dev/mem)
- OpenBSD (/dev/mem)
- Solaris (/dev/mem)
- Windows (GetSystemFirmwareTable)

At this time, macOS is not supported, as it does not expose
SMBIOS information in the same way as the supported operating systems. Pull
requests are welcome to add support for additional operating systems.

Example
-------

See `cmd/lssmbios` for a runnable example.  Note that retrieving SMBIOS
information is a privileged operation.  On Linux, you may invoke the binary
as root directly, or apply the `CAP_DAC_OVERRIDE` capability to enable reading
the information without superuser access.

Here's the gist of it:

```go
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

// Determine SMBIOS version and table location from entry point.
major, minor, rev := ep.Version()
addr, size := ep.Table()

fmt.Printf("SMBIOS %d.%d.%d - table: address: %#x, size: %d\n",
	major, minor, rev, addr, size)

for _, s := range ss {
	fmt.Println(s)
}
```
