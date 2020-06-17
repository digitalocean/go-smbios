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
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unsafe"
)

const (
	// headerLen is the length of the Header structure.
	headerLen = 4

	// typeEndOfTable indicates the end of a stream of Structures.
	typeEndOfTable = 127

	extendedSizeThreyshold = 32767

	mbToByteConvRatio = 1048576
	kbToByteConvRatio = 1024
	sizeAsPer2_1      = 17
	sizeAsPer2_3      = 23
	sizeAsPer2_6      = 24
	sizeAsPer2_7      = 30
	sizeAsPer2_8      = 36
)

var (
	// Byte slices used to help parsing string-sets.
	null         = []byte{0x00}
	endStringSet = []byte{0x00, 0x00}
)

// A Decoder decodes Structures from a stream.
type Decoder struct {
	br      *bufio.Reader
	b       []byte
	Version SMBIOSVersion
}

// Stream locates and opens a stream of SMBIOS data and the SMBIOS entry
// point from an operating system-specific location.  The stream must be
// closed after decoding to free its resources.
//
// If no suitable location is found, an error is returned.
func Stream() (io.ReadCloser, EntryPoint, error) {
	rc, ep, err := stream()
	if err != nil {
		return nil, nil, err
	}

	// The io.ReadCloser from stream could be any one of a number of types
	// depending on the source of the SMBIOS stream information.
	//
	// To prevent the caller from potentially tampering with something dangerous
	// like mmap'd memory by using a type assertion, we make the io.ReadCloser
	// into an opaque and unexported type to prevent type assertion.
	return &opaqueReadCloser{rc: rc}, ep, nil
}

// NewDecoder creates a Decoder which decodes Structures from the input stream.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		br: bufio.NewReader(r),
		b:  make([]byte, 1024),
	}
}

type Extract func([]string) error

// Decode decodes Structures from the Decoder's stream until an End-of-table
// structure is found.
func (d *Decoder) Decode() ([]*Structure, error) {
	var ss []*Structure

	for {
		s, err := d.next()
		if err != nil {
			return nil, err
		}

		// End-of-table structure indicates end of stream.
		ss = append(ss, s)
		if s.Header.Type == typeEndOfTable {
			break
		}
	}

	return ss, nil
}

// next decodes the next Structure from the stream.
func (d *Decoder) next() (*Structure, error) {
	h, err := d.parseHeader()
	if err != nil {
		return nil, err
	}

	// Length of formatted section is length specified by header, minus
	// the length of the header itself.
	l := int(h.Length) - headerLen
	fb, err := d.parseFormatted(l)
	if err != nil {
		return nil, err
	}

	ss, err := d.parseStrings()
	if err != nil {
		return nil, err
	}

	systemInfo := SystemInfo{}

	if h.Type == 1 {
		sysInfo := (*SMBIOSSystemInfo)(unsafe.Pointer(&fb[0]))
		if h.Length > 8 {
			only0xFF := 1
			only0x00 := 1
			for i := 0; (i < 16) && ((1 == only0x00) || (1 == only0xFF)); i++ {
				if sysInfo.UUID[i] != 0x00 {
					only0x00 = 0
				}
				if sysInfo.UUID[i] != 0xFF {
					only0xFF = 0
				}
			}

			if 0 == only0xFF && 0 == only0x00 {

				strUUID := fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
					sysInfo.UUID[3], sysInfo.UUID[2], sysInfo.UUID[1], sysInfo.UUID[0], sysInfo.UUID[5], sysInfo.UUID[4], sysInfo.UUID[7], sysInfo.UUID[6],
					sysInfo.UUID[8], sysInfo.UUID[9], sysInfo.UUID[10], sysInfo.UUID[11], sysInfo.UUID[12], sysInfo.UUID[13], sysInfo.UUID[14], sysInfo.UUID[15])

				systemInfo.VirtualMachineUUID = strUUID
				ss = append(ss, strUUID)
			}
		}

		if sysInfo.ProductName > 0 {
			systemInfo.SystemManufacturerRef = ss[sysInfo.ProductName-1]
		}

		if sysInfo.Manufacturer > 0 {
			systemInfo.SystemProductName = ss[sysInfo.Manufacturer-1]
		}

		if sysInfo.SN > 0 {
			systemInfo.BiosSerial = ss[sysInfo.SN-1]
		}
	}

	if h.Type == 2 {
		mbInfo := (*SMBIOSBaseboardInfo)(unsafe.Pointer(&fb[0]))
		bbInfo := &BaseboardInfo{}
		valArrSize := byte(len(ss))
		if mbInfo.Manufacturer > 0 && mbInfo.Manufacturer <= valArrSize {
			bbInfo.Manufacturer = ss[mbInfo.Manufacturer-1]
		}
		if mbInfo.Product > 0 && mbInfo.Product <= valArrSize {
			bbInfo.Product = ss[mbInfo.Product-1]
		}
		if mbInfo.Version > 0 && mbInfo.Version <= valArrSize {
			bbInfo.Version = ss[mbInfo.Version-1]
		}

		if mbInfo.SerialNumber > 0 && mbInfo.SerialNumber <= valArrSize {
			val := ss[mbInfo.SerialNumber-1]
			systemInfo.MotherboardAdapter = val
			bbInfo.SerialNumber = val
		}

		systemInfo.BaseboardInfo = bbInfo
	}
	if h.Type == 3 {

		sysEnclosure := (*SystemEnclosure)(unsafe.Pointer(&fb[0]))

		systemInfo.SystemEnclosure = &SystemEnclosure{}

		systemInfo.SystemEnclosure.Type = sysEnclosure.Type & 0x7F

	}

	if h.Type == 4 {
		procInfo := (*SMBIOSProcessorType)(unsafe.Pointer(&fb[0]))
		isValidProcessorID := false
		processor := &Processor{}
		for i := 0; i < len(procInfo.ProcessorID); i++ {
			if procInfo.ProcessorID[i] > 0 {
				isValidProcessorID = true
				break
			}
		}
		if isValidProcessorID {
			cpuID := fmt.Sprintf("%04X%04X%04X%04X", procInfo.ProcessorID[3], procInfo.ProcessorID[2], procInfo.ProcessorID[1], procInfo.ProcessorID[0])
			systemInfo.ProcessorID = cpuID
			processor.ID = cpuID
		}
		if procInfo.ProcessorType > 0 {
			pType := fmt.Sprintf("%01X", procInfo.ProcessorType)
			systemInfo.ProcessorType = pType
		}
		if procInfo.ProcessorFamily > 0 {
			processor.Family = int(procInfo.ProcessorFamily)
		}
		//This is available at SMBIOS documentation
		if d.Version.Major >= 3 || d.Version.Minor < 5 || d.Version.Minor > 9 {
			if procInfo.CoreCount2 > 0 {
				processor.CoreCount = int(procInfo.CoreCount2)
			}
		} else {
			if procInfo.CoreCount > 0 {
				processor.CoreCount = int(procInfo.CoreCount)
			}

		}

		valArrSize := byte(len(ss))
		if procInfo.ProcessorManufacturer > 0 && procInfo.ProcessorManufacturer < valArrSize {
			processor.Product = strings.TrimSpace(ss[procInfo.ProcessorManufacturer])
		}
		if procInfo.CurrentSpeed > 0 {
			processor.ClockSpeedInMHz = int(procInfo.CurrentSpeed)
		}
		systemInfo.Processors = append(systemInfo.Processors, processor)
	}
	if h.Type == 17 {
		physicalMemory := &PhysicalMemory{}

		fbLen := len(fb)
		var memInfo MemoryInfoRead
		//Note:- For description of each field please refer the pdf 'DSP0134_3.0.0.pdf', which is available in the same repo.
		//Checking size as per SMBIOS 2.1 spec
		if fbLen >= sizeAsPer2_1 {
			//This will copy 2 Bytes related to 'Physical Memory Array Handle'
			memInfo.MemArrayHandle = binary.LittleEndian.Uint16(fb[0:2])
			//This will copy 2 Bytes related to 'Memory Error Information Handle'
			memInfo.MemErrorInfoHandle = binary.LittleEndian.Uint16(fb[2:4])
			//This will copy 2 Bytes related to 'Total Width'
			memInfo.TotalWidth = binary.LittleEndian.Uint16(fb[4:6])
			//This will copy 2 Bytes related to 'Data Width'
			memInfo.DataWidth = binary.LittleEndian.Uint16(fb[6:8])
			//This will copy 2 Bytes related to 'Size'
			memInfo.Size = binary.LittleEndian.Uint16(fb[8:10])
			//This will copy 1 Byte related to 'Form Factor'
			memInfo.FormFactor = fb[10]
			//This will copy 1 Byte related to 'Device Set'
			memInfo.DeviceSet = fb[11]
			//This will copy 1 Byte related to 'Device Locator'
			memInfo.DeviceLocator = fb[12]
			//This will copy 1 Byte related to 'Bank Locator'
			memInfo.BankLocator = fb[13]
			//This will copy 1 Byte related to 'Memory Type'
			memInfo.MemType = fb[14]
			//This will copy 2 Bytes related to 'Type Detail'
			memInfo.TypeDetail = binary.LittleEndian.Uint16(fb[15:17])
		}

		//Checking size as per SMBIOS 2.3 spec
		if fbLen >= sizeAsPer2_3 {
			//This will copy 2 Bytes related to 'Speed'
			memInfo.Speed = binary.LittleEndian.Uint16(fb[17:19])
			//This will copy 1 Byte related to 'Index of the Manufacturer string'
			memInfo.Manufacturer = fb[19]
			//This will copy 1 Byte related to 'Index of the SerialNumber string'
			memInfo.SerialNumber = fb[20]
			//This will copy 1 Byte related to 'Index of the AssetTag string'
			memInfo.AssetTag = fb[21]
			//This will copy 1 Byte related to 'Index of the PartNumber string'
			memInfo.PartNumber = fb[22]
		}

		//Checking size as per SMBIOS 2.6 spec
		if fbLen >= sizeAsPer2_6 {
			//This will copy 1 Byte related to 'Attribute'
			memInfo.Attribute = fb[23]
		}

		//Checking size as per SMBIOS 2.7 spec
		if fbLen >= sizeAsPer2_7 {
			//This will copy 4 Bytes related to 'Extended Memory Size'
			memInfo.ExtendedSize = binary.LittleEndian.Uint32(fb[24:28])
			//This will copy 2 Bytes related to 'Configured Memory Clock Speed'
			memInfo.ConfiguredMemClockSpeed = binary.LittleEndian.Uint16(fb[28:30])
		}

		//Checking size as per SMBIOS 2.8 spec
		if fbLen >= sizeAsPer2_8 {
			//This will copy 2 Bytes related to 'Minimum voltage'
			memInfo.MinVoltage = binary.LittleEndian.Uint16(fb[30:32])
			//This will copy 2 Bytes related to 'Maximum voltage'
			memInfo.MaxVoltage = binary.LittleEndian.Uint16(fb[32:34])
			//This will copy 2 Bytes related to 'Configured voltage'
			memInfo.ConfiguredVoltage = binary.LittleEndian.Uint16(fb[34:36])
		}

		arrSize := byte(len(ss))

		// In case of virtual machine Manufacturer may not be reterived, Reason: NOT RETURNED FROM SMBIOS INFO
		if memInfo.Manufacturer > 0 && memInfo.Manufacturer <= arrSize {
			index := memInfo.Manufacturer - 1
			if index >= 0 {
				physicalMemory.Manufacturer = ss[index]
			}
		}

		// In case of virtual machine SerialNumber may not be reterived, Reason: NOT RETURNED FROM SMBIOS INFO
		if memInfo.SerialNumber > 0 && memInfo.SerialNumber <= arrSize {
			index := memInfo.SerialNumber - 1
			if index >= 0 {
				memSerNo := ss[index]
				systemInfo.Memory = memSerNo
				physicalMemory.SerialNumber = memSerNo
			}
		}

		memSize := uint64(memInfo.Size)
		//If the memInfo.Size size is 32GB or greater, we need to parse the extended field.
		// Spec says 0x7fff(extendedSizeThreyshold) in regular size field means we should parse the extended.
		if memInfo.Size == extendedSizeThreyshold && fbLen >= sizeAsPer2_7 {
			memSize = uint64(memInfo.ExtendedSize)
		}

		// The granularity in which the value is specified
		// depends on the setting of the most-significant bit (bit
		// 15). If the bit is 0, the value is specified in megabyte
		// units; if the bit is 1, the value is specified in kilobyte
		// units.
		memSizeInByte := memSize * uint64(kbToByteConvRatio)
		if fb[9]&0x80 == 0 {
			memSizeInByte = memSize * uint64(mbToByteConvRatio)
		}
		physicalMemory.SizeInBytes = memSizeInByte

		if memInfo.TotalWidth > 0 {
			physicalMemory.TotalWidth = uint64(memInfo.TotalWidth)
		}
		if memInfo.DataWidth > 0 {
			physicalMemory.DataWidth = uint64(memInfo.DataWidth)
		}

		// Check for the size, if size is zero that means Empty DIMM Slot
		if physicalMemory.SizeInBytes != 0 {
			systemInfo.PhyMemory = append(systemInfo.PhyMemory, physicalMemory)
		}
	}
	if h.Type == 0 {
		bios := (*BIOSInfoRead)(unsafe.Pointer(&fb[0]))
		biosInfo := &BIOSInfo{}
		valArrSize := byte(len(ss))
		if bios.Vendor > 0 && bios.Vendor <= valArrSize {
			biosInfo.Vendor = ss[bios.Vendor-1]
		}
		if bios.Version > 0 && bios.Version <= valArrSize {
			biosInfo.Version = ss[bios.Version-1]
		}
		if d.Version.Major >= 0 && d.Version.Minor >= 0 {
			biosInfo.BiosVersion = strconv.Itoa(d.Version.Major) + "." + strconv.Itoa(d.Version.Minor)
		}
		systemInfo.BiosInfo = biosInfo
		if bios.ReleaseDate > 0 {
			systemInfo.BiosInfo.ReleaseDate = ss[bios.ReleaseDate-1]
		}
	}

	return &Structure{
		Header:     *h,
		Formatted:  fb,
		Strings:    ss,
		SystemInfo: systemInfo,
	}, nil
}

// parseHeader parses a Structure's Header from the stream.
func (d *Decoder) parseHeader() (*Header, error) {
	if _, err := io.ReadFull(d.br, d.b[:headerLen]); err != nil {
		return nil, err
	}

	return &Header{
		Type:   d.b[0],
		Length: d.b[1],
		Handle: binary.LittleEndian.Uint16(d.b[2:4]),
	}, nil
}

// parseFormatted parses a Structure's formatted data from the stream.
func (d *Decoder) parseFormatted(l int) ([]byte, error) {
	// Guard against malformed input length.
	if l < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	if l == 0 {
		// No formatted data.
		return nil, nil
	}

	if _, err := io.ReadFull(d.br, d.b[:l]); err != nil {
		return nil, err
	}

	// Make a copy to free up the internal buffer.
	fb := make([]byte, len(d.b[:l]))
	copy(fb, d.b[:l])

	return fb, nil
}

func (d *Decoder) parseField() ([]string, error) {
	term, err := d.br.Peek(2)
	if err != nil {
		return nil, err
	}

	// If no string-set present, discard delimeter and end parsing.
	if bytes.Equal(term, endStringSet) {
		if _, err := d.br.Discard(2); err != nil {
			return nil, err
		}

		return nil, nil
	}

	var ss []string
	for {
		s, more, err := d.parseString()
		if err != nil {
			return nil, err
		}

		// When final string is received, end parse loop.
		ss = append(ss, s)
		if !more {
			break
		}
	}

	return ss, nil
}

// parseStrings parses a Structure's strings from the stream, if they
// are present.
func (d *Decoder) parseStrings() ([]string, error) {
	term, err := d.br.Peek(2)
	if err != nil {
		return nil, err
	}

	// If no string-set present, discard delimeter and end parsing.
	if bytes.Equal(term, endStringSet) {
		if _, err := d.br.Discard(2); err != nil {
			return nil, err
		}

		return nil, nil
	}

	var ss []string
	for {
		s, more, err := d.parseString()
		if err != nil {
			return nil, err
		}

		// When final string is received, end parse loop.
		ss = append(ss, s)
		if !more {
			break
		}
	}

	return ss, nil
}

// parseString parses a single string from the stream, and returns if
// any more strings are present.
func (d *Decoder) parseString() (str string, more bool, err error) {
	// We initially read bytes because it's more efficient to manipulate bytes
	// and allocate a string once we're all done.
	//
	// Strings are null-terminated.
	raw, err := d.br.ReadBytes(0x00)
	if err != nil {
		return "", false, err
	}

	b := bytes.TrimRight(raw, "\x00")

	peek, err := d.br.Peek(1)
	if err != nil {
		return "", false, err
	}

	if !bytes.Equal(peek, null) {
		// Next byte isn't null; more strings to come.
		return string(b), true, nil
	}

	// If two null bytes appear in a row, end of string-set.
	// Discard the null and indicate no more strings.
	if _, err := d.br.Discard(1); err != nil {
		return "", false, err
	}

	return string(b), false, nil
}

var _ io.ReadCloser = &opaqueReadCloser{}

// An opaqueReadCloser masks the type of the underlying io.ReadCloser to
// prevent type assertions.
type opaqueReadCloser struct {
	rc io.ReadCloser
}

func (rc *opaqueReadCloser) Read(b []byte) (int, error) { return rc.rc.Read(b) }
func (rc *opaqueReadCloser) Close() error               { return rc.rc.Close() }
