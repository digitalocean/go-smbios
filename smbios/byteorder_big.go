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

// +build armbe arm64be ppc64 mips mips64 mips64p32 ppc s390 s390x sparc sparc64

// This file defines the native byte order for big-endian architectures.
// If your architecture is missing, please modify the build tags above or in
// byteorder_little.go.

package smbios

import (
	"encoding/binary"
)

var nativeByteOrder = binary.BigEndian
