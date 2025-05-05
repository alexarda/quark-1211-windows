/** @file
  Quark Boot Rom definitions.

Copyright (c) 2013-2016 Intel Corporation.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in
the documentation and/or other materials provided with the
distribution.
* Neither the name of Intel Corporation nor the names of its
contributors may be used to endorse or promote products derived
from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**/

#ifndef _QUARK_BOOT_ROM_H_
#define _QUARK_BOOT_ROM_H_

#include "FlashMap.h"

#define QUARK_DEFAULT_INTEL_KEY_FUSE_BANK                   0             // There are 3 fuse banks - we use 0 as a default.
#define QUARK_KEY_MODULE_MAX_SIZE                           0x00008000    // 32K
#define QUARK_KEY_MODULE_BASE_ADDRESS                       FLASH_REGION_QUARK_KEY_MODULE_BASE_ADDRESS
#define QUARK_CRYPTO_HEAP_SIZE_BYTES                        0x1900
#define QUARK_BOOTROM_VALIDATE_FUNCTION_ENTRYPOINT_ADDRESS  0xFFFFFFE0
#define QUARK_BOOTROM_VALIDATE_KEY_ENTRYPOINT_ADDRESS       0xFFFE1D3A
#define QUARK_CSH_IDENTIFIER                                SIGNATURE_32 ('H', 'S', 'C', '_')
#define QUARK_RSA_2048_MODULUS_SIZE_BYTES                   256           // 256 Bytes Modulus size = 2048 bits.
#define QUARK_RSA_2048_EXPONENT_SIZE_BYTES                  4

//
// Quark ROM error type and error values.
//
typedef UINT32                                              QuarkRomFatalErrorCode;
#define QUARK_ROM_NO_ERROR                                  0
#define QUARK_ROM_FATAL_NO_VALID_MODULES                    1
#define QUARK_ROM_FATAL_RMU_DMA_TIMEOUT                     2
#define QUARK_ROM_FATAL_MEM_TEST_FAIL                       3
#define QUARK_ROM_FATAL_ACPI_TIMER_ERROR                    4
#define QUARK_ROM_FATAL_UNEX_RETURN_FROM_RUNTIME            5
#define QUARK_ROM_FATAL_ERROR_DMA_TIMEOUT                   6
#define QUARK_ROM_FATAL_OUT_OF_BOUNDS_MODULE_ENTRY          7
#define QUARK_ROM_FATAL_MODULE_SIZE_EXCEEDS_MEMORY          8
#define QUARK_ROM_FATAL_KEY_MODULE_FUSE_COMPARE_FAIL        9
#define QUARK_ROM_FATAL_KEY_MODULE_VALIDATION_FAIL          10
#define QUARK_ROM_FATAL_STACK_CORRUPT                       11
#define QUARK_ROM_FATAL_INVALID_KEYBANK_NUM                 12

//
// Svn constants.
//
#define QUARK_SVN_ARRAY_SIZE                                16
#define QUARK_FIXED_SVN_INDEX_KEY_MODULE                    0
#define QUARK_FIXED_SVN_INDEX_STAGE1_IMAGE                  1
#define QUARK_FIXED_SVN_INDEX_RECOVERY_IMAGE                2
#define QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE                 15

//
// Boot Rom structures.
//
typedef struct QuarkSecurityHeader_t
{
  UINT32  CSH_Identifier;             // Unique identifier to sanity check signed module presence
  UINT32  Version;                    // Current version of CSH used. Should be one for Quark A0.
  UINT32  ModuleSizeBytes;            // Size of the entire module including the module header and payload
  UINT32  SecurityVersionNumberIndex; // Index of SVN to use for validation of signed module
  UINT32  SecurityVersionNumber;      // Used to prevent against roll back of modules
  UINT32  RsvdModuleID;               // Currently unused for Clanton. Maintaining for future use
  UINT32  RsvdModuleVendor;           // Vendor Identifier. For Intel products value is 0x00008086
  UINT32  RsvdDate;                   // BCD representation of build date as yyyymmdd, where yyyy=4 digit year, mm=1-12, dd=1-31
  UINT32  ModuleHeaderSizeBytes;      // Total length of the header including including any padding optionally added by the signing tool.
  UINT32  HashAlgorithm;              // What Hash is used in the module signing.
  UINT32  CryptoAlgorithm;            // What Crypto is used in the module signing.
  UINT32  KeySizeBytes;               // Total length of the key data including including any padding optionally added by the signing tool.
  UINT32  SignatureSizeBytes;         // Total length of the signature including including any padding optionally added by the signing tool.
  UINT32  RsvdNextHeaderPointer;      // 32-bit pointer to the next Secure Boot Module in the chain, if there is a next header.
  UINT32  Reserved[8/sizeof(UINT32)]; // Bytes reserved for future use, padding structure to required size.
} QuarkSecurityHeader_t;

typedef struct RSA2048PublicKey_t
{
  UINT32  ModulusSizeBytes;           // Size of the RSA public key modulus
  UINT32  ExponentSizeBytes;          // Size of the RSA public key exponent
  UINT32  Modulus[QUARK_RSA_2048_MODULUS_SIZE_BYTES/sizeof(UINT32)];// Key Modulus, 256 bytes = 2048 bits
  UINT32  Exponent[QUARK_RSA_2048_EXPONENT_SIZE_BYTES/sizeof(UINT32)]; // Exponent Key, can be up to 4 bytes in our case.
} RSA2048PublicKey_t;

typedef struct ScratchMemory_t
{
  UINT8   *HeapStart;                 // Address of memory from which we can start to allocate.
  UINT8   *HeapEnd;                   // Address of final byte of memory we can allocate up to.
  UINT8   *NextFreeMem;               // Pointer to the next free address in the heap.
  UINT32  DebugCode;                  // A progress code, updated as we go along.
  UINT32  FatalCode;                  // An indicator of why we failed to boot.
} ScratchMemory_t;

#endif
