/*++

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

Module Name:

  PlatformVariableTables.h

Abstract:

  Tables of UEFI variables used by this platform package.

--*/

#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>

#ifndef _PLATFORM_VARIABLE_TABLES_H_
#define _PLATFORM_VARIABLE_TABLES_H_

//
// Struct for table entries specifing vendor guid and variable names
// of variables.
// If the VariableName is NULL then all variables with the specified VendorGuid
// are relevant.
//
typedef struct {
  EFI_GUID                          *VendorGuid;
  CHAR16                            *VariableName;
} PLATFORM_VARIABLE_TABLE_ENTRY;

//
// VendorGuid specified by Microsoft reguirement in
// System.Fundamentals.Firmware.UEFISecureBoot to be maintained
// during normal firmware updates on UEFI Secure Boot Enabled
// systems.
//
extern EFI_GUID gEfiMicrosoftSecureBootMaintainGuid;

//
// Table of variables to be maintained on UEFI Secure Boot enabled systems on
// firmware update.
//
#define SECURE_BOOT_MAINTAIN_VARIABLE_TABLE_DEFINITION \
  /* VendorGuid,                                VariableName*/\
  {&gEfiGlobalVariableGuid,                     EFI_PLATFORM_KEY_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_KEY_EXCHANGE_KEY_NAME},\
  {&gEfiImageSecurityDatabaseGuid,              NULL},\
  {&gEfiMicrosoftSecureBootMaintainGuid,        NULL},\
  {&gEfiGlobalVariableGuid,                     EFI_SETUP_MODE_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_SECURE_BOOT_MODE_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_SIGNATURE_SUPPORT_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_VENDOR_KEYS_VARIABLE_NAME},\
  {&gEfiAuthenticatedVariableGuid,              NULL},\
  {&gEfiCertDbGuid,                             NULL},\
  {&gEfiVendorKeysNvGuid,                       NULL},\
  {&gEfiSecureBootEnableDisableGuid,            NULL},\
  {&gEfiCustomModeEnableGuid,                   NULL},\

//
// Table of variables required by platform policy to be locked
// after the DXE phase of execution.
//
#define QUARK_VARIABLE_REQUEST_TO_LOCK_TABLE_DEFINITION \
  /* VendorGuid,                                VariableName*/\
  {&gEfiMemoryConfigDataGuid,                   EFI_MEMORY_CONFIG_DATA_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_PLATFORM_KEY_NAME},\
  {&gEfiGlobalVariableGuid,                     EFI_KEY_EXCHANGE_KEY_NAME},\
  {&gEfiImageSecurityDatabaseGuid,              EFI_IMAGE_SECURITY_DATABASE},\
  {&gEfiImageSecurityDatabaseGuid,              EFI_IMAGE_SECURITY_DATABASE1},

#endif // #ifndef _PLATFORM_VARIABLE_TABLES_H_
