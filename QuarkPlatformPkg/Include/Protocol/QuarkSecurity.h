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
  QuarkSecurity.h

Abstract:
  Protocol header file for QuarkSecurity Protocol.

--*/

#ifndef _QUARK_SECURITY_PROTOCOL_H_
#define _QUARK_SECURITY_PROTOCOL_H_

#include "QuarkBootRom.h"
#include <Guid/QuarkCapsuleGuid.h>

//
// Constant definitions.
//

//
// Type definitions.
//

///
/// Forward reference for pure ANSI compatability
///
typedef struct _QUARK_SECURITY_PROTOCOL  QUARK_SECURITY_PROTOCOL;

///
/// Extern the GUID for protocol users.
///
extern EFI_GUID gQuarkSecurityGuid;

//
// Service typedefs to follow.
//

/**
  Service to authenticate a signed image.

  @param[in]       ImageBaseAddress       Pointer to the current image under
                                          consideration
  @param[in]       CallerSignedKeyModule  Pointer to signed key module to
                                          validate image against. If NULL use
                                          default.
  @param[in]       AuthKeyModule          If TRUE authenticate key module
                                          as well as image.
  @param[in]       KeyBankNumberPtr       Pointer to key bank number. If NULL
                                          use default bank.

  @retval EFI_SUCCESS             Image is legal
  @retval EFI_SECURITY_VIOLATION  Image is NOT legal.
  @retval EFI_INVALID_PARAMETER   Param options required QAllocPool
                                  and QFreePool to be provided.
  @retval EFI_OUT_OF_RESOURCES    Not enough memory to complete
                                  operation.

**/
typedef
EFI_STATUS
(EFIAPI *QUARK_AUTHENTICATE_IMAGE) (
  IN VOID                                 *ImageBaseAddress,
  IN QuarkSecurityHeader_t                *CallerSignedKeyModule OPTIONAL,
  IN CONST BOOLEAN                        AuthKeyModule,
  IN UINT8                                *KeyBankNumberPtr OPTIONAL
  );

/**
  Service to authenticate a signed key module.

  @param[in]       SignedKetModule  Pointer to key module to authenticate.
  @param[in]       KeyBankNumber    Key bank number to use.
  @param[in]       CallerMemBuf     Heap to be used by the BootRom crypto
                                    functions. If == NULL alloc a heap.
  @param[in]       CallerMemBufSize Size in bytes of CallerMemBuf param.

  @retval EFI_SUCCESS             Key module is legal
  @retval EFI_SECURITY_VIOLATION  Key module is NOT legal.
  @retval EFI_INVALID_PARAMETER   Param options required QAllocPool
                                  and QFreePool to be provided.
  @retval EFI_OUT_OF_RESOURCES    Not enough memory to complete
                                  operation.

**/
typedef
EFI_STATUS
(EFIAPI *QUARK_AUTHENTICATE_KEY_MODULE) (
  IN QuarkSecurityHeader_t                *SignedKeyModule,
  IN CONST UINT8                          KeyBankNumber,
  IN UINT8                                *CallerMemBuf OPTIONAL,
  IN UINTN                                CallerMemBufSize OPTIONAL
  );

/**
  Capsule security service.

  Given capsule this service will:
    1) Copy capsule for programming into signed capsule buffer.
    2) Do no security tasks if running on base hardware sku.
    3) Verify capsule properly signed.
    4) Verify Capsule embedded images have Svn Value >= Current Value.
    5) Return new Svn Area data if Svn Area needs to be updated.
    6) Inform caller when Svn Area has to be updated.
    7) Check that fixed Svn Index rules not broken by capsule embedded images.
    8) Do extra validation for firmware known capsule embedded images.
    9) Place update hints for critical embedded images first in hint array,
       recovery image always 1st image to be programmed.
    10) If MFH in capsule then return to offset to Mfh Data in capsule.
    11) Return pointer to maniuplated capsule to be programmed.

  @param[in out]   CapsulePtr           On input pointer to capsule, on output
                                        pointer to contiguous buffer with _CSH
                                        and capsule. Caller must free buffer.
  @param[out]      MfhSourceOffset      Offset to New Mfh in capsule.
  @param[out]      NewSvnArray          Caller allocated memory to receive new
                                        Svn Array.
  @param[out]      SvnAreaUpdPoint      When to update Svn Array,
                                        see SVN_UPDATE_POINT enum def.
  @param[out]      SvnAreaUpdTrigAddr   If SvnAreaUpdPoint==SvnUpdAtTrigAddr
                                        then update Svn area when this addr
                                        reached in capsule.

  IN UINT8                                **CapsulePtr,
  OUT UINTN                               *MfhSourceOffset,
  IN OUT UINT32                           *NewSvnArray,
  OUT SVN_UPDATE_POINT                    *SvnAreaUpdPoint,
  OUT UINT32                              *SvnAreaUpdTrigAddr

**/
typedef
EFI_STATUS
(EFIAPI *QUARK_CAPSULE_SECURITY) (
  IN UINT8                                **CapsulePtr,
  OUT UINTN                               *MfhSourceOffset,
  IN OUT UINT32                           *NewSvnArray,
  OUT SVN_UPDATE_POINT                    *SvnAreaUpdPoint,
  OUT UINT32                              *SvnAreaUpdTrigAddr,
  OUT BOOLEAN                             *NvramUpdatable
  );

/**
  Return TRUE if UEFI Secure Boot Auto Provisioning is active.

  @retval TRUE                    UEFI Secure boot provisioning active.
  @retval FALSE                   UEFI Secure Boot provisioning inactive.

**/
typedef
BOOLEAN
(EFIAPI *QUARK_IS_UEFI_SECURE_BOOT_PROVISIONING_ACTIVE) (
  VOID
  );

/**
  Call EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service.

  Call EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service for a table of
  variables deemed by platform policy to be locked after DXE phase of execution.

  Function will assert if EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service
  returns an error status.

**/
typedef
VOID
(EFIAPI *QUARK_VARIABLE_REQUEST_TO_LOCK) (
  VOID
  );

/**
  Return TRUE if UEFI Secure Boot is enabled.

  @retval TRUE                    UEFI Secure boot enabled.
  @retval FALSE                   UEFI Secure Boot disabled or not supported.

**/
typedef
BOOLEAN
(EFIAPI *QUARK_IS_UEFI_SECURE_BOOT_ENABLED) (
  VOID
  );

///
/// Quark security protocol declaration.
///
struct _QUARK_SECURITY_PROTOCOL {
  QUARK_AUTHENTICATE_IMAGE           AuthenticateImage;              ///< see service typedef.
  QUARK_AUTHENTICATE_KEY_MODULE      AuthenticateKeyModule;          ///< see service typedef.
  QUARK_CAPSULE_SECURITY             CapsuleSecurity;                ///< see service typedef.
  QUARK_IS_UEFI_SECURE_BOOT_PROVISIONING_ACTIVE IsUefiSecureBootProvisioningActive;  ///< see service typedef.
  QUARK_VARIABLE_REQUEST_TO_LOCK     RequestToLock;                  ///< see service typedef.
  QUARK_IS_UEFI_SECURE_BOOT_ENABLED  IsUefiSecureBootEnabled;        ///< see service typedef.
};

#endif  // _QUARK_SECURITY_PROTOCOL_H_
