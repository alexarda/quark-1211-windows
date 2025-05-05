/** @file
  Definition of Pei Core Structures and Services
  
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

#ifndef _QUARK_BOOT_ROM_LIB_H_
#define _QUARK_BOOT_ROM_LIB_H_

#include "QuarkBootRom.h"

//
// Rom lib has one .inf with MODULE_TYPE=BASE (for inclusion in PEI or DXE)
// so Mem Alloc Routines passed to its entry points.
//
typedef
VOID *
(EFIAPI *QUARK_AUTH_ALLOC_POOL) (
  IN UINTN                                AllocationSize
  );

typedef
VOID
(EFIAPI *QUARK_AUTH_FREE_POOL) (
  IN VOID                                 *Buffer
  );

/** Validate key module routine.

  Checks the SHA256 digest of the Oem Key in a module header against
  that of the key held in fuse bank and then uses that key to validate
  key module.

  @param[in]       Header         A pointer to a header structure of a key
                                  module in memory to be validated..
  @param[in]       Data           Pointer to the signed data associated with
                                  this module.
  @param[in]       ModuleKey      The key used to sign the data.
  @param[in]       Signature      The signature of the data.
  @param[in]       MemoryBuffer   Pointer to crypto heap management structure.
  @param[in]       KeyBankNumber  Which fuse bank are we pulling the Intel key from.

  @retval  QUARK_ROM_NO_ERROR                            If Key Module Validates 
                                                         Successfully.
  @retval  QUARK_ROM_FATAL_KEY_MODULE_FUSE_COMPARE_FAIL  if the Digest of the Intel Key
                                                         in the Header does not match
                                                         that stored in the fuse.
  @retval  QUARK_ROM_FATAL_KEY_MODULE_VALIDATION_FAIL    if the RSA signature
                                                         is not successfully validated.
  @retval  QUARK_ROM_FATAL_INVALID_KEYBANK_NUM           If key bank number too large.
  @return  Other                                         Unexpected error.

**/
typedef
QuarkRomFatalErrorCode
(*VALIDATE_KEY_MODULE) (
  const QuarkSecurityHeader_t * const Header,
  const UINT8 * const Data,
  const RSA2048PublicKey_t * const ModuleKey,
  const UINT8 * const Signature,
  ScratchMemory_t * const MemoryBuffer,
  const UINT8 KeyBankNumber
  );

/**
  Security library to authenticate a signed image.

  @param[in]       ImageBaseAddress       Pointer to the current image under
                                          consideration
  @param[in]       CallerSignedKeyModule  Pointer to signed key module to
                                          validate image against. If NULL use
                                          default.
  @param[in]       AuthKeyModule          If TRUE authenticate key module
                                          as well as image.
  @param[in]       KeyBankNumberPtr       Pointer to key bank number. If NULL
                                          use default bank.
  @param[in]       QAllocPool             Pointer allocate pool routine for
                                          UEFI emviroment.
  @param[in]       QFreePool              Pointer free pool routine for
                                          UEFI emviroment.

  @retval EFI_SUCCESS             Image is legal
  @retval EFI_SECURITY_VIOLATION  Image is NOT legal.
  @retval EFI_INVALID_PARAMETER   Param options required QAllocPool
                                  and QFreePool to be provided.
  @retval EFI_OUT_OF_RESOURCES    Not enough memory to complete
                                  operation.

**/
EFI_STATUS
EFIAPI
SecurityAuthenticateImage (
  IN VOID                                 *ImageBaseAddress,
  IN QuarkSecurityHeader_t                *CallerSignedKeyModule OPTIONAL,
  IN CONST BOOLEAN                        AuthKeyModule,
  IN UINT8                                *KeyBankNumberPtr OPTIONAL,
  IN QUARK_AUTH_ALLOC_POOL                QAllocPool OPTIONAL,
  IN QUARK_AUTH_FREE_POOL                 QFreePool OPTIONAL
  );

/**
  Security library to authenticate a signed key module.

  @param[in]       SignedKetModule  Pointer to key module to authenticate.
  @param[in]       KeyBankNumber    Key bank number to use.
  @param[in]       CallerMemBuf     Heap to be used by the BootRom crypto
                                    functions. If == NULL alloc a heap.
  @param[in]       CallerMemBufSize Size in bytes of CallerMemBuf param.
  @param[in]       QAllocPool       Pointer allocate pool routine for
                                    UEFI emviroment.
  @param[in]       QFreePool        Pointer free pool routine for
                                    UEFI emviroment.

  @retval EFI_SUCCESS             Key module is legal
  @retval EFI_SECURITY_VIOLATION  Key module is NOT legal.
  @retval EFI_INVALID_PARAMETER   Param options required QAllocPool
                                  and QFreePool to be provided.
  @retval EFI_OUT_OF_RESOURCES    Not enough memory to complete
                                  operation.

**/
EFI_STATUS
EFIAPI
SecurityAuthenticateKeyModule (
  IN QuarkSecurityHeader_t                *SignedKeyModule,
  IN CONST UINT8                          KeyBankNumber,
  IN UINT8                                *CallerMemBuf OPTIONAL,
  IN UINTN                                CallerMemBufSize OPTIONAL,
  IN QUARK_AUTH_ALLOC_POOL                QAllocPool OPTIONAL,
  IN QUARK_AUTH_FREE_POOL                 QFreePool OPTIONAL
  );

/**
  Check if a secure lock boot is required based on Pcd
  and SKU / Provisioning

  @retval TRUE  Secure Lock boot required
  @retval FALSE Secure Lock noot not required
**/
BOOLEAN
EFIAPI
QuarkCheckSecureLockBoot (
  VOID
  );

/**
  Check if CSH is valid for EDKII Firmware volume install.

  @param[in]       CshFv  Firmware volume CSH to check

  @retval TRUE     Valid CSH for EDKII Fv Install.
  @retval FALSE    Invalid CSH for EDKII Fv Install.

**/
BOOLEAN
EFIAPI
SecurityValidCshForEdkFvInstall (
  IN QuarkSecurityHeader_t                *CshFv
  );

#endif
