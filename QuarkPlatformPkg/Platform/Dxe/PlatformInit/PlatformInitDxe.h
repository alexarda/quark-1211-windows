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
  PlatformInitDxe.h

Abstract:
  Platform init DXE driver header file.

--*/

#ifndef _PLATFORM_TYPES_H_
#define _PLATFORM_TYPES_H_

#include <PiDxe.h>
#include <Protocol/PlatformType.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/PlatformHelperLib.h>
#include <Library/PlatformPcieHelperLib.h>
#include <Library/IntelQNCLib.h>
#include <Library/QNCAccessLib.h>
#include <Library/QuarkBootRomLib.h>
#include <Library/PlatformDataLib.h>
#include <Library/I2cLib.h>
#include <Protocol/Variable.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/VariableLock.h>
#include <Protocol/CpuIo.h>
#include <Protocol/Cpu.h>
#include <Protocol/PlatformType.h>
#include <Protocol/PciEnumerationComplete.h>
#include <Protocol/Spi.h>
#include <Protocol/PlatformSmmSpiReady.h>
#include <Protocol/IioUds.h>
#include <Protocol/SmmConfiguration.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/QuarkSecurity.h>
#include <Protocol/SecureBootHelper.h>
#include <Protocol/GlobalNvsArea.h>
#include <Protocol/TcgService.h>
#include <Guid/HobList.h>
#include <Guid/ImageAuthentication.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/MemoryConfigData.h>
#include <CpuRegs.h>
#include <IntelQNCRegs.h>
#include <Platform.h>
#include <Pcal9555.h>
#include <PlatformBoards.h>
#include <IohAccess.h>
#include <FlashLayout.h>
#include <PlatformVariableTables.h>
#include "DxeFvSecurity.h"

#define BLOCK_SIZE_32KB                             0x8000
#define BLOCK_SIZE_64KB                             0x10000
#define EFI_PLATFORM_TYPE_DRIVER_PRIVATE_SIGNATURE  SIGNATURE_32 ('T', 'Y', 'P', 'P')
#define EFI_IIO_UDS_DRIVER_PRIVATE_SIGNATURE        SIGNATURE_32 ('S', 'D', 'U', 'I')
#define EFI_QUARK_SECURITY_DRIVER_PRIVATE_SIGNATURE SIGNATURE_32 ('Q', 'R', 'K', 'S')

typedef struct {
  UINTN                               Signature;
  EFI_HANDLE                          Handle;               // Handle for protocol this driver installs on
  EFI_PLATFORM_TYPE_PROTOCOL          PlatformType;         // Policy protocol this driver installs
} EFI_PLATFORM_DATA_DRIVER_PRIVATE;

typedef struct {
  UINTN                               Signature;
  EFI_HANDLE                          Handle;         // Handle for protocol this driver installs on
  EFI_IIO_UDS_PROTOCOL                IioUds;         // Policy protocol this driver installs
} EFI_IIO_UDS_DRIVER_PRIVATE;

typedef struct {
  UINTN                               Signature;
  EFI_HANDLE                          Handle;         // Handle for protocol this driver installs on
  QUARK_SECURITY_PROTOCOL             Protocol;       // Security protocol this driver installs.
} QUARK_SECURITY_DRIVER_PRIVATE;

//
// Instantiation of Driver's private data.
//
extern EFI_PLATFORM_DATA_DRIVER_PRIVATE    mPrivatePlatformData;
extern EFI_IIO_UDS_DRIVER_PRIVATE          mIioUdsPrivateData;
extern IIO_UDS                             *IioUdsData;

//
// Function prototypes for routines private to this driver.
//
EFI_STATUS
EFIAPI
CreateConfigEvents (
  VOID
  );

EFI_STATUS
EFIAPI
PlatformCapsuleSecurity (
  IN UINT8                                **CapsulePtr,
  OUT UINTN                               *MfhSourceOffset,
  IN OUT UINT32                           *NewSvnArray,
  OUT SVN_UPDATE_POINT                    *SvnAreaUpdPoint,
  OUT UINT32                              *SvnAreaUpdTrigAddr,
  OUT BOOLEAN                             *NvramUpdatable
  );

EFI_STATUS
EFIAPI
QuarkAuthenticateImage (
  IN VOID                                 *ImageBaseAddress,
  IN QuarkSecurityHeader_t                *CallerSignedKeyModule OPTIONAL,
  IN CONST BOOLEAN                        AuthKeyModule,
  IN UINT8                                *KeyBankNumberPtr OPTIONAL
  );

EFI_STATUS
EFIAPI
QuarkAuthenticateKeyModule (
  IN QuarkSecurityHeader_t                *SignedKeyModule,
  IN CONST UINT8                          KeyBankNumber,
  IN UINT8                                *CallerMemBuf OPTIONAL,
  IN UINTN                                CallerMemBufSize OPTIONAL
  );

BOOLEAN
EFIAPI
QuarkAutoProvisionSecureBoot (
  IN OUT PDAT_AREA                        *UserPdatArea
  );

BOOLEAN
EFIAPI
QuarkIsUefiSecureBootProvisioningActive (
  VOID
  );

EFI_STATUS
EFIAPI
QuarkMaintainSecureBootVariables (
  OUT UINTN                               *MaintainCountPtr OPTIONAL
  );

VOID
EFIAPI
QuarkRequestToLock (
  VOID
  );

BOOLEAN
EFIAPI
QuarkIsUefiSecureBootEnabled (
  VOID
  );

#endif
