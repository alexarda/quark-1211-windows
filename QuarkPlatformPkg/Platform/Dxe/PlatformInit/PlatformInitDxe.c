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

  PlatformInitDxe.c

Abstract:

  Platform init DXE driver for this platform.

--*/

//
// Statements that include other files
//
#include "PlatformInitDxe.h"

CHAR16                              QncName[40];
CHAR16                              IioName[40];

//
// Instantiation of Driver's private data.
//
EFI_PLATFORM_DATA_DRIVER_PRIVATE    mPrivatePlatformData;
EFI_IIO_UDS_DRIVER_PRIVATE          mIioUdsPrivateData;
IIO_UDS                             *IioUdsData;          // Pointer to UDS in Allocated Memory Pool
QUARK_SECURITY_DRIVER_PRIVATE       mPrivateSecurity;
PLATFORM_VARIABLE_TABLE_ENTRY       mRequestToLockTable[] = { QUARK_VARIABLE_REQUEST_TO_LOCK_TABLE_DEFINITION };
CONST UINTN                         mRequestToLockTableLen = (sizeof(mRequestToLockTable) / sizeof(PLATFORM_VARIABLE_TABLE_ENTRY));

//
// Routines local to this source module.
//

STATIC
VOID
GetQncName (
  VOID
  )
{

  switch (mPrivatePlatformData.PlatformType.QncSku) {
    case QUARK_MC_DEVICE_ID:
      StrCpy (QncName, L"Quark");
      break;
    case QUARK2_MC_DEVICE_ID:
      StrCpy (QncName, L"Quark2");
      break;
  default:
    StrCpy (QncName, L"Unknown");
  }

  //
  // Revision
  //
  switch (mPrivatePlatformData.PlatformType.QncRevision) {
    case QNC_MC_REV_ID_A0:
      StrCat (QncName, L" - A0 stepping");
      break;
    default:
      StrCat (QncName, L" - xx");
  }

  mPrivatePlatformData.PlatformType.QncStringPtr = (UINT64) (UINTN) QncName;
  return;
}

STATIC
VOID
GetIioName (
  VOID
  )
{

  StrCpy (IioName, L"Unknown");

  mPrivatePlatformData.PlatformType.IioStringPtr = (UINT64) (UINTN) IioName;
  return ;
}

STATIC
EFI_STATUS
InstallQuarkSecurityProtocol (
  VOID
  )
{
  EFI_STATUS                                Status;

  //
  // Make sure the Protocol is not already installed
  // in the system.
  //
  ASSERT_PROTOCOL_ALREADY_INSTALLED (NULL, &gQuarkSecurityGuid);

  //
  // Setup protocol structure.
  //
  mPrivateSecurity.Signature = EFI_QUARK_SECURITY_DRIVER_PRIVATE_SIGNATURE;
  mPrivateSecurity.Protocol.AuthenticateImage = QuarkAuthenticateImage;
  mPrivateSecurity.Protocol.AuthenticateKeyModule = QuarkAuthenticateKeyModule;
  mPrivateSecurity.Protocol.CapsuleSecurity = PlatformCapsuleSecurity;
  mPrivateSecurity.Protocol.IsUefiSecureBootProvisioningActive = QuarkIsUefiSecureBootProvisioningActive;
  mPrivateSecurity.Protocol.RequestToLock = QuarkRequestToLock;
  mPrivateSecurity.Protocol.IsUefiSecureBootEnabled = QuarkIsUefiSecureBootEnabled;

  //
  // Install the FvbSecurityProtocol onto a new handle.
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mPrivateSecurity.Handle,
                  &gQuarkSecurityGuid,
                  &mPrivateSecurity.Protocol,
                  NULL
                  );
  return Status;
}

//
// Routines exported by this source module.
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
EFI_STATUS
EFIAPI
QuarkAuthenticateImage (
  IN VOID                                 *ImageBaseAddress,
  IN QuarkSecurityHeader_t                *CallerSignedKeyModule OPTIONAL,
  IN CONST BOOLEAN                        AuthKeyModule,
  IN UINT8                                *KeyBankNumberPtr OPTIONAL
  )
{
  return SecurityAuthenticateImage(
           ImageBaseAddress,
           CallerSignedKeyModule,
           AuthKeyModule,
           KeyBankNumberPtr,
           (QUARK_AUTH_ALLOC_POOL) AllocatePool,
           (QUARK_AUTH_FREE_POOL) FreePool
           );
}

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
EFI_STATUS
EFIAPI
QuarkAuthenticateKeyModule (
  IN QuarkSecurityHeader_t                *SignedKeyModule,
  IN CONST UINT8                          KeyBankNumber,
  IN UINT8                                *CallerMemBuf OPTIONAL,
  IN UINTN                                CallerMemBufSize OPTIONAL
  )
{
  return SecurityAuthenticateKeyModule(
           SignedKeyModule,
           KeyBankNumber,
           CallerMemBuf,
           CallerMemBufSize,
           (QUARK_AUTH_ALLOC_POOL) AllocatePool,
           (QUARK_AUTH_FREE_POOL) FreePool
           );
}

/**
  Install protocols derived from platform hobs.

  @retval EFI_SUCCESS             Function has completed successfully.

**/
EFI_STATUS
EFIAPI
InstallProtocolsFromHobs (
  VOID
  )
{
  EFI_STATUS                      Status;
  EFI_HOB_GUID_TYPE               *GuidHob;
  EFI_PLATFORM_INFO               *PlatformInfoHobData = NULL;
  IIO_UDS                         *UdsHobPtr;
  EFI_GUID                        UniversalDataGuid = IIO_UNIVERSAL_DATA_GUID;

  //
  // Initialize driver private data.
  // Only one instance exists
  //
  ZeroMem (&mPrivatePlatformData, sizeof (mPrivatePlatformData));
  mPrivatePlatformData.Signature            = EFI_PLATFORM_TYPE_DRIVER_PRIVATE_SIGNATURE;

  //
  // Search for the Platform Info PEIM GUID HOB.
  //
  GuidHob       = GetFirstGuidHob (&gEfiPlatformInfoGuid);
  PlatformInfoHobData  = GET_GUID_HOB_DATA (GuidHob);
  ASSERT (PlatformInfoHobData);

  mPrivatePlatformData.PlatformType.Type            = PlatformInfoHobData->Type;
  mPrivatePlatformData.PlatformType.IioSku          = PlatformInfoHobData->IioSku;
  mPrivatePlatformData.PlatformType.IioRevision     = PlatformInfoHobData->IioRevision;
  mPrivatePlatformData.PlatformType.QncSku          = PlatformInfoHobData->QncSku;
  mPrivatePlatformData.PlatformType.QncRevision     = PlatformInfoHobData->QncRevision;
  mPrivatePlatformData.PlatformType.CpuType         = PlatformInfoHobData->CpuType;
  mPrivatePlatformData.PlatformType.CpuStepping     = PlatformInfoHobData->CpuStepping;
  mPrivatePlatformData.PlatformType.FirmwareVersion = PlatformInfoHobData->FirmwareVersion;
  CopyGuid (
    &mPrivatePlatformData.PlatformType.BiosPlatformDataFile,
    &PlatformInfoHobData->BiosPlatformDataFile
    );

  CopyMem (
    &mPrivatePlatformData.PlatformType.PciData,
    &PlatformInfoHobData->PciData,
    sizeof (mPrivatePlatformData.PlatformType.PciData)
    );
  CopyMem (
    &mPrivatePlatformData.PlatformType.CpuData,
    &PlatformInfoHobData->CpuData,
    sizeof (mPrivatePlatformData.PlatformType.CpuData)
    );
  CopyMem (
    &mPrivatePlatformData.PlatformType.MemData,
    &PlatformInfoHobData->MemData,
    sizeof (mPrivatePlatformData.PlatformType.MemData)
    );
  CopyMem (
    &mPrivatePlatformData.PlatformType.SysData,
    &PlatformInfoHobData->SysData,
    sizeof (mPrivatePlatformData.PlatformType.SysData)
    );

  mPrivatePlatformData.PlatformType.TypeStringPtr =
    PlatformTypeString ((EFI_PLATFORM_TYPE) mPrivatePlatformData.PlatformType.Type);

  mPrivatePlatformData.PlatformType.BootingRecoveryDxe =
    PlatformInfoHobData->BootingRecoveryDxe;

  GetQncName();
  GetIioName();

  //
  // Install the PlatformType policy.
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mPrivatePlatformData.Handle,
                  &gEfiPlatformTypeProtocolGuid,
                  &mPrivatePlatformData.PlatformType,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO, "%s platform is detected!\n", mPrivatePlatformData.PlatformType.TypeStringPtr));

  //
  // Time to get the IIO_UDS HOB data stored in the PEI driver
  //
  GuidHob    = GetFirstGuidHob (&UniversalDataGuid);
  UdsHobPtr = GET_GUID_HOB_DATA (GuidHob);
  ASSERT (UdsHobPtr);

  //
  // Allocate Memory Pool for Universal Data Storage so that protocol can expose it
  //
  Status = gBS->AllocatePool ( EfiBootServicesData, sizeof (IIO_UDS), (VOID **) &IioUdsData );
  ASSERT_EFI_ERROR (Status);
  
  //
  // Initialize the Pool Memory with the data from the Hand-Off-Block
  //
  CopyMem(IioUdsData, UdsHobPtr, sizeof(IIO_UDS));

  //
  // Build the IIO_UDS driver instance for protocol publishing  
  //
  ZeroMem (&mIioUdsPrivateData, sizeof (mIioUdsPrivateData));
    
  mIioUdsPrivateData.Signature            = EFI_IIO_UDS_DRIVER_PRIVATE_SIGNATURE;
  mIioUdsPrivateData.IioUds.IioUdsPtr     = IioUdsData;

  //
  // Install the IioUds Protocol.
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mIioUdsPrivateData.Handle,
                  &gEfiIioUdsProtocolGuid,
                  &mIioUdsPrivateData.IioUds,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

/**
  Call EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service.

  Call EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service for a table of
  variables deemed by platform policy to be locked after DXE phase of execution.

  Function will assert if EDKII_VARIABLE_LOCK_PROTOCOL_REQUEST_TO_LOCK service
  returns an error status.

**/
VOID
EFIAPI
QuarkRequestToLock (
  VOID
  )
{
  EFI_STATUS                        Status;
  EDKII_VARIABLE_LOCK_PROTOCOL      *VariableLockProtocol;
  PLATFORM_VARIABLE_TABLE_ENTRY     *Entry;
  UINTN                             Index;

  Status = gBS->LocateProtocol (&gEdkiiVariableLockProtocolGuid, NULL, (VOID **) &VariableLockProtocol);
  ASSERT_EFI_ERROR (Status);

  Entry = mRequestToLockTable;
  for (Index = 0; Index < mRequestToLockTableLen; Index++, Entry++) {
    Status = VariableLockProtocol->RequestToLock (
                                     VariableLockProtocol,
                                     Entry->VariableName,
                                     Entry->VendorGuid
                                     );
    DEBUG ((DEBUG_INFO, "QuarkRequestToLock '%s':'%g'\n", Entry->VariableName, Entry->VendorGuid));
    ASSERT_EFI_ERROR (Status);
  }
}

/**
  Entry point for the driver.

  @param[in]       ImageHandle  Image Handle.
  @param[in]       SystemTable  EFI System Table.

  @retval EFI_SUCCESS             Function has completed successfully.

**/
EFI_STATUS
EFIAPI
PlatformInit (
  IN EFI_HANDLE                         ImageHandle,
  IN EFI_SYSTEM_TABLE                   *SystemTable
  )
{
  EFI_STATUS                      Status;
  EFI_PLATFORM_TYPE_PROTOCOL      *PlatformType;

  //
  // Install data protocols whose contents are derived from Hobs.
  //
  InstallProtocolsFromHobs ();
  PlatformType = &mPrivatePlatformData.PlatformType;

  //
  // Initialize Firmware Volume security.
  // This must be done before any firmware volume accesses.
  //
  Status = DxeInitializeFvSecurity();
  ASSERT_EFI_ERROR (Status);

  //
  // Create events for configuration callbacks.
  //
  Status = CreateConfigEvents ();
  ASSERT_EFI_ERROR (Status);

  //
  // Install Quark Security Protocol.
  //
  Status = InstallQuarkSecurityProtocol ();
  ASSERT_EFI_ERROR (Status);

  //
  // Init Platform LEDs.
  //
  Status = PlatformLedInit ((EFI_PLATFORM_TYPE) PlatformType->Type);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

