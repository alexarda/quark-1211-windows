/** @file

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

Abstract:
  Capsule Library instance to update capsule image to flash.

**/
#include <PiDxe.h>

#include <Guid/QuarkCapsuleGuid.h>
#include <Protocol/QuarkSecurity.h>
#include <Library/IoLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CapsuleLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/QNCAccessLib.h>

extern  VOID SendCapsuleSmi(UINTN Addr);
extern  VOID GetUpdateStatusSmi(UINTN Addr);

/**
  Those capsules supported by the firmwares.

  @param  CapsuleHeader    Points to a capsule header.

  @retval EFI_SUCESS       Input capsule is supported by firmware.
  @retval EFI_UNSUPPORTED  Input capsule is not supported by the firmware.
**/
EFI_STATUS
EFIAPI
SupportCapsuleImage (
  IN EFI_CAPSULE_HEADER *CapsuleHeader
  )
{
  if (CompareGuid (&gEfiQuarkCapsuleGuid, &CapsuleHeader->CapsuleGuid)) {
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

/**
  The firmware implements to process the capsule image.

  @param  CallerCapsuleHeader   Points to a callers capsule header.
  
  @retval EFI_SUCCESS           Process Capsule Image successfully. 
  @retval EFI_UNSUPPORTED       Capsule image is not supported by the firmware.
  @retval EFI_VOLUME_CORRUPTED  FV volume in the capsule is corrupted.
  @retval EFI_OUT_OF_RESOURCES  Not enough memory.
  @retval EFI_INVALID_PARAMETER Internal capsule data invalid.
  @retval EFI_BUFFER_TOO_SMALL  Capsule embedded image smaller then expected.

**/
EFI_STATUS
EFIAPI
ProcessCapsuleImage (
  IN EFI_CAPSULE_HEADER *CallerCapsuleHeader
  )
{
  CAPSULE_INFO_PACKET                     *CapsuleInfoPacketPtr;
  CAPSULE_FRAGMENT                        *CapsuleFragmentPtr;
  UPDATE_STATUS_PACKET                    *UpdateStatusPacketPtr;
  EFI_STATUS                              Status;
  UINT32                                  NewSvnArray[QUARK_SVN_ARRAY_SIZE];
  UINT8                                   *SignedCapsule;
  EFI_CAPSULE_HEADER                      *CapsuleHeader;
  UINT16                                  WdtBaseAddress;
  STATIC UINT8                            WdtConfigRegister; 
  UINT8                                   WdtResetEnabled;
  UINT8                                   WdtLockEnabled; 
  QUARK_SECURITY_PROTOCOL                 *QuarkSecurityProtocol;

  if (SupportCapsuleImage (CallerCapsuleHeader) != EFI_SUCCESS) {
    return EFI_UNSUPPORTED;
  }

  //
  // Locate quark security protocol.
  //
  Status = gBS->LocateProtocol(
             &gQuarkSecurityGuid,
             NULL,
             (VOID**) &QuarkSecurityProtocol
             );
  ASSERT_EFI_ERROR (Status);
  ASSERT (QuarkSecurityProtocol != NULL);
  ASSERT (QuarkSecurityProtocol->CapsuleSecurity != NULL);

  CapsuleFragmentPtr    = (CAPSULE_FRAGMENT *) AllocateZeroPool (sizeof (CAPSULE_FRAGMENT));
  CapsuleInfoPacketPtr  = (CAPSULE_INFO_PACKET *) AllocateZeroPool (sizeof (CAPSULE_INFO_PACKET));
  UpdateStatusPacketPtr = (UPDATE_STATUS_PACKET *) AllocateZeroPool (sizeof (UPDATE_STATUS_PACKET));

  ASSERT (CapsuleFragmentPtr != NULL);
  ASSERT (CapsuleInfoPacketPtr != NULL);
  ASSERT (UpdateStatusPacketPtr != NULL);

  SignedCapsule = (UINT8 *) CallerCapsuleHeader;
  Status = QuarkSecurityProtocol->CapsuleSecurity (
                                    &SignedCapsule,
                                    &CapsuleInfoPacketPtr->NewMfhSourceOffset,
                                    NewSvnArray,
                                    &CapsuleInfoPacketPtr->SvnAreaUpdPoint,
                                    &CapsuleInfoPacketPtr->SvnAreaUpdTrigAddr,
                                    &CapsuleInfoPacketPtr->NvramUpdatable
                                    );
  DEBUG ((EFI_D_INFO, "CapsuleSecurity result %r\n", Status));
  if (!EFI_ERROR (Status)) {
    CapsuleHeader = (EFI_CAPSULE_HEADER *) &SignedCapsule [PcdGet32 (PcdFvSecurityHeaderSize)];

    //
    // Prepare structures to store capsule image.
    //

    CapsuleFragmentPtr->Address      = (UINTN) CapsuleHeader;
    CapsuleFragmentPtr->BufferOffset = 0;
    CapsuleFragmentPtr->Size         = CapsuleHeader->CapsuleImageSize;
    CapsuleFragmentPtr->Flags        = BIT0;

    CapsuleInfoPacketPtr->CapsuleLocation = (UINTN) CapsuleFragmentPtr;
    CapsuleInfoPacketPtr->CapsuleSize     = CapsuleHeader->CapsuleImageSize;
    CapsuleInfoPacketPtr->Status          = EFI_SUCCESS;
    if (CapsuleInfoPacketPtr->SvnAreaUpdPoint != SvnUpdNever) {
      CapsuleInfoPacketPtr->SvnAreaLocation = (UINTN) &NewSvnArray[0];
    }

    DEBUG ((EFI_D_INFO, "CapsuleImage Address is %10p, CapsuleImage Size is %8x\n", CapsuleHeader, CapsuleHeader->CapsuleImageSize));
    DEBUG ((EFI_D_INFO, "CapsuleFragment Address is %10p, CapsuleInfo Address is %10p\n", CapsuleFragmentPtr, CapsuleInfoPacketPtr));
    DEBUG (
      (EFI_D_INFO, "Capsule SvnUpdPoint %d, SvnAreaUpdTrigAddr %8x, NewMfhSourceOffset %8x\n",
      CapsuleInfoPacketPtr->SvnAreaUpdPoint,
      CapsuleInfoPacketPtr->SvnAreaUpdTrigAddr,
      CapsuleInfoPacketPtr->NewMfhSourceOffset
      ));
    DEBUG (
      (EFI_D_INFO, "Capsule NvramUpdatable %s\n",
      CapsuleInfoPacketPtr->NvramUpdatable ? L"YES" : L"NO"
      ));

    Print (L"Start to update capsule image!\n");

    //
    // Check if WDT reset and lock are enabled
    //
    WdtBaseAddress = (LpcPciCfg16(R_QNC_LPC_WDTBA));
    WdtConfigRegister = IoRead8((WdtBaseAddress + R_QNC_LPC_WDT_WDTCR));
    WdtResetEnabled = WdtConfigRegister & BIT4;
    WdtLockEnabled = IoRead8((WdtBaseAddress + R_QNC_LPC_WDT_WDTLR)) & BIT0;
    ASSERT ((WdtLockEnabled == 0 && WdtResetEnabled == 0));

    //
    // Explicitly clear WDT Reset Enable
    //
    IoWrite8((WdtBaseAddress + R_QNC_LPC_WDT_WDTCR), (WdtConfigRegister & ~BIT4));

    //
    // Trig SMI to update Capsule image.
    //
    SendCapsuleSmi((UINTN)CapsuleInfoPacketPtr);

    UpdateStatusPacketPtr->BlocksCompleted = 0;
    UpdateStatusPacketPtr->TotalBlocks = (UINTN) -1;
    UpdateStatusPacketPtr->Status = EFI_SUCCESS;

    do {
      //
      // Trig SMI to get the status to updating capsule image.
      //
      gBS->Stall (200000);
      GetUpdateStatusSmi((UINTN)UpdateStatusPacketPtr);

      if (UpdateStatusPacketPtr->TotalBlocks != (UINTN) -1) {
        Print (L"Updated Blocks completed: %d of %d\n", UpdateStatusPacketPtr->BlocksCompleted, UpdateStatusPacketPtr->TotalBlocks);
      }
    } while ((UpdateStatusPacketPtr->Status == EFI_SUCCESS) && (UpdateStatusPacketPtr->BlocksCompleted < UpdateStatusPacketPtr->TotalBlocks));

    //
    // Restore Previous WDT Reset Enable setting
    //
    IoWrite8((WdtBaseAddress + R_QNC_LPC_WDT_WDTCR), (WdtConfigRegister));

    Status = UpdateStatusPacketPtr->Status;

    //
    // Free memory allocated by QuarkSecurityProtocol->CapsuleSecurity.
    //
    FreePool (SignedCapsule);
  }

  FreePool (CapsuleFragmentPtr);
  FreePool (CapsuleInfoPacketPtr);
  FreePool (UpdateStatusPacketPtr);

  if (EFI_ERROR (Status)) {
    Print (L"Invalid capsule format. Please furnish a valid capsule. Return status is %r!\n", Status);
  } else {
    Print (L"Capsule image is updated done!\n");
  }
  return Status;
}

