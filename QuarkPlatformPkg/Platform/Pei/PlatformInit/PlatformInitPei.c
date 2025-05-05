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

Module Name:
  PlatformInitPei.c

Abstract:
  Implements PlatformInitPei driver entry and initial Notify Callbacks.

--*/

#include "CommonHeader.h"
#include "PlatformEarlyInit.h"

/**
  Callback to call PlatformMainInit when capsule ppi installed.

  @param[in] PeiServices       An indirect pointer to the EFI_PEI_SERVICES table published by the PEI Foundation.
  @param[in] NotifyDescriptor  Address of the notification descriptor data structure.
  @param[in] Ppi               Address of the PPI that was installed.

  @retval EFI_SUCCESS          Callback success.
  @return Others               Unexpected error.

**/
EFI_STATUS
EFIAPI
CapsulePpiCallback (
  IN EFI_PEI_SERVICES              **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR     *NotifyDescriptor,
  IN VOID                          *Ppi
  );

//
// Global variables.
//

EFI_PEI_NOTIFY_DESCRIPTOR           mPlatformInitPeiNotifyList[] = {
  {
    (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
    &gPeiCapsulePpiGuid,
    CapsulePpiCallback
  }
};

//
// Private routines to this source module.
//

STATIC
BOOLEAN
IsCapsulePpiInstalled (
  VOID
  )
{
  EFI_STATUS                       Status;
  PEI_CAPSULE_PPI                  *Capsule;

  //
  // Check if we have capsule services.
  //
  Status = PeiServicesLocatePpi (
              &gPeiCapsulePpiGuid,
              0,
              NULL,
              (VOID **) &Capsule
              );

  return (Status == EFI_SUCCESS);
}


/**
  Callback to call PlatformMainInit when capsule services installed.

  @param[in] PeiServices       An indirect pointer to the EFI_PEI_SERVICES table published by the PEI Foundation.
  @param[in] NotifyDescriptor  Address of the notification descriptor data structure.
  @param[in] Ppi               Address of the PPI that was installed.

  @return ASSERT if PPI not installed else return PlatformMainInit result.

**/
EFI_STATUS
EFIAPI
CapsulePpiCallback (
  IN EFI_PEI_SERVICES              **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR     *NotifyDescriptor,
  IN VOID                          *Ppi
  )
{

  //
  // Assert if Capule ppi not installed.
  //
  ASSERT (IsCapsulePpiInstalled() == TRUE);

  //
  // return by Calling PlatformMainInit.
  // Note never shadowed in memory if running in this callback.
  //

  return PlatformMainInit ((CONST EFI_PEI_SERVICES **) PeiServices, FALSE);
}

/** PlatformInitPei driver entry point.

  @param[in]       FfsHeader    Pointer to Firmware File System file header.
  @param[in]       PeiServices  General purpose services available to every PEIM.

  @retval EFI_SUCCESS           Driver Entry Point success.
*/
EFI_STATUS
EFIAPI
PeiInitPlatform (
  IN       EFI_PEI_FILE_HANDLE            FileHandle,
  IN CONST EFI_PEI_SERVICES               **PeiServices
  )
{
  EFI_STATUS                        Status;
  EFI_FV_FILE_INFO                  FileInfo;
  BOOLEAN                           InMemory;
  BOOLEAN                           CapsulePpiInstalled;
  BOOLEAN                           RecoveryStage1;

  RecoveryStage1 = PlatformIsBootWithRecoveryStage1 ();
  CapsulePpiInstalled = IsCapsulePpiInstalled ();
  InMemory = FALSE;  // Assume not in memory.

  //
  // Get file info to determine if running shadowed memory instance.
  //
  Status = PeiServicesFfsGetFileInfo (FileHandle, &FileInfo);
  ASSERT_EFI_ERROR (Status);

  //
  // The follow conditional check only works for memory-mapped FFS,
  // so we ASSERT that the file is really a MM FFS.
  //
  ASSERT (FileInfo.Buffer != NULL);
  if (!(((UINTN) FileInfo.Buffer <= (UINTN) PeiInitPlatform) &&  
        ((UINTN) PeiInitPlatform <= (UINTN) FileInfo.Buffer + FileInfo.BufferSize))) {
    InMemory = TRUE;
  }

  if (!InMemory) {

    //
    // Do early platform config tasks if not in memory.
    //
    EarlyPlatformConfig (PeiServices);

    //
    // Do early boot mode check if is in recovery.
    //
    EarlyUpdateBootMode (PeiServices);

    //
    // Build PlatformInfoHob if not in memory.
    //
    BuildPlatformInfoHob (PeiServices);

    //
    // If not in memory register for shadow if recovery stage1 executing.
    //
    if (RecoveryStage1) {
      PeiServicesRegisterForShadow (FileHandle);
    }
  }

  //
  // Only can call main init now if capsule services installed
  // or recovery stage1 running.
  //
  if (!CapsulePpiInstalled && !RecoveryStage1) {

    //
    // Capsule Ppi should be installed if shadowed inst running!
    //
    ASSERT (InMemory == FALSE);

    //
    // Schedule callback to be called when ppi installed.
    //

    Status = PeiServicesNotifyPpi (&mPlatformInitPeiNotifyList[0]);
    ASSERT_EFI_ERROR (Status);

    //
    // The callback will call PlatformMainInit so we can return.
    //
    return Status;
  }

  //
  // Call main platform init.
  //
  Status = PlatformMainInit (PeiServices, InMemory);

  return Status;
}
