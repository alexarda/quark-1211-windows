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

Module Name:

  PlatformSecureLib.c

Abstract:

  Provides a secure platform-specific method to detect physically present user.

--*/

#include <PiDxe.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/Variable.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/QuarkSecurity.h>
#include <Guid/ImageAuthentication.h>

STATIC EFI_BOOT_MODE                      mBootMode;

//
// The critical instance of this library will live in SMM as part of
// VariableAuthSmm.efi. SMM space locked down at the end of PI DXE before
// boot option boot.
// This var will control return of UserPhysicalPresent () if UEFI Secure boot
// is unprovisioned between when gEfiVariableArchProtocolGuid and
// gEfiMonotonicCounterArchProtocolGuid are installed.
// Any calls to UserPhysicalPresent () in this timeframe will result in
// a call to a mQuarkSecurityProtocol to see if auto provisioning is in
// progress, if in progress then UserPhysicalPresent () will return TRUE.
// Note: Auto provisioning happens on a notify event callback for
// gEfiVariableWriteArchProtocolGuid inside the platform dxe driver producing
// mQuarkSecurityProtocol.
// gEfiMonotonicCounterArchProtocolGuid chosen as switch point since it is
// dependant and closely coupled to variable writing.
//
// On firmware update allow key exhanges to happen at anytime before EndOfDxe.
// Quark firmware resets before EndOfDxe on firmware update. 
//
STATIC QUARK_SECURITY_PROTOCOL            *mQuarkSecurityProtocol = NULL;

//
// Routines local to this source module.
//

/**
  Disallow physically present user when gEfiMonotonicCounterArchProtocolGuid signaled.

  This protocol signalled before third party code executed.

  @param[in] Event    Event whose notification function is being invoked.
  @param[in] Context  Pointer to the notification function's context.

**/
STATIC
VOID
EFIAPI
MonotonicCounterArchCallBack (
  IN  EFI_EVENT                           Event,
  IN  VOID                                *Context
  )
{
  EFI_STATUS                        Status;
  VOID                              *ProtocolPointer;

  Status = gBS->LocateProtocol (&gEfiMonotonicCounterArchProtocolGuid, NULL, &ProtocolPointer);
  if (EFI_ERROR (Status)) {
    return;
  }
  DEBUG ((EFI_D_INFO, "NULL mQuarkSecurityProtocol\n"));

  //
  // Force UserPhysicalPresent () to return FALSE from this point on.
  //
  mQuarkSecurityProtocol = NULL;
}

/**
  Callback to decide if QuarkSecurityProtocol needs to be located for provisioning check.

  @param[in] Event    Event whose notification function is being invoked.
  @param[in] Context  Pointer to the notification function's context.

**/
STATIC
VOID
EFIAPI
VariableArchCallBack (
  IN  EFI_EVENT                           Event,
  IN  VOID                                *Context
  )
{
  UINT8                             *SecureBoot;
  BOOLEAN                           SecureBootEnabled;
  VOID                              *Registration;
  EFI_EVENT                         NotifyEvent;
  VOID                              *ProtocolPointer;
  EFI_STATUS                        Status;

  NotifyEvent = NULL;
  Registration = NULL;
  SecureBoot = NULL;
  SecureBootEnabled = FALSE;
  mQuarkSecurityProtocol = NULL;

  Status = gBS->LocateProtocol (&gEfiVariableArchProtocolGuid, NULL, &ProtocolPointer);
  if (EFI_ERROR (Status)) {
    return;
  }

  GetEfiGlobalVariable2 (EFI_SECURE_BOOT_MODE_NAME, (VOID**) &SecureBoot, NULL);
  if (SecureBoot != NULL) {
    SecureBootEnabled = (*SecureBoot == SECURE_BOOT_MODE_ENABLE);
    FreePool (SecureBoot);
  }
  if (SecureBootEnabled) {
    //
    // No need to locate if SecureBoot enabled.
    //
    return;
  }
  DEBUG ((EFI_D_INFO, "Locate QuarkSecurityProtocol\n"));

  //
  // Locate QuarkSecurityProtocol for future checks to see if
  // auto provisioning active.
  //
  Status = gBS->LocateProtocol(
             &gQuarkSecurityGuid,
             NULL,
             (VOID**) &mQuarkSecurityProtocol
             );
  ASSERT_EFI_ERROR (Status);
  ASSERT (mQuarkSecurityProtocol != NULL);

  //
  // Provisoning happen when variable write install is notified and will
  // be over when MonotonicCounterArch install is notified.
  // Set up callback to NULL mQuarkSecurityProtocol when MonotonicCounterArch
  // installed so that physically present user always returns FALSE from this
  // point on.
  //
  NotifyEvent = EfiCreateProtocolNotifyEvent (
                  &gEfiMonotonicCounterArchProtocolGuid,
                  TPL_CALLBACK,
                  MonotonicCounterArchCallBack,
                  NULL,
                  &Registration
                  );
  ASSERT (NotifyEvent != NULL);
}

//
// Routines exported by this component.
//

/**

  This function provides a platform-specific method to detect whether the platform
  is operating by a physically present user.

  Programmatic changing of platform security policy (such as disable Secure Boot,
  or switch between Standard/Custom Secure Boot mode) MUST NOT be possible during
  Boot Services or after exiting EFI Boot Services. Only a physically present user
  is allowed to perform these operations.

  NOTE THAT: This function cannot depend on any EFI Variable Service since they are
  not available when this function is called in AuthenticateVariable driver.

  For Quark we only return TRUE if auto provisioning is active early in PI-DXE.

  @retval  TRUE       The platform is operated by a physically present user.
  @retval  FALSE      The platform is NOT operated by a physically present user.

**/
BOOLEAN
EFIAPI
UserPhysicalPresent (
  VOID
  )
{
  BOOLEAN                           UefiSecureProvisioningActive;

  UefiSecureProvisioningActive = FALSE;
  if (mQuarkSecurityProtocol != NULL) {
    ASSERT (mQuarkSecurityProtocol->IsUefiSecureBootProvisioningActive != NULL);
    UefiSecureProvisioningActive = mQuarkSecurityProtocol->IsUefiSecureBootProvisioningActive ();
  }
  DEBUG ((EFI_D_INFO, "UefiSecureProvisioningActive = %d\n", (UINTN) UefiSecureProvisioningActive));
  return UefiSecureProvisioningActive;
}

/**
  Start protocol callback chain to allow physically present user.

  Physically present user allowed if UEFI Secure boot disabled
  before ExitPmAuthCallBack signalled. ExitPmAuthCallBack signalled
  before any 3rd party code external to flash can run.

  For Quark we disable physically present user early in PI-DXE when
  gEfiMonotonicCounterArchProtocolGuid signalled.

  @param  ImageHandle   ImageHandle of the loaded driver.
  @param  SystemTable   Pointer to the EFI System Table.

  @retval EFI_SUCCESS   The handlers were registered successfully.
**/
EFI_STATUS
EFIAPI
QuarkPlatformSecureLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                        Status;
  EFI_EVENT                         NotifyEvent;
  VOID                              *Registration;

  mQuarkSecurityProtocol = NULL;

  mBootMode = GetBootModeHob ();
  NotifyEvent = NULL;
  Registration = NULL;

  //
  // If flash update we will always allow custom mode and checking if
  // provisioning active.
  //
  if (mBootMode == BOOT_ON_FLASH_UPDATE) {
    Status = gBS->LocateProtocol(
               &gQuarkSecurityGuid,
               NULL,
               (VOID**) &mQuarkSecurityProtocol
               );
    ASSERT_EFI_ERROR (Status);
  } else {
    //
    // Register callback function upon gEfiVariableArchProtocolGuid.
    //
    NotifyEvent = EfiCreateProtocolNotifyEvent (
                    &gEfiVariableArchProtocolGuid,
                    TPL_CALLBACK,
                    VariableArchCallBack,
                    NULL,
                    &Registration
                    );
    ASSERT (NotifyEvent != NULL);
  }
  return EFI_SUCCESS;
}
