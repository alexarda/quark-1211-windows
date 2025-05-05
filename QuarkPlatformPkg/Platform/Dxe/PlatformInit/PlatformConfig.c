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

  PlatformConfig.c

Abstract:

    Essential platform configuration.

Revision History

--*/

#include "PlatformInitDxe.h"

//
// The protocols, PPI and GUID defintions for this module
//

//
// The Library classes this module consumes
//

#define SMM_DEFAULT_SMBASE                  0x30000     // Default SMBASE address
#define SMM_DEFAULT_SMBASE_SIZE_BYTES       0x10000     // Size in bytes of default SMRAM

BOOLEAN                       mMemCfgDone = FALSE;
UINT8                         ChipsetDefaultMac [6] = {0xff,0xff,0xff,0xff,0xff,0xff};

static
VOID
ValidateImrPolicySettings ()
{
  UINT8                 Index;
  EFI_PLATFORM_INFO     *PlatformInfoHobData;
  EFI_HOB_GUID_TYPE     *GuidHob;

  //
  // Search for the Platform Info PEIM GUID HOB.
  //
  GuidHob       = GetFirstGuidHob (&gEfiPlatformInfoGuid);
  PlatformInfoHobData  = GET_GUID_HOB_DATA (GuidHob);
  ASSERT (PlatformInfoHobData);

  for (Index = 0; Index < QUARK_NC_TOTAL_IMR_SET; Index++)
  {
      if ((PlatformInfoHobData->ImrData[Index].RegImrXL != QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID,  \
                                                                        QUARK_NC_MEMORY_MANAGER_IMR0 + (Index*4) + \
                                                                        QUARK_NC_MEMORY_MANAGER_IMRXL)) ||   \
          (PlatformInfoHobData->ImrData[Index].RegImrXH != QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID,  \
                                                                        QUARK_NC_MEMORY_MANAGER_IMR0 + (Index*4) + \
                                                                        QUARK_NC_MEMORY_MANAGER_IMRXH)) ||   \
          (PlatformInfoHobData->ImrData[Index].RegImrXRM != QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, \
                                                                        QUARK_NC_MEMORY_MANAGER_IMR0 + (Index*4) + \
                                                                        QUARK_NC_MEMORY_MANAGER_IMRXRM)) ||  \
          (PlatformInfoHobData->ImrData[Index].RegImrXWM != QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, \
                                                                        QUARK_NC_MEMORY_MANAGER_IMR0 + (Index*4) + \
                                                                        QUARK_NC_MEMORY_MANAGER_IMRXWM)))
          ASSERT_EFI_ERROR (EFI_SECURITY_VIOLATION);
  }
}

EFI_STATUS
EFIAPI
VerifyQncSmramValues (
  IN  CONST EFI_PHYSICAL_ADDRESS          HwProgrammedSmramBase,
  IN  CONST UINT64                        HwProgrammedSmramLen
  )
/*++


Routine Description:

  Verify SMM Ranges read from HW registers during DXE are valid.

  Verify values read from HW against values retured from SMM Access protocol.
  SMM Access protocol uses HOBs built by PEI to publish CPU SMM ranges info.

Arguments:

  HwProgrammedSmramBase     SmmRange Base address read from hardware.
  HwProgrammedSmramLen      SmmRange length read from hardware.

Returns:

  EFI_SUCCESS           SMM Range is valid.
  EFI_DEVICE_ERROR      Hardware programmed values do not match published.

--*/
{
  EFI_STATUS                        Status;
  EFI_SMM_ACCESS2_PROTOCOL          *SmmAccess;
  UINTN                             Size;
  EFI_SMRAM_DESCRIPTOR              *SmramRanges;
  UINTN                             SmramRangeCount;

  //
  // Get SMRAM information from SmmAccess that will be used by core modules.
  // SmramRanges table built from HOB received from stage1 PEI image.
  //
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  ASSERT_EFI_ERROR (Status);
  Size = 0;
  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, NULL);
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);
  SmramRanges = (EFI_SMRAM_DESCRIPTOR *) AllocatePool (Size);
  ASSERT (SmramRanges != NULL);
  Status = SmmAccess->GetCapabilities (SmmAccess, &Size, SmramRanges);
  ASSERT_EFI_ERROR (Status);
  SmramRangeCount = Size / sizeof (EFI_SMRAM_DESCRIPTOR);

  //
  // Check that only one Smram range since thats all Quark supports.
  // Check HW programmed length against build time fixed pcd length.
  // Check HW programmed base against published base address.
  // Check HW programmed length against published length.
  //
  if ((SmramRangeCount == 1) &&
      (HwProgrammedSmramLen == ((UINT64) FixedPcdGet32 (PcdTSegSize))) &&
      (HwProgrammedSmramBase == SmramRanges[0].CpuStart) &&
      (HwProgrammedSmramLen == SmramRanges[0].PhysicalSize)) {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_DEVICE_ERROR;
  }

  FreePool ((VOID *) SmramRanges);
  return Status;
}

VOID
EFIAPI
PlatformConfigOnSmmConfigurationProtocol (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
/*++

Routine Description:

  Function runs in PI-DXE to perform platform specific config when
  SmmConfigurationProtocol is installed.

Arguments:
  Event       - The event that occured.
  Context     - For EFI compatiblity.  Not used.

Returns:
  None.
--*/

{
  EFI_STATUS            Status;
  UINT32                NewValue;
  UINT64                BaseAddress;
  UINT64                SmramLength;
  EFI_CPU_ARCH_PROTOCOL *CpuArchProtocol;
  VOID                  *SmmCfgProt;

  Status = gBS->LocateProtocol (&gEfiSmmConfigurationProtocolGuid, NULL, &SmmCfgProt);
  if (Status != EFI_SUCCESS){
    DEBUG ((DEBUG_INFO, "gEfiSmmConfigurationProtocolGuid triggered but not valid.\n"));
    return;
  }
  if (mMemCfgDone) {
    DEBUG ((DEBUG_INFO, "Platform DXE Mem config already done.\n"));
    return;
  }

  //
  // Disable eSram block (this will also clear/zero eSRAM)
  // We only use eSRAM in the PEI phase. Disable now that we are in the DXE phase
  //
  NewValue = QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_ESRAMPGCTRL_BLOCK);
  NewValue |= BLOCK_DISABLE_PG;
  QNCPortWrite (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_ESRAMPGCTRL_BLOCK, NewValue);

  //
  // Update HMBOUND to top of DDR3 memory and LOCK
  // We disabled eSRAM so now we move HMBOUND down to top of DDR3
  //
  QNCGetTSEGMemoryRange (&BaseAddress, &SmramLength);
  
  //
  // Verify programmed SMRAM values against published values and pcd values
  // before use for locking HMBOUND.
  //
  Status = VerifyQncSmramValues ((EFI_PHYSICAL_ADDRESS) BaseAddress, SmramLength);
  ASSERT_EFI_ERROR (Status);

  NewValue = (UINT32)(BaseAddress + SmramLength);
  DEBUG ((EFI_D_INFO,"Locking HMBOUND at: = 0x%8x\n",NewValue));
  QNCPortWrite (QUARK_NC_HOST_BRIDGE_SB_PORT_ID, QUARK_NC_HOST_BRIDGE_HMBOUND_REG, (NewValue | HMBOUND_LOCK));

  if (QuarkCheckSecureLockBoot()) {

    //
    // Validate if current IMR setting matched policy settings
    //
    ValidateImrPolicySettings ();

    //
    // Lock IMR5 now that HMBOUND is locked (legacy S3 region)
    //
    NewValue = QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_IMR5+QUARK_NC_MEMORY_MANAGER_IMRXL);
    NewValue |= IMR_LOCK;
    QNCPortWrite (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_IMR5+QUARK_NC_MEMORY_MANAGER_IMRXL, NewValue);

    //
    // Lock IMR6 now that HMBOUND is locked (ACPI Reclaim/ACPI/Runtime services/Reserved)
    //
    NewValue = QNCPortRead (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_IMR6+QUARK_NC_MEMORY_MANAGER_IMRXL);
    NewValue |= IMR_LOCK;
    QNCPortWrite (QUARK_NC_MEMORY_MANAGER_SB_PORT_ID, QUARK_NC_MEMORY_MANAGER_IMR6+QUARK_NC_MEMORY_MANAGER_IMRXL, NewValue);

    //
    // Disable IMR2 memory protection (RMU Main Binary)
    //
    QncImrWrite (
              QUARK_NC_MEMORY_MANAGER_IMR2,
              (UINT32)(IMRL_RESET & ~IMR_EN),
              (UINT32)IMRH_RESET,
              (UINT32)IMRX_ALL_ACCESS,
              (UINT32)IMRX_ALL_ACCESS
          );

    //
    // Disable IMR3 memory protection (Default SMRAM)
    //
    QncImrWrite (
              QUARK_NC_MEMORY_MANAGER_IMR3,
              (UINT32)(IMRL_RESET & ~IMR_EN),
              (UINT32)IMRH_RESET,
              (UINT32)IMRX_ALL_ACCESS,
              (UINT32)IMRX_ALL_ACCESS
          );

    //
    // Disable IMR4 memory protection (eSRAM).
    //
    QncImrWrite (
              QUARK_NC_MEMORY_MANAGER_IMR4,
              (UINT32)(IMRL_RESET & ~IMR_EN),
              (UINT32)IMRH_RESET,
              (UINT32)IMRX_ALL_ACCESS,
              (UINT32)IMRX_ALL_ACCESS
          );
  }

  //
  // Default SMRAM UnCachable until SMBASE relocated.
  // SMRAM has now been relocated so we can make default area Cachable for
  // next user of area.
  //
  Status = gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **) &CpuArchProtocol);
  ASSERT_EFI_ERROR (Status);

  CpuArchProtocol->SetMemoryAttributes (
                     CpuArchProtocol,
                     (EFI_PHYSICAL_ADDRESS) SMM_DEFAULT_SMBASE,
                     SMM_DEFAULT_SMBASE_SIZE_BYTES,
                     EFI_MEMORY_WB
                     );

  mMemCfgDone = TRUE;
}

VOID
EFIAPI
PlatformConfigOnSpiReady (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
/*++

Routine Description:

  Function runs in PI-DXE to perform platform specific config when SPI
  interface is ready.

Arguments:
  Event       - The event that occured.
  Context     - For EFI compatiblity.  Not used.

Returns:
  None.

--*/
{
  EFI_STATUS                        Status;
  VOID                              *SpiReadyProt = NULL;
  EFI_PLATFORM_TYPE_PROTOCOL        *PlatformType;
  EFI_BOOT_MODE                      BootMode;

  BootMode = GetBootModeHob ();

  PlatformType = &mPrivatePlatformData.PlatformType;

  Status = gBS->LocateProtocol (&gEfiSmmSpiReadyProtocolGuid, NULL, &SpiReadyProt);
  if (Status != EFI_SUCCESS){
    DEBUG ((DEBUG_INFO, "gEfiSmmSpiReadyProtocolGuid triggered but not valid.\n"));
    return;
  }

  //
  // Lock regions SPI flash.
  //
  PlatformFlashLockPolicy (FALSE);
}

VOID
EFIAPI
PlatformConfigOnVariableWrite (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
/*++

Routine Description:

  Function runs in PI-DXE to perform platform specific config when
  Variable Write service ready.

Arguments:
  Event       - The event that occured.
  Context     - For EFI compatiblity.  Not used.

Returns:
  None.

--*/
{
  EFI_STATUS                        Status;
  VOID                              *ProtocolPointer;
  EFI_PLATFORM_TYPE_PROTOCOL        *PlatformType;

  PlatformType = &mPrivatePlatformData.PlatformType;

  Status = gBS->LocateProtocol (&gEfiVariableWriteArchProtocolGuid, NULL, &ProtocolPointer);
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Auto provision secure boot resources.
  //
  QuarkAutoProvisionSecureBoot (NULL);  // NULL to use Pdat in flash.

  //
  // Lock regions SPI flash.
  //
  PlatformFlashLockPolicy (FALSE);

}

VOID
EFIAPI
PlatformConfigUpdateTPM (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
/**
  Ready to Boot Event notification handler.

  Updating ACPI table to notify OS if TPM is present and acquire I2c
  resources accordingly.

  @param[in]  Event     Event whose notification function is being invoked
  @param[in]  Context   Pointer to the notification function's context

**/
{
  EFI_STATUS                        Status;
  EFI_TCG_PROTOCOL                  *TcgProtocol;
  EFI_GLOBAL_NVS_AREA_PROTOCOL      *GlobalNvsAreaProtocol;
  EFI_GLOBAL_NVS_AREA               *GlobalNvsAreaPtr = NULL;

  Status = EFI_SUCCESS;
  //
  // Get Global NVS Area Protocol
  //
  Status = gBS->LocateProtocol (&gEfiGlobalNvsAreaProtocolGuid, NULL, (VOID **)&GlobalNvsAreaProtocol);
  ASSERT_EFI_ERROR (Status);

  GlobalNvsAreaPtr = GlobalNvsAreaProtocol->Area;

  Status = gBS->LocateProtocol (&gEfiTcgProtocolGuid, NULL, (VOID **)&TcgProtocol);
  if (Status != EFI_SUCCESS){
    GlobalNvsAreaPtr->TpmPresent = FALSE;
    return;
  }
  GlobalNvsAreaPtr->TpmPresent = TRUE;
}


EFI_STATUS
EFIAPI
CreateConfigEvents (
  VOID
  )
/*++

Routine Description:

Arguments:
  None

Returns:
  EFI_STATUS

--*/
{
  EFI_EVENT   Event;          // We don't use value returned here, so we can overwrite.
  VOID        *Registration;  // We don't use pointer returned here, so we can overwrite.
  EFI_BOOT_MODE  BootMode;
  EFI_STATUS   Status;

  Status = EFI_SUCCESS;
  BootMode = GetBootModeHob ();

  //
  // Schedule callback for when SmmConfigurationProtocol installed.
  //
  Event = EfiCreateProtocolNotifyEvent (
                  &gEfiSmmConfigurationProtocolGuid,
                  TPL_CALLBACK,
                  PlatformConfigOnSmmConfigurationProtocol,
                  NULL,
                  &Registration
                  );
  ASSERT (Event != NULL);

  //
  // Update ACPI table if TPM is present when ready to boot.
  //
  Status = EfiCreateEventReadyToBootEx (
            TPL_CALLBACK,
            PlatformConfigUpdateTPM,
            NULL,
            &Event
            );
  ASSERT_EFI_ERROR (Status);

  if (BootMode != BOOT_ON_FLASH_UPDATE && BootMode != BOOT_IN_RECOVERY_MODE) {
    //
    // Do full config on normal boot when variable write service is installed.
    // Provision secure boot and setup SPI Flash Policy.
    //
    Event = EfiCreateProtocolNotifyEvent (
              &gEfiVariableWriteArchProtocolGuid,
              TPL_CALLBACK,
              PlatformConfigOnVariableWrite,
              NULL,
              &Registration
              );
    ASSERT (Event != NULL);
  } else {
    //
    // On Flash update or recovery just setup SPI Flash Policy when
    // SPI interface ready.
    //
    Event = EfiCreateProtocolNotifyEvent (
              &gEfiSmmSpiReadyProtocolGuid,
              TPL_CALLBACK,
              PlatformConfigOnSpiReady,
              NULL,
              &Registration
              );
    ASSERT (Event != NULL);
  }

  return EFI_SUCCESS;
}
