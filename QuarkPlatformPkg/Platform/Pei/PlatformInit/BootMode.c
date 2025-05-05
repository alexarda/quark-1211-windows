/** @file
  This file provide the function to detect boot mode
  
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


#include "CommonHeader.h"
#include <Pi/PiFirmwareVolume.h>

EFI_PEI_PPI_DESCRIPTOR mPpiListRecoveryBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiBootInRecoveryModePpiGuid,
  NULL
};

EFI_PEI_PPI_DESCRIPTOR mPpiListSStateBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gPeiSStateBootModePpiGuid,
  NULL
};

/**
  Check for undected / uncleared / unsupported wake of system.

  @retval TRUE  undected / uncleared / unsupported system wake.
  @retval FALSE can't determine.

**/
STATIC
BOOLEAN
IsUndectedUnclearedWake (
  IN CONST EFI_PEI_SERVICES               **PeiServices
  )
{
  UINT16                            Pm1Cnt;

  Pm1Cnt = IoRead16 (
             PcdGet16 (PcdPm1blkIoBaseAddress) + R_QNC_PM1BLK_PM1C
             );

  return ((Pm1Cnt & B_QNC_PM1BLK_PM1C_SLPTP) == V_S3);
}

/**
  If the box was opened, it's boot with full config.
  If the box is closed, then
    1. If it's first time to boot, it's boot with full config.
    2. If the ChassisIntrution is selected, force to be a boot with full config
    3. Otherwise it's boot with no change.

  @param  PeiServices General purpose services available to every PEIM.

  @retval TRUE  If it's boot with no change.
  @retval FALSE If boot with no change.
**/
STATIC
BOOLEAN
IsBootWithNoChange (
  IN EFI_PEI_SERVICES   **PeiServices
  )
{
  BOOLEAN IsFirstBoot = FALSE;
  
  BOOLEAN EnableFastBoot = FALSE;
  IsFirstBoot = PcdGetBool(PcdBootState);
  EnableFastBoot = PcdGetBool (PcdEnableFastBoot);

  DEBUG ((EFI_D_INFO, "IsFirstBoot = %x , EnableFastBoot= %x. \n", IsFirstBoot, EnableFastBoot));

  if ((!IsFirstBoot) && EnableFastBoot) {
    return TRUE;
  } else {
    return FALSE;
  }
}


/**

Routine Description:

  This function is used to verify if the FV header is validate.

  @param  FwVolHeader - The FV header that to be verified.

  @retval EFI_SUCCESS   - The Fv header is valid.
  @retval EFI_NOT_FOUND - The Fv header is invalid.
  
**/
EFI_STATUS
ValidateFvHeader (
  EFI_BOOT_MODE      *BootMode
  )
{
  UINT16  *Ptr;
  UINT16  HeaderLength;
  UINT16  Checksum;

  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader;

  if (BOOT_IN_RECOVERY_MODE == *BootMode) {
    return EFI_SUCCESS;
  }
  //
  // Let's check whether FvMain header is valid, if not enter into recovery mode
  //  
  //
  // Verify the header revision, header signature, length
  // Length of FvBlock cannot be 2**64-1
  // HeaderLength cannot be an odd number
  //
  FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)PcdGet32(PcdFlashFvMainBase);
  if ((FwVolHeader->Revision != EFI_FVH_REVISION)||
      (FwVolHeader->Signature != EFI_FVH_SIGNATURE) ||
      (FwVolHeader->FvLength == ((UINT64) -1)) ||
      ((FwVolHeader->HeaderLength & 0x01) != 0)
      ) {
    return EFI_NOT_FOUND;
  }
  //
  // Verify the header checksum
  //
  HeaderLength  = (UINT16) (FwVolHeader->HeaderLength / 2);
  Ptr           = (UINT16 *) FwVolHeader;
  Checksum      = 0;
  while (HeaderLength > 0) {
    Checksum = Checksum +*Ptr;
    Ptr++;
    HeaderLength--;
  }

  if (Checksum != 0) {
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

/**

  Check whether go to recovery path
  @retval TRUE  Go to recovery path
  @retval FALSE Go to normal path
  
**/
BOOLEAN
OemRecoveryBootMode ()
{
  return PlatformIsBootWithRecoveryStage1 ();
}

/**
  Peform the boot mode determination logic
  If the box is closed, then
    1. If it's first time to boot, it's boot with full config .
    2. If the ChassisIntrution is selected, force to be a boot with full config
    3. Otherwise it's boot with no change.
  
  @param  PeiServices General purpose services available to every PEIM.   
  
  @param  BootMode The detected boot mode.
  
  @retval EFI_SUCCESS if the boot mode could be set
**/
EFI_STATUS
UpdateBootMode (
  IN  EFI_PEI_SERVICES     **PeiServices,
  OUT EFI_BOOT_MODE        *BootModePtr
  )
{
  EFI_STATUS          Status;
  PEI_CAPSULE_PPI     *Capsule;
  CHAR8               UserSelection;
  UINT32              Straps32;
  CHAR8               *BootModeDescStr;

  BootModeDescStr = NULL;

  //
  // Read Straps. Used later if recovery boot.
  //
  Straps32 = QNCAltPortRead (QUARK_SCSS_SOC_UNIT_SB_PORT_ID, QUARK_SCSS_SOC_UNIT_STPDDRCFG);

  //
  // Get current boot mode.
  //
  Status = PeiServicesGetBootMode (BootModePtr);
  ASSERT_EFI_ERROR (Status);

  if ((*BootModePtr) != BOOT_IN_RECOVERY_MODE) {
    if ((*BootModePtr) == BOOT_ON_S3_RESUME) {
      //
      // Determine if we're in capsule update mode
      //
      Status = PeiServicesLocatePpi (
                               &gPeiCapsulePpiGuid,
                               0,
                               NULL,
                               (VOID **)&Capsule
                               );
      if (Status == EFI_SUCCESS) {
        Status = Capsule->CheckCapsuleUpdate (PeiServices);
        if (Status == EFI_SUCCESS) {
          BootModeDescStr = "Flash Update";
          *BootModePtr = BOOT_ON_FLASH_UPDATE;
        }
      }
      if ((*BootModePtr) == BOOT_ON_S3_RESUME) {
        BootModeDescStr = "S3Resume";
        Status = PeiServicesInstallPpi (&mPpiListSStateBootMode);
        ASSERT_EFI_ERROR (Status);
      }
    } else {
      //
      // Check if this is a power on reset
      //
      if (QNCCheckPowerOnResetAndClearState ()) {
        DEBUG ((EFI_D_INFO, "Power On Reset\n"));
        PcdSetBool (PcdIsPowerOnReset, TRUE);
      }
      if (IsBootWithNoChange (PeiServices)) {
        BootModeDescStr = "MinCfg";
        *BootModePtr = BOOT_ASSUMING_NO_CONFIGURATION_CHANGES;
      } else {
        BootModeDescStr = "FullCfg";
        *BootModePtr = BOOT_WITH_FULL_CONFIGURATION;
      }
    }
    if (BootModeDescStr != NULL) {
      DEBUG ((EFI_D_INFO, "BootMode: %a\n", BootModeDescStr));
    }
    Status = PeiServicesSetBootMode (*BootModePtr);
    ASSERT_EFI_ERROR (Status);
  } else {

    //
    // If Recovery Boot then prompt the user to insert a USB key with recovery nodule and
    // continue with the recovery. Also give the user a chance to retry a normal boot.
    //
    if ((Straps32 & B_STPDDRCFG_FORCE_RECOVERY) == 0) {
      DEBUG ((EFI_D_ERROR, "*****************************************************************\n"));
      DEBUG ((EFI_D_ERROR, "*****           Force Recovery Jumper Detected.             *****\n"));
      DEBUG ((EFI_D_ERROR, "*****      Attempting auto recovery of system flash.        *****\n"));
      DEBUG ((EFI_D_ERROR, "*****   Expecting USB key with recovery module connected.   *****\n"));
      DEBUG ((EFI_D_ERROR, "*****         PLEASE REMOVE FORCE RECOVERY JUMPER.          *****\n"));
      DEBUG ((EFI_D_ERROR, "*****************************************************************\n"));
    } else {
      DEBUG ((EFI_D_ERROR, "*****************************************************************\n"));
      DEBUG ((EFI_D_ERROR, "*****           ERROR: System boot failure!!!!!!!           *****\n"));
      DEBUG ((EFI_D_ERROR, "***** - Press 'R' if you wish to force system recovery      *****\n"));
      DEBUG ((EFI_D_ERROR, "*****     (connect USB key with recovery module first)      *****\n"));
      DEBUG ((EFI_D_ERROR, "***** - Press any other key to attempt another boot         *****\n"));
      DEBUG ((EFI_D_ERROR, "*****************************************************************\n"));

      UserSelection = PlatformDebugPortGetChar8 ();
      if ((UserSelection != 'R') && (UserSelection != 'r')) {
        DEBUG ((EFI_D_ERROR, "New boot attempt selected........\n"));
        //
        // Initialte the cold reset
        //
        ResetCold ();
      }
      DEBUG ((EFI_D_ERROR, "Recovery boot selected..........\n"));
    }
  }

  return EFI_SUCCESS;  
}


/**
  Early check if booting in recovery mode.

  @param  PeiServices General purpose services available to every PEIM.

  @retval EFI_SUCCESS if the boot mode could be set
**/

EFI_STATUS
EFIAPI
EarlyUpdateBootMode (
  IN CONST EFI_PEI_SERVICES               **PeiServices
)
{
  EFI_STATUS          Status;
  EFI_BOOT_MODE       BootMode;

  Status = PeiServicesGetBootMode (&BootMode);
  ASSERT_EFI_ERROR (Status);

  //
  // Check if we need to boot in recovery mode
  //
  if (OemRecoveryBootMode ()) {
    BootMode = BOOT_IN_RECOVERY_MODE;
    Status = PeiServicesInstallPpi (&mPpiListRecoveryBootMode);
    ASSERT_EFI_ERROR (Status);
  } else if (BootMode == BOOT_IN_RECOVERY_MODE || (ValidateFvHeader (&BootMode) != EFI_SUCCESS)) {
    if (BootMode != BOOT_IN_RECOVERY_MODE) {
      DEBUG ((EFI_D_INFO, "Stage2 FVHdr corrupt. "));
    }
    DEBUG ((EFI_D_INFO, "Reboot into recovery\n"));
    OemInitiateRecoveryAndWait ();
  } else if (QNCCheckS3AndClearState ()) {
    BootMode = BOOT_ON_S3_RESUME;
  } else {
    //
    // If system was put asleep but wakeup not detected/cleared/supported
    // by QNCCheckS3AndClearState above then do a cold reset for a known
    // state hw/sw reset for booting.
    //
    if (IsUndectedUnclearedWake (PeiServices)) {
      DEBUG ((EFI_D_INFO, "Undetected/uncleared/unsupported wake, do cold reset\n"));
      ResetCold();
    }
    return EFI_SUCCESS;
  }

  Status = PeiServicesSetBootMode (BootMode);
  ASSERT_EFI_ERROR (Status);
  return EFI_SUCCESS;
}
