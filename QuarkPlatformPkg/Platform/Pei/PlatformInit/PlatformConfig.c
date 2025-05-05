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
  PlatformConfig.c

Abstract:
  Principle source module for Clanton Peak platform config PEIM driver.

--*/

#include "CommonHeader.h"
#include "PlatformEarlyInit.h"
#include <Library/I2cLib.h>

//
// Global variables.
//

//
// Private routines to this source module.
//

STATIC
VOID
EFIAPI
LegacySpiProtect (
  VOID
  )
{
  UINT32                            RegVal;

  RegVal = FixedPcdGet32 (PcdLegacyProtectedBIOSRange0Pei);
  if (RegVal != 0) {

    PlatformWriteFirstFreeSpiProtect (
      RegVal,
      0,
      0
      );

  }
  RegVal = FixedPcdGet32 (PcdLegacyProtectedBIOSRange1Pei);
  if (RegVal != 0) {
    PlatformWriteFirstFreeSpiProtect (
      RegVal,
      0,
      0
      );
  }
  RegVal = FixedPcdGet32 (PcdLegacyProtectedBIOSRange2Pei);
  if (RegVal != 0) {
    PlatformWriteFirstFreeSpiProtect (
      RegVal,
      0,
      0
      );
  }

  //
  // Make legacy SPI READ/WRITE enabled if not a secure build
  //
  if (QuarkCheckSecureLockBoot()) {
    LpcPciCfg32And (R_QNC_LPC_BIOS_CNTL, ~B_QNC_LPC_BIOS_CNTL_BIOSWE);
  } else {
    LpcPciCfg32Or (R_QNC_LPC_BIOS_CNTL, B_QNC_LPC_BIOS_CNTL_BIOSWE);
  }

}


/** Set Dynamic PCD values.

**/
STATIC
VOID
EFIAPI
UpdateDynamicPcds (
  VOID
  )
{
  MFH_LIB_FINDCONTEXT               FindContext;
  MFH_FLASH_ITEM                    *FlashItem;
  UINT32                            SecHdrSize;
  UINT32                            Temp32;
  UINT32                            SramImageIndex;
  QUARK_EDKII_STAGE1_HEADER         *SramEdk2ImageHeader;
  QUARK_EDKII_STAGE1_HEADER         *FlashEntryEdk2ImageHeader;
  MFH_LIB_FINDCONTEXT               MfhFindContext;
  UINT32                            Stage1Base;
  UINT32                            Stage1Len;
  UINT32                            SetBase;
  UINT32                            SetLen;

  SecHdrSize = FixedPcdGet32 (PcdFvSecurityHeaderSize);

  //
  // Init stage1 locals with fixed recovery image constants.
  //
  Stage1Base = FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase);
  Stage1Len = FixedPcdGet32 (PcdFlashFvFixedStage1AreaSize);

  //
  // Setup PCDs determined from MFH if not running in recovery.
  //
  if (!PlatformIsBootWithRecoveryStage1()) {
    //
    // If found in SPI MFH override Stage1Base & Len with MFH values.
    //
    SramEdk2ImageHeader = (QUARK_EDKII_STAGE1_HEADER *) (FixedPcdGet32 (PcdEsramStage1Base) + SecHdrSize);
    SramImageIndex = (UINT32)  SramEdk2ImageHeader->ImageIndex;
    FlashItem = MfhLibFindFirstWithFilter (
                  NULL,
                  MFH_FIND_ALL_STAGE1_FILTER,
                  FALSE,
                  &MfhFindContext
                  );
    while (FlashItem != NULL) {
      FlashEntryEdk2ImageHeader = (QUARK_EDKII_STAGE1_HEADER *) (FlashItem->FlashAddress + SecHdrSize);
      if (SramImageIndex == FlashEntryEdk2ImageHeader->ImageIndex) {
        Stage1Base = FlashItem->FlashAddress;
        Stage1Len = FlashItem->LengthBytes;
        break;
      }
      FlashItem = MfhLibFindNextWithFilter (
                    MFH_FIND_ALL_STAGE1_FILTER,
                    &MfhFindContext
                    );
    }

    Temp32 = PcdSet32 (PcdFlashFvRecoveryBase, (Stage1Base + SecHdrSize));
    ASSERT (Temp32 == (Stage1Base + SecHdrSize));

    Temp32 = PcdSet32 (PcdFlashFvRecoverySize, (Stage1Len - SecHdrSize));
    ASSERT (Temp32 == (Stage1Len - SecHdrSize));

    //
    // Set FvMain base and length PCDs from SPI MFH database.
    //
    FlashItem = MfhLibFindFirstWithFilter (
                  NULL,
                  MFH_FIND_ALL_STAGE2_FILTER,
                  FALSE,
                  &FindContext
                  );

    if (FlashItem != NULL) {
      SetBase = FlashItem->FlashAddress + SecHdrSize;
      SetLen = FlashItem->LengthBytes - SecHdrSize;
    } else {
      SetBase = FixedPcdGet32 (PcdFlashFvDefaultMainBase);
      SetLen = FixedPcdGet32 (PcdFlashFvDefaultMainSize);
    }
    Temp32 = PcdSet32 (PcdFlashFvMainBase, SetBase);
    ASSERT (Temp32 == SetBase);

    Temp32 = PcdSet32 (PcdFlashFvMainSize, SetLen);
    ASSERT (Temp32 == SetLen);

    //
    // Set Payload base and length PCDs from SPI MFH database.
    //
    FlashItem = MfhLibFindFirstWithFilter (
                  NULL,
                  MFH_FIND_ALL_BOOTLOADER_FILTER,
                  FALSE,
                  &FindContext
                  );

    if (FlashItem != NULL) {
      SetBase = FlashItem->FlashAddress + SecHdrSize;
      SetLen = FlashItem->LengthBytes;
    } else {
      SetBase = FixedPcdGet32 (PcdFlashFvDefaultPayloadBase);
      SetLen = FixedPcdGet32 (PcdFlashFvDefaultPayloadSize);
    }
    Temp32 = PcdSet32 (PcdFlashFvPayloadBase, SetBase);
    ASSERT (Temp32 == SetBase);

    Temp32 = PcdSet32 (PcdFlashFvPayloadSize, SetLen);
    ASSERT (Temp32 == SetLen);
  }
}

/** Do early platform config tasks.

  @param[in]       PeiServices  General purpose services available to every PEIM.

  @retval EFI_SUCCESS           Platform config success.
*/
EFI_STATUS
EFIAPI
EarlyPlatformConfig (
  IN CONST EFI_PEI_SERVICES               **PeiServices
  )
{
  //
  // Do SOC Init Pre memory init.
  //
  PeiQNCPreMemInit ();

  //
  // Protect areas specified by PCDs.
  //
  LegacySpiProtect ();

  //
  // Early update of Dynamic PCDs given run time info.
  //
  UpdateDynamicPcds ();

  return EFI_SUCCESS;
}

/** This is the routine to initialize UART0 on Galileo platform.

**/
VOID
EFIAPI
PlatformInitializeUart0MuxGalileo (
  VOID
  )
{
  EFI_STATUS                        Status;
  EFI_I2C_DEVICE_ADDRESS            I2CSlaveAddress;
  UINTN                             Length;
  UINT8                             Buffer[2];

  if (PlatformLegacyGpioGetLevel (R_QNC_GPIO_RGLVL_RESUME_WELL, GALILEO_DETERMINE_IOEXP_SLA_RESUMEWELL_GPIO)) {
    I2CSlaveAddress.I2CDeviceAddress = GALILEO_IOEXP_J2HI_7BIT_SLAVE_ADDR;
  } else {
    I2CSlaveAddress.I2CDeviceAddress = GALILEO_IOEXP_J2LO_7BIT_SLAVE_ADDR;
  }

  //
  // Set GPIO_SUS<2> as an output, raise voltage to Vdd.
  //
  PlatformLegacyGpioSetLevel (R_QNC_GPIO_RGLVL_RESUME_WELL, 2, TRUE);

  //
  // Select Port 3
  //
  Length = 2;
  Buffer[0] = CY8C95XXA_REG_PORT_SELECT; // sub-address = register to address.
  Buffer[1] = 0x03; // data = 0x3 to select port 3

  Status = I2cWriteMultipleByte (
             I2CSlaveAddress,
             EfiI2CSevenBitAddrMode,
             &Length,
             &Buffer
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Set "Pin Direction" bit4 and bit5 as outputs.
  // Default value == 0xFF with GPIOs configured as inputs.
  // Clear bit4 and bit5 to configure as outputs ie 0xCF.
  //
  Length = 2;
  Buffer[0] = CY8C95XXA_REG_PORT_DIRECTION; // sub-address = register to address.
  Buffer[1] = 0xCF; // data = 0xCF to clear bit4 & bit5.

  Status = I2cWriteMultipleByte (
             I2CSlaveAddress,
             EfiI2CSevenBitAddrMode,
             &Length,
             &Buffer
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Lower GPORT3 bit4 and bit5 to Vss
  // To output reg for port3 is CY8C95XXA_REG_PORT_OUTPUT_BASE + 3
  // Writes to this register has no effect on GPIOs configured as inputs.
  //
  Length = 2;
  Buffer[0] = CY8C95XXA_REG_PORT_OUTPUT_BASE + 0x3; // sub-address = register to address.
  Buffer[1] = 0xCF; // data = output 0 on bit3 pin & bit4 pin.
  Status = I2cWriteMultipleByte (
             I2CSlaveAddress,
             EfiI2CSevenBitAddrMode,
             &Length,
             &Buffer
             );
  ASSERT_EFI_ERROR (Status);
}

/** This is the routine to initialize UART0 on Galileo Gen2 platform.

  The hardware used in this process is
  I2C controller and the configuring the following IO Expander signal.

  EXP1.P1_5 should be configured as an output & driven high.
  EXP1.P0_0 should be configured as an output & driven high.
  EXP0.P1_4 should be configured as an output, driven low.
  EXP1.P0_1 pullup should be disabled.
  EXP0.P1_5 Pullup should be disabled.

**/
VOID
EFIAPI
PlatformInitializeUart0MuxGalileoGen2 (
  VOID
  )
{
  //
  //  EXP1.P1_5 should be configured as an output & driven high.
  //
  PlatformPcal9555GpioSetDir (
    GALILEO_GEN2_IOEXP1_7BIT_SLAVE_ADDR,  // IO Expander 1.
    13,                                   // P1-5.
    TRUE
    );
  PlatformPcal9555GpioSetLevel (
    GALILEO_GEN2_IOEXP1_7BIT_SLAVE_ADDR,  // IO Expander 1.
    13,                                   // P1-5.
    TRUE
    );

  //
  // EXP1.P0_0 should be configured as an output & driven high.
  //
  PlatformPcal9555GpioSetDir (
    GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR,  // IO Expander 0.
    0,                                    // P0_0.
    TRUE
    );
  PlatformPcal9555GpioSetLevel (
    GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR,  // IO Expander 0.
    0,                                    // P0_0.
    TRUE
    );

  //
  //  EXP0.P1_4 should be configured as an output, driven low.
  //
  PlatformPcal9555GpioSetDir (
    GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR,  // IO Expander 0.
    12,                                   // P1-4.
    FALSE
    );
  PlatformPcal9555GpioSetLevel (          // IO Expander 0.
    GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR,  // P1-4
    12,
    FALSE
    );

  //
  // EXP1.P0_1 pullup should be disabled.
  //
  PlatformPcal9555GpioDisablePull (
    GALILEO_GEN2_IOEXP1_7BIT_SLAVE_ADDR,  // IO Expander 1.
    1                                     // P0-1.
    );

  //
  // EXP0.P1_5 Pullup should be disabled.
  //
  PlatformPcal9555GpioDisablePull (
    GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR,  // IO Expander 0.
    13                                    // P1-5.
    );
}

