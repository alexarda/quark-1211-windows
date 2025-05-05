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

  PlatformBoards.h

Abstract:

  Board config definitions for each of the boards supported by this platform
  package.

--*/

#include "Pcal9555.h"
#include "CY8C95XXA.h"

#ifndef __PLATFORM_BOARDS_H__
#define __PLATFORM_BOARDS_H__

//
// Constant definition
//

// Cross Hill TPM reset - GPIO_SUS<5>.
#define PLATFORM_RESUMEWELL_TPM_RST_GPIO                5

// Reliance Creek TPM reset.  GPIO<8> is the first GPIO of the core iLB GPIO block.
#define PLATFORM_COREWELL_TPM_RST_GPIO_RCK              0

//
// Basic Configs for GPIO table definitions.
//
#define NULL_LEGACY_GPIO_INITIALIZER                    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}
#define ALL_INPUT_LEGACY_GPIO_INITIALIZER               {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x3f,0x00,0x00,0x00,0x00,0x00,0x3f,0x00}
#define QUARK_EMULATION_LEGACY_GPIO_INITIALIZER         ALL_INPUT_LEGACY_GPIO_INITIALIZER
#define CLANTON_PEAK_SVP_LEGACY_GPIO_INITIALIZER        {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x3f,0x00,0x00,0x3f,0x3f,0x00,0x3f,0x00}
#define KIPS_BAY_LEGACY_GPIO_INITIALIZER                {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x25,0x10,0x00,0x00,0x00,0x00,0x3f,0x00}
#define CROSS_HILL_LEGACY_GPIO_INITIALIZER              {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x03,0x10,0x00,0x03,0x03,0x00,0x3f,0x00}
#define CLANTON_HILL_LEGACY_GPIO_INITIALIZER            {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x06,0x10,0x00,0x04,0x04,0x00,0x3f,0x00}
#define GALILEO_LEGACY_GPIO_INITIALIZER                 {0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x21,0x14,0x00,0x01,0x01,0x00,0x3f,0x00}
#define GALILEO_GEN2_LEGACY_GPIO_INITIALIZER            {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x1c,0x02,0x00,0x00,0x00,0x00,0x3f,0x00}
#define RELIANCE_CREEK_LEGACY_GPIO_INITIALIZER          {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x38,0x06,0x00,0x00,0x00,0x00,0x3f,0x00}
#define RELIANCE_CREEK_SPU_LEGACY_GPIO_INITIALIZER      {0x03,0x03,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x3f,0x38,0x06,0x00,0x00,0x00,0x00,0x3f,0x00}
#define NULL_GPIO_CONTROLLER_INITIALIZER                {0,0,0,0,0,0,0,0}
#define ALL_INPUT_GPIO_CONTROLLER_INITIALIZER           NULL_GPIO_CONTROLLER_INITIALIZER
#define QUARK_EMULATION_GPIO_CONTROLLER_INITIALIZER     NULL_GPIO_CONTROLLER_INITIALIZER
#define CLANTON_PEAK_SVP_GPIO_CONTROLLER_INITIALIZER    NULL_GPIO_CONTROLLER_INITIALIZER
#define KIPS_BAY_GPIO_CONTROLLER_INITIALIZER            {0x05,0x05,0,0,0,0,0,0}
#define CROSS_HILL_GPIO_CONTROLLER_INITIALIZER          {0x0D,0x2D,0,0,0,0,0,0}
#define CLANTON_HILL_GPIO_CONTROLLER_INITIALIZER        {0x01,0x39,0,0,0,0,0,0}
#define GALILEO_GPIO_CONTROLLER_INITIALIZER             {0x05,0x15,0,0,0,0,0,0}
#define GALILEO_GEN2_GPIO_CONTROLLER_INITIALIZER        {0x05,0x05,0,0,0,0,0,0}
#define RELIANCE_CREEK_GPIO_CONTROLLER_INITIALIZER      {0x04,0x04,0,0,0,0,0,0}
#define RELIANCE_CREEK_SPU_GPIO_CONTROLLER_INITIALIZER  {0x04,0x04,0,0,0,0,0,0}

//
// Legacy Gpio to be used to assert / deassert PCI express PERST# signal
// on Galileo Gen 2 platform.
//
#define GALILEO_GEN2_PCIEXP_PERST_RESUMEWELL_GPIO       0

//
// Io expander slave address.
//

//
// On Galileo value of Jumper J2 determines slave address of io expander.
//
#define GALILEO_DETERMINE_IOEXP_SLA_RESUMEWELL_GPIO     5
#define GALILEO_IOEXP_J2HI_7BIT_SLAVE_ADDR              0x20
#define GALILEO_IOEXP_J2LO_7BIT_SLAVE_ADDR              0x21

//
// Three IO Expmanders at fixed addresses on Galileo Gen2.
//
#define GALILEO_GEN2_IOEXP0_7BIT_SLAVE_ADDR             0x25
#define GALILEO_GEN2_IOEXP1_7BIT_SLAVE_ADDR             0x26
#define GALILEO_GEN2_IOEXP2_7BIT_SLAVE_ADDR             0x27

//
// Led GPIOs for flash update / recovery.
//
#define GALILEO_FLASH_UPDATE_LED_RESUMEWELL_GPIO        1
#define GALILEO_GEN2_FLASH_UPDATE_LED_RESUMEWELL_GPIO   5

//
// Legacy GPIO config struct for each element in PLATFORM_LEGACY_GPIO_TABLE_DEFINITION.
//
typedef struct {
  UINT32  CoreWellEnable;               ///< Value for QNC NC Reg R_QNC_GPIO_CGEN_CORE_WELL.
  UINT32  CoreWellIoSelect;             ///< Value for QNC NC Reg R_QNC_GPIO_CGIO_CORE_WELL.
  UINT32  CoreWellLvlForInputOrOutput;  ///< Value for QNC NC Reg R_QNC_GPIO_CGLVL_CORE_WELL.
  UINT32  CoreWellTriggerPositiveEdge;  ///< Value for QNC NC Reg R_QNC_GPIO_CGTPE_CORE_WELL.
  UINT32  CoreWellTriggerNegativeEdge;  ///< Value for QNC NC Reg R_QNC_GPIO_CGTNE_CORE_WELL.
  UINT32  CoreWellGPEEnable;            ///< Value for QNC NC Reg R_QNC_GPIO_CGGPE_CORE_WELL.
  UINT32  CoreWellSMIEnable;            ///< Value for QNC NC Reg R_QNC_GPIO_CGSMI_CORE_WELL.
  UINT32  CoreWellTriggerStatus;        ///< Value for QNC NC Reg R_QNC_GPIO_CGTS_CORE_WELL.
  UINT32  CoreWellNMIEnable;            ///< Value for QNC NC Reg R_QNC_GPIO_CGNMIEN_CORE_WELL.
  UINT32  ResumeWellEnable;             ///< Value for QNC NC Reg R_QNC_GPIO_RGEN_RESUME_WELL.
  UINT32  ResumeWellIoSelect;           ///< Value for QNC NC Reg R_QNC_GPIO_RGIO_RESUME_WELL.
  UINT32  ResumeWellLvlForInputOrOutput;///< Value for QNC NC Reg R_QNC_GPIO_RGLVL_RESUME_WELL.
  UINT32  ResumeWellTriggerPositiveEdge;///< Value for QNC NC Reg R_QNC_GPIO_RGTPE_RESUME_WELL.
  UINT32  ResumeWellTriggerNegativeEdge;///< Value for QNC NC Reg R_QNC_GPIO_RGTNE_RESUME_WELL.
  UINT32  ResumeWellGPEEnable;          ///< Value for QNC NC Reg R_QNC_GPIO_RGGPE_RESUME_WELL.
  UINT32  ResumeWellSMIEnable;          ///< Value for QNC NC Reg R_QNC_GPIO_RGSMI_RESUME_WELL.
  UINT32  ResumeWellTriggerStatus;      ///< Value for QNC NC Reg R_QNC_GPIO_RGTS_RESUME_WELL.
  UINT32  ResumeWellNMIEnable;          ///< Value for QNC NC Reg R_QNC_GPIO_RGNMIEN_RESUME_WELL.
} BOARD_LEGACY_GPIO_CONFIG;

//
// GPIO controller config struct for each element in PLATFORM_GPIO_CONTROLLER_CONFIG_DEFINITION.
//
typedef struct {
  UINT32  PortADR;                      ///< Value for IOH REG GPIO_SWPORTA_DR.
  UINT32  PortADir;                     ///< Value for IOH REG GPIO_SWPORTA_DDR.
  UINT32  IntEn;                        ///< Value for IOH REG GPIO_INTEN.
  UINT32  IntMask;                      ///< Value for IOH REG GPIO_INTMASK.
  UINT32  IntType;                      ///< Value for IOH REG GPIO_INTTYPE_LEVEL.
  UINT32  IntPolarity;                  ///< Value for IOH REG GPIO_INT_POLARITY.
  UINT32  Debounce;                     ///< Value for IOH REG GPIO_DEBOUNCE.
  UINT32  LsSync;                       ///< Value for IOH REG GPIO_LS_SYNC.
} BOARD_GPIO_CONTROLLER_CONFIG;

//
// Define valid platform types.
// First add value before TypePlatformMax in EFI_PLATFORM_TYPE definition
// and then add string description to end of EFI_PLATFORM_TYPE_NAME_TABLE_DEFINITION.
// Value shown for supported platforms to help sanity checking with build tools
// and ACPI method usage.
//
typedef enum {
  TypeUnknown = 0,      // !!! SHOULD BE THE FIRST ENTRY AND NOT USED BY REAL HW!!!
  QuarkEmulation = 1,
  ClantonPeakSVP = 2,
  KipsBay = 3,
  CrossHill = 4,
  ClantonHill = 5,
  Galileo = 6,
  TypePlatformRsv7 = 7,
  GalileoGen2 = 8,
  RelianceCreek = 9,
  RelianceCreekSPU = 0xa,
  //
  // Following TypeIntelPlatformMax def should be the last Intel platform type
  //
  TypeIntelPlatformMax = 0xfff,

  //
  // All ODM boards should use values from here to TypePlatformMax.
  //

  //
  // PDAT_ITEM_ID_PLATFORM_ID record contains 16bit value for platform type.
  // Hence TypePlatformMax is 0xffff & like TypeUnknown should not be used
  // by real Hardware.
  //
  TypePlatformMax = 0xffff
} EFI_PLATFORM_TYPE;

//
// All tables with platform specific elements must be ordered
// as follows. The tables must also contain an element for each of the
// platform types listed.
//
#define EFI_PLATFORM_TYPE_TO_INDEX_TABLE_DEFINITION \
  TypeUnknown, \
  QuarkEmulation, \
  ClantonPeakSVP, \
  KipsBay, \
  CrossHill, \
  ClantonHill, \
  Galileo, \
  TypePlatformRsv7, \
  GalileoGen2, \
  RelianceCreek, \
  RelianceCreekSPU, \

#define EFI_PLATFORM_TYPE_NAME_TABLE_DEFINITION \
  L"TypeUnknown",\
  L"QuarkEmulation",\
  L"ClantonPeakSVP",\
  L"KipsBay",\
  L"CrossHill",\
  L"ClantonHill",\
  L"Galileo",\
  L"TypePlatformRsv7",\
  L"GalileoGen2",\
  L"RelianceCreek",\
  L"RelianceCreekSPU",\
///
/// Table of BOARD_LEGACY_GPIO_CONFIG structures for each board supported
/// by this platform package.
/// Table indexed with EFI_PLATFORM_TYPE enum value.
///
#define PLATFORM_LEGACY_GPIO_TABLE_DEFINITION \
  /* EFI_PLATFORM_TYPE - TypeUnknown*/\
  NULL_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - QuarkEmulation*/\
  QUARK_EMULATION_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - ClantonPeakSVP*/\
  CLANTON_PEAK_SVP_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - KipsBay*/\
  KIPS_BAY_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - CrossHill*/\
  CROSS_HILL_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - ClantonHill*/\
  CLANTON_HILL_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - Galileo*/\
  GALILEO_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - TypePlatformRsv7*/\
  NULL_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - GalileoGen2*/\
  GALILEO_GEN2_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - RelianceCreek*/\
  RELIANCE_CREEK_LEGACY_GPIO_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - RelianceCreekSPU*/\
  RELIANCE_CREEK_SPU_LEGACY_GPIO_INITIALIZER,\

///
/// Table of BOARD_GPIO_CONTROLLER_CONFIG structures for each board
/// supported by this platform package.
/// Table indexed with EFI_PLATFORM_TYPE enum value.
///
#define PLATFORM_GPIO_CONTROLLER_CONFIG_DEFINITION \
  /* EFI_PLATFORM_TYPE - TypeUnknown*/\
  NULL_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - QuarkEmulation*/\
  QUARK_EMULATION_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - ClantonPeakSVP*/\
  CLANTON_PEAK_SVP_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - KipsBay*/\
  KIPS_BAY_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - CrossHill*/\
  CROSS_HILL_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - ClantonHill*/\
  CLANTON_HILL_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - Galileo*/\
  GALILEO_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - TypePlatformRsv7 */\
  NULL_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - GalileoGen2*/\
  GALILEO_GEN2_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - RelianceCreek*/\
  RELIANCE_CREEK_GPIO_CONTROLLER_INITIALIZER,\
  /* EFI_PLATFORM_TYPE - RelianceCreekSPU */\
  RELIANCE_CREEK_SPU_GPIO_CONTROLLER_INITIALIZER,\

#endif
