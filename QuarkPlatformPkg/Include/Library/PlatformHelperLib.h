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

  PlatformHelperLib.h

Abstract:

  PlatformHelperLib function prototype definitions.

--*/

#ifndef __PLATFORM_HELPER_LIB_H__
#define __PLATFORM_HELPER_LIB_H__

#include "Platform.h"
#include "PlatformData.h"
#include "PlatformVariableTables.h"

// Descriptor structure for data pool.
typedef struct {
  UINT8                      *Data;   ///< Pointer to the Data memory.
  UINTN                      Cnt;     ///< Number of data elements in pool.
  UINTN                      Len;     ///< Amount of Data memory used.
  UINTN                      TermLen; ///< Length of data terminator.
  UINTN                      MaxLen;  ///< Max amount of Data memory available.
} PLATLIB_DATA_POOL;

//
// Function prototypes for routines exported by this library.
//

/**
  The PlatformCalculateCrc32 routine.

  @param   Data                   The buffer containing the data to be processed.
  @param   DataSize               The size of data to be processed.
  @param   CrcOut                 A pointer to the caller allocated UINT32 that
                                  on return contains the CRC32 checksum of Data.

  @retval  EFI_SUCCESS            Calculation is successful.
  @retval  EFI_INVALID_PARAMETER  Data / CrcOut = NULL, or DataSize = 0.
  @retval  EFI_NOT_FOUND          Firmware volume file not found.

**/
EFI_STATUS
EFIAPI
PlatformCalculateCrc32 (
  IN  UINT8                             *Data,
  IN  UINTN                             DataSize,
  IN OUT UINT32                         *CrcOut
  );

/**
  Find pointer to RAW data in Firmware volume file.

  @param   FvNameGuid       Firmware volume to search. If == NULL search all.
  @param   FileNameGuid     Firmware volume file to search for.
  @param   SectionData      Pointer to RAW data section of found file.
  @param   SectionDataSize  Pointer to UNITN to get size of RAW data.

  @retval  EFI_SUCCESS            Raw Data found.
  @retval  EFI_INVALID_PARAMETER  FileNameGuid == NULL.
  @retval  EFI_NOT_FOUND          Firmware volume file not found.
  @retval  EFI_UNSUPPORTED        Unsupported in current enviroment (PEI or DXE).

**/
EFI_STATUS
EFIAPI
PlatformFindFvFileRawDataSection (
  IN CONST EFI_GUID                 *FvNameGuid OPTIONAL,
  IN CONST EFI_GUID                 *FileNameGuid,
  OUT VOID                          **SectionData,
  OUT UINTN                         *SectionDataSize
  );

/**
  Read 8bit character from debug stream.

  Block until character is read.

  @return 8bit character read from debug stream.

**/
CHAR8
EFIAPI
PlatformDebugPortGetChar8 (
  VOID
  );

/**
  Return platform type string given platform type enum.

  @param  PlatformType  Executing platform type.

  ASSERT if invalid platform type enum.
  ASSERT if EFI_PLATFORM_TYPE_NAME_TABLE_DEFINITION has no entries.
  ASSERT if EFI_PLATFORM_TYPE_NAME_TABLE_DEFINITION has no string for type.

  @return string for platform type enum.

**/
CHAR16 *
EFIAPI
PlatformTypeString (
  IN CONST EFI_PLATFORM_TYPE              Type
  );

/**
  Return if platform type value is supported.

  @param  PlatformType  Executing platform type.

  @retval  TRUE    If type within range and not reserved.
  @retval  FALSE   if type is not supported.

**/
BOOLEAN
EFIAPI
PlatformIsSupportedPlatformType (
  IN CONST EFI_PLATFORM_TYPE              Type
  );

/**
  Find free spi protect register and write to it to protect a flash region.

  @param   DirectValue      Value to directly write to register.
                            if DirectValue == 0 the use Base & Length below.
  @param   BaseAddress      Base address of region in Flash Memory Map.
  @param   Length           Length of region to protect.

  @retval  EFI_SUCCESS      Free spi protect register found & written.
  @retval  EFI_NOT_FOUND    Free Spi protect register not found.
  @retval  EFI_DEVICE_ERROR Unable to write to spi protect register.

**/
EFI_STATUS
EFIAPI
PlatformWriteFirstFreeSpiProtect (
  IN CONST UINT32                         DirectValue,
  IN CONST UINT32                         BaseAddress,
  IN CONST UINT32                         Length
  );

/**
  Lock legacy SPI static configuration information.

  Function will assert if unable to lock config.

**/
VOID
EFIAPI
PlatformFlashLockConfig (
  VOID
  );

/**
  Lock regions and config of SPI flash given the policy for this platform.

  Function will assert if unable to lock regions or config.

  @param   PreBootPolicy    If TRUE do Pre Boot Flash Lock Policy.

**/
VOID
EFIAPI
PlatformFlashLockPolicy (
  IN CONST BOOLEAN                        PreBootPolicy
  );

/**
  Erase and Write to platform flash.

  Routine accesses one flash block at a time, each access consists
  of an erase followed by a write of FLASH_BLOCK_SIZE. One or both
  of DoErase & DoWrite params must be TRUE.

  Limitations:-
    CpuWriteAddress must be aligned to FLASH_BLOCK_SIZE.
    DataSize must be a multiple of FLASH_BLOCK_SIZE.

  @param   Smst                   If != NULL then InSmm and use to locate
                                  SpiProtocol.
  @param   CpuWriteAddress        Address in CPU memory map of flash region.
  @param   Data                   The buffer containing the data to be written.
  @param   DataSize               Amount of data to write.
  @param   DoErase                Earse each block.
  @param   DoWrite                Write to each block.

  @retval  EFI_SUCCESS            Operation successful.
  @retval  EFI_NOT_READY          Required resources not setup.
  @retval  EFI_INVALID_PARAMETER  Invalid parameter.
  @retval  Others                 Unexpected error happened.

**/
EFI_STATUS
EFIAPI
PlatformFlashEraseWrite (
  IN  VOID                              *Smst,
  IN  UINTN                             CpuWriteAddress,
  IN  UINT8                             *Data,
  IN  UINTN                             DataSize,
  IN  BOOLEAN                           DoErase,
  IN  BOOLEAN                           DoWrite
  );

/**
  Those capsules supported by the firmwares.

  @param  CapsuleHeader    Points to a capsule header.

  @retval EFI_SUCESS       Input capsule is supported by firmware.
  @retval EFI_UNSUPPORTED  Input capsule is not supported by the firmware.
**/
EFI_STATUS
EFIAPI
PlatformSupportCapsuleImage (
  IN VOID *CapsuleHeader
  );

/** Check if System booted with recovery Boot Stage1 image.

  @retval  TRUE    If system booted with recovery Boot Stage1 image.
  @retval  FALSE   If system booted with normal stage1 image.

**/
BOOLEAN
EFIAPI
PlatformIsBootWithRecoveryStage1 (
  VOID
  );

/**
  Clear SPI Protect registers.

  @retval EFI_SUCESS         SPI protect registers cleared.
  @retval EFI_ACCESS_DENIED  Unable to clear SPI protect registers.
**/

EFI_STATUS
EFIAPI
PlatformClearSpiProtect (
  VOID
  );

/**
  Determine if an SPI address range is protected.

  @param  SpiBaseAddress  Base of SPI range.
  @param  Length          Length of SPI range.

  @retval TRUE       Range is protected.
  @retval FALSE      Range is not protected.
**/
BOOLEAN
EFIAPI
PlatformIsSpiRangeProtected (
  IN CONST UINT32                         SpiBaseAddress,
  IN CONST UINT32                         Length
  );

/**
  Set Legacy GPIO Level

  @param  LevelRegOffset      GPIO level register Offset from GPIO Base Address.
  @param  GpioNum             GPIO bit to change.
  @param  HighLevel           If TRUE set GPIO High else Set GPIO low.

**/
VOID
EFIAPI
PlatformLegacyGpioSetLevel (
  IN CONST UINT32       LevelRegOffset,
  IN CONST UINT32       GpioNum,
  IN CONST BOOLEAN      HighLevel
  );

/**
  Get Legacy GPIO Level

  @param  LevelRegOffset      GPIO level register Offset from GPIO Base Address.
  @param  GpioNum             GPIO bit to check.

  @retval TRUE       If bit is SET.
  @retval FALSE      If bit is CLEAR.

**/
BOOLEAN
EFIAPI
PlatformLegacyGpioGetLevel (
  IN CONST UINT32       LevelRegOffset,
  IN CONST UINT32       GpioNum
  );

/**
  Set the direction of Pcal9555 IO Expander GPIO pin.

  @param  Pcal9555SlaveAddr  I2c Slave address of Pcal9555 Io Expander.
  @param  GpioNum            Gpio direction to configure - values 0-7 for Port0
                             and 8-15 for Port1.
  @param  CfgAsInput         If TRUE set pin direction as input else set as output.

**/
VOID
EFIAPI
PlatformPcal9555GpioSetDir (
  IN CONST UINT32                         Pcal9555SlaveAddr,
  IN CONST UINT32                         GpioNum,
  IN CONST BOOLEAN                        CfgAsInput
  );

/**
  Set the level of Pcal9555 IO Expander GPIO high or low.

  @param  Pcal9555SlaveAddr  I2c Slave address of Pcal9555 Io Expander.
  @param  GpioNum            Gpio to change values 0-7 for Port0 and 8-15
                             for Port1.
  @param  HighLevel          If TRUE set pin high else set pin low.

**/
VOID
EFIAPI
PlatformPcal9555GpioSetLevel (
  IN CONST UINT32                         Pcal9555SlaveAddr,
  IN CONST UINT32                         GpioNum,
  IN CONST BOOLEAN                        HighLevel
  );

/**

  Enable pull-up/pull-down resistors of Pcal9555 GPIOs.

  @param  Pcal9555SlaveAddr  I2c Slave address of Pcal9555 Io Expander.
  @param  GpioNum            Gpio to change values 0-7 for Port0 and 8-15
                             for Port1.

**/
VOID
EFIAPI
PlatformPcal9555GpioEnablePull (
  IN CONST UINT32                         Pcal9555SlaveAddr,
  IN CONST UINT32                         GpioNum
  );

/**

  Disable pull-up/pull-down resistors of Pcal9555 GPIOs.

  @param  Pcal9555SlaveAddr  I2c Slave address of Pcal9555 Io Expander.
  @param  GpioNum            Gpio to change values 0-7 for Port0 and 8-15
                             for Port1.

**/
VOID
EFIAPI
PlatformPcal9555GpioDisablePull (
  IN CONST UINT32                         Pcal9555SlaveAddr,
  IN CONST UINT32                         GpioNum
  );

/**
  Init platform LEDs into known state.

  @param   PlatformType     Executing platform type.

  @retval  EFI_SUCCESS      Operation success.

**/
EFI_STATUS
EFIAPI
PlatformLedInit (
  IN CONST EFI_PLATFORM_TYPE              Type
  );

/**
  Turn on or off platform flash update LED.

  @param   PlatformType     Executing platform type.
  @param   TurnOn           If TRUE turn on else turn off.

  @retval  EFI_SUCCESS      Operation success.

**/
EFI_STATUS
EFIAPI
PlatformFlashUpdateLed (
  IN CONST EFI_PLATFORM_TYPE              Type,
  IN CONST BOOLEAN                        TurnOn
  );

/**
  Find a UEFI variable entry(guid/name) in a UEFI variable table.

  Optionally find if a vendor global entry is in the table (ie if entry
  with vendor guid != NULL and variable name == NULL.

  @param   Table                  Table of variables to search.
  @param   TableLen               Number of entries in table.
  @param   VendorGuid             Vendor Guid to search for in table.
  @param   VariableName           Variable name to search for in table, can be
                                  NULL if caller searching for a vendor global
                                  entry.
  @param   VendorGlobalEntryPtr   Location to write pointer to vendor global entry.

  @retval NULL                    Variable not found in table.
  @return Pointer to entry found in table.
  @return *VendorGlobalEntryPtr updated if vendor global entry in table.

**/
PLATFORM_VARIABLE_TABLE_ENTRY *
EFIAPI
PlatformFindVariableTableEntry (
  IN CONST PLATFORM_VARIABLE_TABLE_ENTRY  *Table,
  IN CONST UINTN                          TableLen,
  IN EFI_GUID                             *VendorGuid,
  IN CHAR16                               *VariableName OPTIONAL,
  OUT PLATFORM_VARIABLE_TABLE_ENTRY       **VendorGlobalEntryPtr OPTIONAL
  );

/**
  Return TRUE if any entries in a variable table are in the UEFI Variable Store

  If entry in table has vendor guid != NULL and variable name == NULL
  then return true if any variables in UEFI Variable store with entry
  vendor guid.

  @param   Table                  Table of variables.
  @param   TableLen               Number of entries in table.

  @retval  TRUE    If entry in table also in variable store
  @retval  FALSE   If no entries in variable store.

**/
BOOLEAN
EFIAPI
PlatformIsVariableTableEntryInVariableStore (
  IN CONST PLATFORM_VARIABLE_TABLE_ENTRY  *Table,
  IN CONST UINTN                          TablenLen
  );

/**
  Delete variables in UEFI Variable store which are writeable.

  The routine can optionally be provided with a table of variables to maintain.

  @param   MaintainTable          Table of variables to maintain.
  @param   MaintainTableLen       Number of entries in maintain table.
  @param   DeleteCountPtr         Optionally return number of variables deleted.
  @param   MaintainCountPtr       Optionally return number of variables maintained.

  @retval  EFI_SUCCESS            Variables deleted from store.
  @retval  EFI_NOT_FOUND          No variables found to delete.
  @retval  EFI_OUT_OF_RESOURCES   Unable to delete due to resourcing problems.

**/
EFI_STATUS
EFIAPI
PlatformDeleteVariables (
  IN CONST PLATFORM_VARIABLE_TABLE_ENTRY  *MaintainTable OPTIONAL,
  IN CONST UINTN                          MaintainTableLen OPTIONAL,
  OUT UINTN                               *DeleteCountPtr OPTIONAL,
  OUT UINTN                               *MaintainCountPtr OPTIONAL
  );

/** Append Data to a PlatLib DataPool.

  @param[in, out]  PoolPtr        Data PoolPtr if *PoolPtr = NULL allocate new pool.
  @param[in]       AppendData     Data to append to data pool.
  @param[in]       DataLen        Byte size of memory pointed to by AppendData.
  @param[in]       Terminator     Optional terminator eg NULL pointer for
                                  multistrings, NULL DevicePath for
                                  multi device paths or pointer to 16byte NULL GUID
                                  for multi guid list.
  @param[in]       TerminatorLen  Byte size Terminator data.

  @retval  NULL                   Unexpected error - Operation failed.
  @return  Pointer to Appended Data within Data Pool.
**/
UINT8 *
EFIAPI
PlatformDataPoolAppend (
  IN OUT PLATLIB_DATA_POOL                **PoolPtr,
  IN UINT8                                *AppendData,
  IN UINTN                                DataLen,
  IN UINT8                                *Terminator OPTIONAL,
  IN UINTN                                TerminatorLen OPTIONAL
  );

/**
  Inserts a string into PLATLIB_DATA_POOL.

  @param   MultiStrList     Tracks the allocated pool, size in use, and amount of pool allocated.
  @param   InsertString     String to insert.

  @return Allocated buffer with PLATLIB_DATA_POOL fields updated.
          The caller must free the allocated buffer.
          The buffer allocation is not packed.
**/
CHAR16 *
EFIAPI
PlatformMultiStringInsert (
  IN OUT PLATLIB_DATA_POOL                **MultiStrList,
  IN CHAR16                               *InsertString
  );

/**
  Inserts a GUID into PLATLIB_DATA_POOL.

  @param   MultiGuitList    Tracks the allocated pool, size in use, and amount of pool allocated.
  @param   InsertGuid       Guid to insert.

  @return Allocated buffer with PLATLIB_DATA_POOL fields updated.
          The caller must free the allocated buffer.
          The buffer allocation is not packed.
**/
EFI_GUID *
EFIAPI
PlatformMultiGuidInsert (
  IN OUT PLATLIB_DATA_POOL                **MultiGuidList,
  IN EFI_GUID                             *InsertGuid
  );

/**
  Signal guid named events shown in 5.1.1 of PI Spec.

  @param   EventName    Guid named event to signal.

  @return one of EFI_CREATE_EVENT_EX service return values.

**/
EFI_STATUS
EFIAPI
PlatformSignalGuidNamedEvent (
  IN CONST EFI_GUID                       *EventName
  );

/**

  @param  Type      Type to search for in table.
  @param  IndexPtr  Pointer to receive index of type in table.

  @retval  TRUE    If type in TypeToIndexTable.
  @retval  FALSE   if type not found in TypeToIndexTable.
  @return in *IndexPtr the Index of the type in TypeToIndexTable.

**/
BOOLEAN
EFIAPI
PlatformTypeToTableIndex (
  IN CONST EFI_PLATFORM_TYPE              Type,
  OUT UINTN                               *IndexPtr
  );
#endif // #ifndef __PLATFORM_HELPER_LIB_H__
