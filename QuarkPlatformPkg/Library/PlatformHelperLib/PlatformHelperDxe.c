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

  PlatformHelperDxe.c

Abstract:

  Implementation of helper routines for DXE enviroment.

--*/

#include <PiDxe.h>

#include <Library/UefiBootServicesTableLib.h>
#include <Library/S3BootScriptLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/QuarkBootRomLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/I2cLib.h>
#include <Protocol/PlatformType.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/Spi.h>

#include "CommonHeader.h"

//
// Global variables.
//
EFI_SPI_PROTOCOL                    *mPlatHelpSpiProtocolRef = NULL;

//
// Routines defined in other source modules of this component.
//

//
// Routines local to this component.
//

STATIC
VOID
EFIAPI
EmptyEventFunction (
  IN EFI_EVENT                Event,
  IN VOID                     *Context
  )
{
  // An empty function to pass error checking of CreateEventEx ().
  // This empty function ensures that EVT_NOTIFY_SIGNAL_ALL is error
  // checked correctly since it is now mapped into CreateEventEx() in UEFI 2.0.

  return;
};

//
// Routines shared with other souce modules in this component.
//

VOID
Pcal9555SetPortRegBit (
  IN CONST UINT32                         Pcal9555SlaveAddr,
  IN CONST UINT32                         GpioNum,
  IN CONST UINT8                          RegBase,
  IN CONST BOOLEAN                        LogicOne
  )
{
  EFI_STATUS                        Status;
  UINTN                             ReadLength;
  UINTN                             WriteLength;
  UINT8                             Data[2];
  EFI_I2C_DEVICE_ADDRESS            I2cDeviceAddr;
  EFI_I2C_ADDR_MODE                 I2cAddrMode;
  UINT8                             *RegValuePtr;
  UINT8                             GpioNumMask;
  UINT8                             SubAddr;

  I2cDeviceAddr.I2CDeviceAddress = (UINTN) Pcal9555SlaveAddr;
  I2cAddrMode = EfiI2CSevenBitAddrMode;

  if (GpioNum < 8) {
    SubAddr = RegBase;
    GpioNumMask = (UINT8) (1 << GpioNum);
  } else {
    SubAddr = RegBase + 1;
    GpioNumMask = (UINT8) (1 << (GpioNum - 8));
  }

  //
  // Output port value always at 2nd byte in Data variable.
  //
  RegValuePtr = &Data[1];

  //
  // On read entry sub address at 2nd byte, on read exit output
  // port value in 2nd byte.
  //
  Data[1] = SubAddr;
  WriteLength = 1;
  ReadLength = 1;
  Status = I2cReadMultipleByte (
             I2cDeviceAddr,
             I2cAddrMode,
             &WriteLength,
             &ReadLength,
             &Data[1]
             );
  ASSERT_EFI_ERROR (Status);

  //
  // Adjust output port bit given callers request.
  //
  if (LogicOne) {
    *RegValuePtr = *RegValuePtr | GpioNumMask;
  } else {
    *RegValuePtr = *RegValuePtr & ~(GpioNumMask);
  }

  //
  // Update register. Sub address at 1st byte, value at 2nd byte.
  //
  WriteLength = 2;
  Data[0] = SubAddr;
  Status = I2cWriteMultipleByte (
             I2cDeviceAddr,
             I2cAddrMode,
             &WriteLength,
             Data
             );
  ASSERT_EFI_ERROR (Status);
}

EFI_SPI_PROTOCOL *
LocateSpiProtocol (
  IN  EFI_SMM_SYSTEM_TABLE2             *Smst
  )
{
  if (mPlatHelpSpiProtocolRef == NULL) {
    if (Smst != NULL) {
      Smst->SmmLocateProtocol (
              &gEfiSmmSpiProtocolGuid,
              NULL,
              (VOID **) &mPlatHelpSpiProtocolRef
              );
    } else {
      gBS->LocateProtocol (
             &gEfiSpiProtocolGuid,
             NULL,
             (VOID **) &mPlatHelpSpiProtocolRef
             );
    }
    ASSERT (mPlatHelpSpiProtocolRef != NULL);
  }
  return mPlatHelpSpiProtocolRef;
}

//
// Routines exported by this source module.
//

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
  )
{
  if (FileNameGuid == NULL || SectionData == NULL || SectionDataSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (FvNameGuid != NULL) {
    return EFI_UNSUPPORTED;  // Searching in specific FV unsupported in DXE.
  }

  return GetSectionFromAnyFv (FileNameGuid, EFI_SECTION_RAW, 0, SectionData, SectionDataSize);
}

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
  )
{
  UINT32                            FreeOffset;
  UINT32                            PchRootComplexBar;
  EFI_STATUS                        Status;

  PchRootComplexBar = QNC_RCRB_BASE;

  Status = WriteFirstFreeSpiProtect (
             PchRootComplexBar,
             DirectValue,
             BaseAddress,
             Length,
             &FreeOffset
             );

  if (!EFI_ERROR (Status)) {
    S3BootScriptSaveMemWrite (
      S3BootScriptWidthUint32,
        (UINTN) (PchRootComplexBar + FreeOffset),
        1,
        (VOID *) (UINTN) (PchRootComplexBar + FreeOffset)
        );
  }

  return Status;
}

/**
  Lock legacy SPI static configuration information.

  Function will assert if unable to lock config.

**/
VOID
EFIAPI
PlatformFlashLockConfig (
  VOID
  )
{
  EFI_STATUS        Status;
  EFI_SPI_PROTOCOL  *SpiProtocol;

  //
  // Enable lock of legacy SPI static configuration information.
  //

  SpiProtocol = LocateSpiProtocol (NULL);  // This routine will not be called in SMM.
  ASSERT_EFI_ERROR (SpiProtocol != NULL);
  if (SpiProtocol != NULL) {
    Status = SpiProtocol->Lock (SpiProtocol);

    if (!EFI_ERROR (Status)) {
      DEBUG ((EFI_D_INFO, "Platform: Spi Config Locked Down\n"));
    } else if (Status == EFI_ACCESS_DENIED) {
      DEBUG ((EFI_D_INFO, "Platform: Spi Config already locked down\n"));
    } else {
      ASSERT_EFI_ERROR (Status);
    }
  }
}

/**
  Lock regions and config of SPI flash given the policy for this platform.

  Function will assert if unable to lock regions or config.

  @param   PreBootPolicy    If TRUE do Pre Boot Flash Lock Policy.

**/
VOID
EFIAPI
PlatformFlashLockPolicy (
  IN CONST BOOLEAN                        PreBootPolicy
  )
{
  EFI_PLATFORM_TYPE_PROTOCOL        *PlatformType;
  EFI_STATUS                        Status;
  UINT64                            CpuAddressNvStorage;
  UINT64                            CpuAddressRmu;
  UINT64                            CpuAddressFixedRecovery;
  UINT64                            CpuAddressFlashDevice;
  UINT64                            SpiAddress;
  EFI_BOOT_MODE                     BootMode;
  UINT32                            ProtectLength;

  ProtectLength = 0;
  BootMode = GetBootModeHob ();

  Status = gBS->LocateProtocol (&gEfiPlatformTypeProtocolGuid, NULL, (VOID **) &PlatformType);
  ASSERT_EFI_ERROR (Status);

  CpuAddressFlashDevice = SIZE_4GB - ((UINT64) PlatformType->FlashDeviceSize);
  DEBUG (
      (EFI_D_INFO,
      "Platform:FlashDeviceSize = 0x%08x Bytes\n",
      (UINTN) PlatformType->FlashDeviceSize)
      );

  //
  // Lock regions if Secure lock down.
  //

  if (QuarkCheckSecureLockBoot()) {

    CpuAddressNvStorage = (UINT64) PcdGet32 (PcdFlashNvStorageBase);

    //
    // Lock from start of flash device up to Smi writable flash storage areas.
    //
    SpiAddress = 0;
    if (!PlatformIsSpiRangeProtected ((UINT32) SpiAddress, (UINT32) (CpuAddressNvStorage - CpuAddressFlashDevice))) {
      DEBUG (
        (EFI_D_INFO,
        "Platform: Protect Region Base:Len 0x%08x:0x%08x\n",
        (UINTN) SpiAddress, (UINTN)(CpuAddressNvStorage - CpuAddressFlashDevice))
        );
      Status = PlatformWriteFirstFreeSpiProtect (
                 0,
                 (UINT32) SpiAddress,
                 (UINT32) (CpuAddressNvStorage - CpuAddressFlashDevice)
                 );

      ASSERT_EFI_ERROR (Status);
    }
    //
    // Move Spi Address to after Smi writable flash storage areas.
    //
    SpiAddress = CpuAddressNvStorage - CpuAddressFlashDevice;
    SpiAddress += ((UINT64) PcdGet32 (PcdFlashNvStorageSize)) + ((UINT64) FLASH_REGION_OEM_NV_STORAGE_SIZE);

    //
    // Lock from end of OEM area to end of flash part.
    //
    if (!PlatformIsSpiRangeProtected ((UINT32) SpiAddress, PlatformType->FlashDeviceSize - ((UINT32) SpiAddress))) {
      DEBUG (
        (EFI_D_INFO,
        "Platform: Protect Region Base:Len 0x%08x:0x%08x\n",
        (UINTN) SpiAddress,
        (UINTN) (PlatformType->FlashDeviceSize - ((UINT32) SpiAddress)))
        );
      ASSERT (SpiAddress < ((UINT64) PlatformType->FlashDeviceSize));
      Status = PlatformWriteFirstFreeSpiProtect (
                 0,
                 (UINT32) SpiAddress,
                 PlatformType->FlashDeviceSize - ((UINT32) SpiAddress)
                 );

      ASSERT_EFI_ERROR (Status);
    }
  } else {

    //
    // Lock consecutive areas RMU, MFH & Platform data.
    //

    ProtectLength = PcdGet32 (PcdPlatformDataBaseAddress) + (PcdGet32 (PcdPlatformDataMaxLen));
    ProtectLength -= FLASH_REGION_RMU_BASE_ADDRESS;
    CpuAddressRmu = FLASH_REGION_RMU_BASE_ADDRESS;

    SpiAddress = CpuAddressRmu - CpuAddressFlashDevice;
    if (!PlatformIsSpiRangeProtected ((UINT32) SpiAddress, ProtectLength)) {
      DEBUG (
          (EFI_D_INFO,
          "Platform: Protect Region Base:Len 0x%08x:0x%08x\n",
          (UINTN) SpiAddress, (UINTN) ProtectLength)
          );
      Status = PlatformWriteFirstFreeSpiProtect (
                 0,
                 (UINT32) SpiAddress,
                 ProtectLength
                 );
      ASSERT_EFI_ERROR (Status);
    }

    //
    // Move Spi Address to beginning of Fixed Recovery area.
    //
    CpuAddressFixedRecovery = (UINT64) PcdGet32 (PcdFlashFvFixedStage1AreaBase);
    SpiAddress = CpuAddressFixedRecovery - CpuAddressFlashDevice;

    //
    // Lock from Fixed Recovery area to end of flash, covering fixed recovery
    // and rom override.
    //
    ProtectLength = (UINT32) (SIZE_4GB - CpuAddressFixedRecovery);
    if (!PlatformIsSpiRangeProtected ((UINT32) SpiAddress, ProtectLength)) {
      DEBUG (
          (EFI_D_INFO,
          "Platform: Protect Region Base:Len 0x%08x:0x%08x\n",
          (UINTN) SpiAddress,
          (UINTN) ProtectLength)
          );
      ASSERT (SpiAddress < ((UINT64) PlatformType->FlashDeviceSize));
      Status = PlatformWriteFirstFreeSpiProtect (
                 0,
                 (UINT32) SpiAddress,
                 ProtectLength
                 );

      ASSERT_EFI_ERROR (Status);
    }
  }

  //
  // Always Lock flash config registers if about to boot a boot option
  // else lock depending on boot mode.
  //
  if (PreBootPolicy || (BootMode != BOOT_ON_FLASH_UPDATE)) {
    PlatformFlashLockConfig ();
  }
}

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
  )
{
  EFI_STATUS                        Status;
  UINT64                            CpuBaseAddress;
  SPI_INIT_INFO                     *SpiInfo;
  UINT8                             *WriteBuf;
  UINTN                             Index;
  UINTN                             SpiWriteAddress;
  EFI_SPI_PROTOCOL                  *SpiProtocol;

  if (!DoErase && !DoWrite) {
    return EFI_INVALID_PARAMETER;
  }
  if (DoWrite && Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if ((CpuWriteAddress % FLASH_BLOCK_SIZE) != 0) {
    return EFI_INVALID_PARAMETER;
  }
  if ((DataSize % FLASH_BLOCK_SIZE) != 0) {
    return EFI_INVALID_PARAMETER;
  }
  SpiProtocol = LocateSpiProtocol ((EFI_SMM_SYSTEM_TABLE2 *)Smst);
  if (SpiProtocol == NULL) {
    return EFI_NOT_READY;
  }

  //
  // Find info to allow usage of SpiProtocol->Execute.
  //
  Status = SpiProtocol->Info (
             SpiProtocol,
             &SpiInfo
             );
  if (EFI_ERROR(Status)) {
    return Status;
  }
  ASSERT (SpiInfo->InitTable != NULL);
  ASSERT (SpiInfo->EraseOpcodeIndex < SPI_NUM_OPCODE);
  ASSERT (SpiInfo->ProgramOpcodeIndex < SPI_NUM_OPCODE);

  CpuBaseAddress = PcdGet32 (PcdFlashAreaBaseAddress) - (UINT32)SpiInfo->InitTable->BiosStartOffset;
  ASSERT(CpuBaseAddress >= (SIZE_4GB - SIZE_8MB));
  if (CpuWriteAddress < CpuBaseAddress) {
    return (EFI_INVALID_PARAMETER);
  }

  SpiWriteAddress = CpuWriteAddress - ((UINTN) CpuBaseAddress);
  WriteBuf = Data;
  DEBUG (
    (EFI_D_INFO, "PlatformFlashWrite:SpiWriteAddress=%08x EraseIndex=%d WriteIndex=%d\n", 
    SpiWriteAddress,
    (UINTN) SpiInfo->EraseOpcodeIndex,
    (UINTN) SpiInfo->ProgramOpcodeIndex
    ));
  for (Index =0; Index < DataSize / FLASH_BLOCK_SIZE; Index++) {
    if (DoErase) {
      DEBUG (
        (EFI_D_INFO, "PlatformFlashWrite:Erase[%04x] SpiWriteAddress=%08x\n",
        Index,
        SpiWriteAddress
        ));
      Status = SpiProtocol->Execute (
                              SpiProtocol,
                              SpiInfo->EraseOpcodeIndex,// OpcodeIndex
                              0,                        // PrefixOpcodeIndex
                              FALSE,                    // DataCycle
                              TRUE,                     // Atomic
                              FALSE,                    // ShiftOut
                              SpiWriteAddress,          // Address
                              0,                        // Data Number
                              NULL,
                              EnumSpiRegionAll          // SPI_REGION_TYPE
                              );
      if (EFI_ERROR(Status)) {
        return Status;
      }
    }

    if (DoWrite) {
      DEBUG (
        (EFI_D_INFO, "PlatformFlashWrite:Write[%04x] SpiWriteAddress=%08x\n",
        Index,
        SpiWriteAddress
        ));
      Status = SpiProtocol->Execute (
                              SpiProtocol,
                              SpiInfo->ProgramOpcodeIndex,   // OpcodeIndex
                              0,                             // PrefixOpcodeIndex
                              TRUE,                          // DataCycle
                              TRUE,                          // Atomic
                              TRUE,                          // ShiftOut
                              SpiWriteAddress,               // Address
                              FLASH_BLOCK_SIZE,              // Data Number
                              WriteBuf,
                              EnumSpiRegionAll
                              );
      if (EFI_ERROR(Status)) {
        return Status;
      }
      WriteBuf+=FLASH_BLOCK_SIZE;
    }
    SpiWriteAddress+=FLASH_BLOCK_SIZE;
  }
  return EFI_SUCCESS;
}

/** Check if System booted with recovery Boot Stage1 image.

  @retval  TRUE    If system booted with recovery Boot Stage1 image.
  @retval  FALSE   If system booted with normal stage1 image.

**/
BOOLEAN
EFIAPI
PlatformIsBootWithRecoveryStage1 (
  VOID
  )
{
  ASSERT_EFI_ERROR (EFI_UNSUPPORTED);
  return FALSE;
}

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
  )
{
  PLATFORM_VARIABLE_TABLE_ENTRY     *Entry;
  PLATFORM_VARIABLE_TABLE_ENTRY     *Found;
  UINTN                             Index;

  if (Table == NULL || VendorGuid == NULL) {
    return NULL;
  }
  if (VendorGlobalEntryPtr != NULL) {
    *VendorGlobalEntryPtr = NULL;
  }
  Found = NULL;
  Entry = (PLATFORM_VARIABLE_TABLE_ENTRY *) Table;
  for (Index = 0; Index < TableLen; Index++, Entry++) {
    //
    // Check current entry matches vendor guid we are searching for.
    //
    if (CompareGuid(Entry->VendorGuid, VendorGuid)) {
      //
      // Check if vendor global entry, ie entry in table is for all
      // variables of the same vendor.
      //
      if (Entry->VariableName == NULL || VariableName == NULL) {
        if (Entry->VariableName == NULL && VendorGlobalEntryPtr != NULL) {
          //
          // Return to caller vendor global entry if caller is looking for it.
          //
          *VendorGlobalEntryPtr = Entry;  // Table has vendor global entry.
          //
          // If caller wants both a specific entry and vendor global entry
          // then return if we have found everything.
          //
          if (Found != NULL) {
            break;  // We were waiting for vendor global so we can now return.
          }
        }
        if (VariableName == NULL) {
          Found = Entry;  // Caller only wants a vendor global entry so return.
          break;
        }

        //
        // One of the name vars == NULL so skip strcmp.
        //
        continue;
      }

      //
      // Check if we have found the specific entry that the caller wants.
      //
      if (StrCmp (Entry->VariableName, VariableName) == 0) {
        Found = Entry;
        if (VendorGlobalEntryPtr == NULL) {
          break; // Caller not interested in finding VendorGlobal goto return
        }
        // continue until we also find VendorGlobal entry.
      }
    }
  }
  return Found;
}

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
  )
{
  EFI_STATUS                        Status;
  CHAR16                            *VariableName;
  UINTN                             NameSize;
  UINT64                            MaxVarSize;
  EFI_GUID                          VendorGuid;
  PLATFORM_VARIABLE_TABLE_ENTRY     *FoundSpecific;
  PLATFORM_VARIABLE_TABLE_ENTRY     *FoundVendorGlobalEntry;
  BOOLEAN                           Result;

  ASSERT (Table != NULL);

  MaxVarSize = EFI_PAGE_SIZE;
  NameSize = (UINTN) MaxVarSize;
  VariableName = AllocateZeroPool(NameSize);
  ASSERT (VariableName != NULL);

  StrCpy(VariableName, L"");  // Tell variable services to start browsing.
  FoundVendorGlobalEntry = NULL;
  Result = FALSE;
  do {
    NameSize = (UINTN)MaxVarSize;
    Status = gRT->GetNextVariableName(&NameSize, VariableName, &VendorGuid);
    if (Status == EFI_NOT_FOUND){
      break;
    }
    if (!EFI_ERROR(Status)) {
      FoundSpecific = PlatformFindVariableTableEntry (
                        Table,
                        TablenLen,
                        &VendorGuid,
                        VariableName,
                        &FoundVendorGlobalEntry
                        );
      if (FoundSpecific != NULL || FoundVendorGlobalEntry != NULL) {
        //
        // TRUE if this var is in table or
        // TRUE if any variable with VendorGuid in Variable Store.
        //
        Result = TRUE;
        break;
      }
    }
  } while (TRUE);
  FreePool (VariableName);
  return Result;
}

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
  )
{
  EFI_STATUS                        Status;
  CHAR16                            *VariableName;
  UINTN                             NameSize;
  UINT64                            MaxVarSize;
  EFI_GUID                          VendorGuidBuf;
  EFI_GUID                          *VendorGuid;
  PLATFORM_VARIABLE_TABLE_ENTRY     *FoundSpecific;
  PLATFORM_VARIABLE_TABLE_ENTRY     *FoundVendorGlobalEntry;
  UINTN                             DataSize;
  UINT32                            Attr;
  UINTN                             DeleteCount;
  PLATLIB_DATA_POOL                 *MultiVariableNameList;
  PLATLIB_DATA_POOL                 *MultiVendorGuidList;
  UINT8                             *VariableNamePosition;

  if (DeleteCountPtr != NULL) {
    *DeleteCountPtr = 0;
  }
  if (MaintainCountPtr != NULL) {
    *MaintainCountPtr = 0;
  }

  Status = EFI_SUCCESS;
  DeleteCount = 0;
  MultiVariableNameList = NULL;
  MultiVendorGuidList = NULL;
  VariableNamePosition = NULL;

  MaxVarSize = EFI_PAGE_SIZE;
  NameSize = (UINTN)MaxVarSize;
  VariableName = AllocateZeroPool(NameSize);
  ASSERT (VariableName != NULL);
  StrCpy(VariableName, L"");
  FoundVendorGlobalEntry = NULL;
  VendorGuid = &VendorGuidBuf;

  //
  // Not possible to delete variable within a gRT->GetNextVariableName
  // loop so need to save names/guids for later deletion.
  //
  do {
    NameSize = (UINTN) MaxVarSize;
    Status = gRT->GetNextVariableName(&NameSize, VariableName, VendorGuid);
    if (Status == EFI_NOT_FOUND){
      Status = EFI_SUCCESS; // End of list and tell next part ok to delete.
      break;
    }
    if (EFI_ERROR(Status)) {
      break;
    }
    if (MaintainTable != NULL) {
      //
      // See if variable is in an maintain table and if yes don't
      // delete and goto next.
      //
      FoundSpecific = PlatformFindVariableTableEntry (
                        MaintainTable,
                        MaintainTableLen,
                        VendorGuid,
                        VariableName,
                        &FoundVendorGlobalEntry
                        );
      if (FoundSpecific != NULL || FoundVendorGlobalEntry != NULL) {

        if (MaintainCountPtr != NULL) {
          //
          // Update maintain count if caller wants that info.
          //
          *MaintainCountPtr = *MaintainCountPtr + 1;
        }
        continue;  // Variable in Maintain table so don't delete.
      }
    }
    //
    // This variable can be deleted, insert variable specifiers in multi list
    // so it can be deleted in delete loop.
    //
    if (PlatformMultiStringInsert (&MultiVariableNameList, VariableName) == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
    }
    if (PlatformMultiGuidInsert (&MultiVendorGuidList, VendorGuid) == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
    }
  } while (TRUE);
  FreePool (VariableName);

  //
  // Now Delete the variables using info saved in multi lists.
  //
  if (!EFI_ERROR(Status) && MultiVariableNameList != NULL && MultiVendorGuidList != NULL) {
    VendorGuid = (EFI_GUID *) MultiVendorGuidList->Data;  // First variable vendor guid.
    VariableNamePosition =  MultiVariableNameList->Data;
    VariableName = (CHAR16 *) VariableNamePosition;  // First variable name.
    //
    // Loop until we find the null string terminator in the variable name list.
    //
    while (VariableName[0] != L'\0') {
      DataSize = 0;
      Status = gRT->GetVariable (
                      VariableName,
                      VendorGuid,
                      &Attr,
                      &DataSize,
                      (VOID *) NULL
                      );
      if (EFI_ERROR(Status) && Status != EFI_BUFFER_TOO_SMALL) {
        ASSERT_EFI_ERROR (Status);  // Should not happen if GetNext was OK.
      }
      //
      // Delete this variable.
      //
      Status = gRT->SetVariable (
                      VariableName,
                      VendorGuid,
                      0,
                      0,
                      (VOID *) NULL
                      );
      if (Status == EFI_WRITE_PROTECTED) {
        DEBUG ((EFI_D_WARN, "Unable to delete ReadOnly Variable '%s'\n", VariableName));

        //
        // Can't delete write protected variables so continue in success state.
        //
        Status = EFI_SUCCESS;

        if (MaintainCountPtr != NULL) {
          *MaintainCountPtr = *MaintainCountPtr + 1;
        }
      } else {
        ASSERT_EFI_ERROR (Status);
        DeleteCount++;
      }
      //
      // Move on to next variable specified by multistring & multi guid lists.
      //
      VariableNamePosition += StrSize (VariableName);
      VariableName = (CHAR16 *) VariableNamePosition;
      VendorGuid++;
    }
    //
    // Return not found error if no variables deleted or success if variables
    // deleted.
    //
    Status = (DeleteCount == 0) ? EFI_NOT_FOUND : EFI_SUCCESS;
  }
  if (DeleteCountPtr != NULL) {
    //
    // Update delete count if caller wants that info.
    //
    *DeleteCountPtr = DeleteCount;
  }
  if (MultiVariableNameList) {
    FreePool (MultiVariableNameList);
  }
  if (MultiVendorGuidList) {
    FreePool (MultiVendorGuidList);
  }
  return Status;
}

/** Append Data to a PlatLib DataPool.

  @param   PoolPtr        Data PoolPtr if *PoolPtr = NULL allocate new pool.
  @param   AppendData     Data to append to data pool.
  @param   DataLen        Byte size of memory pointed to by AppendData.
  @param   Terminator     Optional terminator eg NULL char for
                          multistrings, NULL DevicePath for
                          multi device paths or 16byte NULL GUID
                          for multi guid list.
  @param   TerminatorLen  Byte size Terminator data.

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
  )
{
  UINTN                             AddLen;
  UINTN                             DescLen;
  UINTN                             ReallocByteCnt;
  UINT8                             *Dest;
  UINT8                             *Alloc;
  PLATLIB_DATA_POOL                 *Pool;

  if (PoolPtr == NULL || AppendData == NULL || DataLen == 0) {
    return NULL;
  }
  DescLen = sizeof (PLATLIB_DATA_POOL);
  AddLen = DataLen + TerminatorLen;
  Pool = *PoolPtr;

  //
  // First call to append for this pool, allocate initial pool.
  //
  if (Pool == NULL) {
    Alloc = AllocateZeroPool (EFI_PAGE_SIZE);
    *PoolPtr = (PLATLIB_DATA_POOL *) Alloc;
    Pool = *PoolPtr;
    if (Pool == NULL) {
      ASSERT (FALSE);
      return NULL;
    }
    Pool->Data = Alloc + DescLen;
    Pool->Cnt = 0;
    Pool->Len = 0;
    Pool->MaxLen = (UINT64) (EFI_PAGE_SIZE - DescLen);
  }
  //
  // Check if current pool has enough space for item to append.
  //
  if ((Pool->Len + AddLen) > Pool->MaxLen) {
    //
    // Need to realloc a bigger pool given this append.
    //
    ReallocByteCnt = (DescLen + (UINTN) Pool->Len + AddLen) / EFI_PAGE_SIZE;
    ReallocByteCnt += 1;  // Now have number of pages.
    ReallocByteCnt *= EFI_PAGE_SIZE;  // Now number of bytes so lets get them.
    Alloc = ReallocatePool (
              DescLen + ((UINTN)Pool->MaxLen),
              ReallocByteCnt,
              Pool
              );
    if (Alloc == NULL) {
      ASSERT (FALSE);
      return NULL;
    }
    *PoolPtr = (PLATLIB_DATA_POOL *) Alloc;
    Pool = *PoolPtr;
    Pool->MaxLen = (UINT64) (ReallocByteCnt - DescLen);
    Pool->Data = Alloc + DescLen;
  }
  Dest = Pool->Data + Pool->Len;

  //
  // Append item.
  //
  CopyMem (Dest, AppendData, DataLen);
  Pool->Len += (UINT64) DataLen;
  Pool->Cnt = Pool->Cnt + 1;
  if (Terminator && TerminatorLen) {
    //
    // This pool has a terminator eg for multistr, multiguid lists etc.
    //
    Pool->TermLen = (UINT64) TerminatorLen;
    CopyMem (&Dest[DataLen], Terminator, TerminatorLen);
  }
  //
  // return pointer to appended element in pool.
  //
  return Dest;
}

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
  IN OUT PLATLIB_DATA_POOL                  **MultiStrList,
  IN CHAR16                               *InsertString
  )
{
  CHAR16 Terminator;
  Terminator = L'\0';

  if (InsertString == NULL) {
    return NULL;
  }
  return (CHAR16 *) PlatformDataPoolAppend (
                      MultiStrList,
                      (UINT8 *) InsertString,
                      StrSize (InsertString),
                      (UINT8 *) &Terminator,
                      sizeof (Terminator)
                      );
}

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
  )
{
  EFI_GUID Terminator;

  SetMem (&Terminator, sizeof (EFI_GUID), 0);
  if (InsertGuid == NULL) {
    return NULL;
  }
  return (EFI_GUID *) PlatformDataPoolAppend (
                        MultiGuidList,
                        (UINT8 *) InsertGuid,
                        sizeof (EFI_GUID),
                        (UINT8 *) &Terminator,
                        sizeof (EFI_GUID)
                        );
}

/**
  Signal guid named events shown in 5.1.1 of PI Spec.

  @param   EventName    Guid named event to signal.

  @return one of EFI_CREATE_EVENT_EX service return values.

**/
EFI_STATUS
EFIAPI
PlatformSignalGuidNamedEvent (
  IN CONST EFI_GUID                       *EventName
  )
{
  EFI_STATUS    Status;
  EFI_EVENT     Event;

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  EmptyEventFunction,  // Only signalling, use empty function.
                  NULL,
                  EventName,
                  &Event
                  );

  if (!EFI_ERROR (Status)) {
    gBS->SignalEvent (Event);
    gBS->CloseEvent (Event);
  }
  return Status;
}
