/** @file
  PCI Rom supporting funtions implementation for PCI Bus module.

Copyright (c) 2006 - 2012, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "PciBus.h"

/**
  Load the EFI Image from Option ROM

  @param PciIoDevice   PCI IO device instance.
  @param FilePath      The file path of the EFI Image
  @param BufferSize    On input the size of Buffer in bytes. On output with a return
                       code of EFI_SUCCESS, the amount of data transferred to Buffer.
                       On output with a return code of EFI_BUFFER_TOO_SMALL,
                       the size of Buffer required to retrieve the requested file.
  @param Buffer        The memory buffer to transfer the file to. If Buffer is NULL,
                       then no the size of the requested file is returned in BufferSize.

  @retval EFI_SUCCESS           The file was loaded.
  @retval EFI_INVALID_PARAMETER FilePath is not a valid device path, or
                                BufferSize is NULL.
  @retval EFI_NOT_FOUND         Not found PCI Option Rom on PCI device.
  @retval EFI_DEVICE_ERROR      Failed to decompress PCI Option Rom image.
  @retval EFI_BUFFER_TOO_SMALL  The BufferSize is too small to read the current directory entry.
                                BufferSize has been updated with the size needed to complete the request.
**/
EFI_STATUS
LocalLoadFile2 (
  IN PCI_IO_DEVICE            *PciIoDevice,
  IN EFI_DEVICE_PATH_PROTOCOL *FilePath,
  IN OUT UINTN                *BufferSize,
  IN VOID                     *Buffer      OPTIONAL
  )
{
  EFI_STATUS                                Status;
  MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH   *EfiOpRomImageNode;
  EFI_PCI_EXPANSION_ROM_HEADER              *EfiRomHeader;
  PCI_DATA_STRUCTURE                        *Pcir;
  UINT32                                    ImageSize;
  UINT8                                     *ImageBuffer;
  UINT32                                    ImageLength;
  UINT32                                    DestinationSize;
  UINT32                                    ScratchSize;
  VOID                                      *Scratch;
  EFI_DECOMPRESS_PROTOCOL                   *Decompress;
  UINT32                                    InitializationSize;

  EfiOpRomImageNode = (MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH *) FilePath;
  if ((EfiOpRomImageNode == NULL) ||
      (DevicePathType (FilePath) != MEDIA_DEVICE_PATH) ||
      (DevicePathSubType (FilePath) != MEDIA_RELATIVE_OFFSET_RANGE_DP) ||
      (DevicePathNodeLength (FilePath) != sizeof (MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH)) ||
      (!IsDevicePathEnd (NextDevicePathNode (FilePath))) ||
      (EfiOpRomImageNode->StartingOffset > EfiOpRomImageNode->EndingOffset) ||
      (EfiOpRomImageNode->EndingOffset >= PciIoDevice->RomSize) ||
      (BufferSize == NULL)
      ) {
    return EFI_INVALID_PARAMETER;
  }

  EfiRomHeader = (EFI_PCI_EXPANSION_ROM_HEADER *) (
      (UINT8 *) PciIoDevice->PciIo.RomImage + EfiOpRomImageNode->StartingOffset
      );
  if (EfiRomHeader->Signature != PCI_EXPANSION_ROM_HEADER_SIGNATURE) {
    return EFI_NOT_FOUND;
  }


  Pcir = (PCI_DATA_STRUCTURE *) ((UINT8 *) EfiRomHeader + EfiRomHeader->PcirOffset);
  ASSERT (Pcir->Signature == PCI_DATA_STRUCTURE_SIGNATURE);

  if ((Pcir->CodeType == PCI_CODE_TYPE_EFI_IMAGE) &&
      (EfiRomHeader->EfiSignature == EFI_PCI_EXPANSION_ROM_HEADER_EFISIGNATURE) &&
      ((EfiRomHeader->EfiSubsystem == EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) ||
       (EfiRomHeader->EfiSubsystem == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER)) &&
      (EfiRomHeader->CompressionType <= EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED)
       ) {

    ImageSize = Pcir->ImageLength * 512;
    InitializationSize = (UINT32) EfiRomHeader->InitializationSize * 512;
    if (InitializationSize > ImageSize || EfiRomHeader->EfiImageHeaderOffset >=  InitializationSize) {
      return EFI_NOT_FOUND;
    }

    ImageBuffer             = (UINT8 *) EfiRomHeader + EfiRomHeader->EfiImageHeaderOffset;
    ImageLength             = InitializationSize - EfiRomHeader->EfiImageHeaderOffset;

    if (EfiRomHeader->CompressionType != EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED) {
      //
      // Uncompressed: Copy the EFI Image directly to user's buffer
      //
      if (Buffer == NULL || *BufferSize < ImageLength) {
        *BufferSize = ImageLength;
        return EFI_BUFFER_TOO_SMALL;
      }

      *BufferSize = ImageLength;
      CopyMem (Buffer, ImageBuffer, ImageLength);
      return EFI_SUCCESS;

    } else {
      //
      // Compressed: Uncompress before copying
      //
      Status = gBS->LocateProtocol (&gEfiDecompressProtocolGuid, NULL, (VOID **) &Decompress);
      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }
      Status = Decompress->GetInfo (
                             Decompress,
                             ImageBuffer,
                             ImageLength,
                             &DestinationSize,
                             &ScratchSize
                             );
      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }

      if (Buffer == NULL || *BufferSize < DestinationSize) {
        *BufferSize = DestinationSize;
        return EFI_BUFFER_TOO_SMALL;
      }

      *BufferSize = DestinationSize;
      Scratch = AllocatePool (ScratchSize);
      if (Scratch == NULL) {
        return EFI_DEVICE_ERROR;
      }

      Status = Decompress->Decompress (
                             Decompress,
                             ImageBuffer,
                             ImageLength,
                             Buffer,
                             DestinationSize,
                             Scratch,
                             ScratchSize
                             );
      FreePool (Scratch);

      if (EFI_ERROR (Status)) {
        return EFI_DEVICE_ERROR;
      }
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Initialize a PCI LoadFile2 instance.

  @param PciIoDevice   PCI IO Device.

**/
VOID
InitializePciLoadFile2 (
  IN PCI_IO_DEVICE       *PciIoDevice
  )
{
  PciIoDevice->LoadFile2.LoadFile = LoadFile2;
}

/**
  Causes the driver to load a specified file.

  @param This        Indicates a pointer to the calling context.
  @param FilePath    The device specific path of the file to load.
  @param BootPolicy  Should always be FALSE.
  @param BufferSize  On input the size of Buffer in bytes. On output with a return
                     code of EFI_SUCCESS, the amount of data transferred to Buffer.
                     On output with a return code of EFI_BUFFER_TOO_SMALL,
                     the size of Buffer required to retrieve the requested file.
  @param Buffer      The memory buffer to transfer the file to. If Buffer is NULL,
                     then no the size of the requested file is returned in BufferSize.

  @retval EFI_SUCCESS           The file was loaded.
  @retval EFI_UNSUPPORTED       BootPolicy is TRUE.
  @retval EFI_INVALID_PARAMETER FilePath is not a valid device path, or
                                BufferSize is NULL.
  @retval EFI_NOT_FOUND         Not found PCI Option Rom on PCI device.
  @retval EFI_DEVICE_ERROR      Failed to decompress PCI Option Rom image.
  @retval EFI_BUFFER_TOO_SMALL  The BufferSize is too small to read the current directory entry.
                                BufferSize has been updated with the size needed to complete the request.

**/
EFI_STATUS
EFIAPI
LoadFile2 (
  IN EFI_LOAD_FILE2_PROTOCOL  *This,
  IN EFI_DEVICE_PATH_PROTOCOL *FilePath,
  IN BOOLEAN                  BootPolicy,
  IN OUT UINTN                *BufferSize,
  IN VOID                     *Buffer      OPTIONAL
  )
{
  PCI_IO_DEVICE                             *PciIoDevice;

  if (BootPolicy) {
    return EFI_UNSUPPORTED;
  }
  PciIoDevice = PCI_IO_DEVICE_FROM_LOAD_FILE2_THIS (This);

  return LocalLoadFile2 (
           PciIoDevice,
           FilePath,
           BufferSize,
           Buffer
           );
}

/**
  Get Pci device's oprom information.

  @param PciIoDevice    Input Pci device instance.
                        Output Pci device instance with updated OptionRom size.

  @retval EFI_NOT_FOUND Pci device has not Option Rom.
  @retval EFI_SUCCESS   Pci device has Option Rom.

**/
EFI_STATUS
GetOpRomInfo (
  IN OUT PCI_IO_DEVICE    *PciIoDevice
  )
{
  UINT8                           RomBarIndex;
  UINT32                          AllOnes;
  UINT64                          Address;
  EFI_STATUS                      Status;
  UINT8                           Bus;
  UINT8                           Device;
  UINT8                           Function;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *PciRootBridgeIo;

  Bus             = PciIoDevice->BusNumber;
  Device          = PciIoDevice->DeviceNumber;
  Function        = PciIoDevice->FunctionNumber;

  PciRootBridgeIo = PciIoDevice->PciRootBridgeIo;

  //
  // Offset is 0x30 if is not ppb
  //

  //
  // 0x30
  //
  RomBarIndex = PCI_EXPANSION_ROM_BASE;

  if (IS_PCI_BRIDGE (&PciIoDevice->Pci)) {
    //
    // If is ppb, 0x38
    //
    RomBarIndex = PCI_BRIDGE_ROMBAR;
  }
  //
  // The bit0 is 0 to prevent the enabling of the Rom address decoder
  //
  AllOnes = 0xfffffffe;
  Address = EFI_PCI_ADDRESS (Bus, Device, Function, RomBarIndex);

  Status = PciRootBridgeIo->Pci.Write (
                                  PciRootBridgeIo,
                                  EfiPciWidthUint32,
                                  Address,
                                  1,
                                  &AllOnes
                                  );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  //
  // Read back
  //
  Status = PciRootBridgeIo->Pci.Read(
                                  PciRootBridgeIo,
                                  EfiPciWidthUint32,
                                  Address,
                                  1,
                                  &AllOnes
                                  );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  //
  // Bits [1, 10] are reserved
  //
  AllOnes &= 0xFFFFF800;
  if ((AllOnes == 0) || (AllOnes == 0xFFFFF800)) {
    return EFI_NOT_FOUND;
  }

  PciIoDevice->RomSize = (UINT64) ((~AllOnes) + 1);
  DEBUG ((EFI_D_INFO, "GetOpRomInfo: ROM Size = 0x%llx", PciIoDevice->RomSize));
  DEBUG ((EFI_D_INFO, "GetOpRomInfo: ROM Size = 0x%llx", PciIoDevice->RomSize));
  return EFI_SUCCESS;
}

/**
  Load Option Rom image for specified PCI device.

  @param PciDevice Pci device instance.
  @param RomBase   Base address of Option Rom.

  @retval EFI_OUT_OF_RESOURCES No enough memory to hold image.
  @retval EFI_SUCESS           Successfully loaded Option Rom.

**/
EFI_STATUS
LoadOpRomImage (
  IN PCI_IO_DEVICE   *PciDevice,
  IN UINT64          RomBase
  )
{
  UINT8                     RomBarIndex;
  UINT8                     Indicator;
  UINT16                    OffsetPcir;
  UINT32                    RomBarOffset;
  UINT32                    RomBar;
  EFI_STATUS                RetStatus;
  BOOLEAN                   FirstCheck;
  UINT8                     *Image;
  PCI_EXPANSION_ROM_HEADER  *RomHeader;
  PCI_DATA_STRUCTURE        *RomPcir;
  UINT64                    RomSize;
  UINT64                    RomImageSize;
  UINT32                    LegacyImageLength;
  UINT8                     *RomInMemory;
  UINT8                     CodeType;
  BOOLEAN                   HasEfiOpRom;

  RomSize       = PciDevice->RomSize;

  Indicator     = 0;
  RomImageSize  = 0;
  RomInMemory   = NULL;
  CodeType      = 0xFF;

  //
  // Get the RomBarIndex
  //

  //
  // 0x30
  //
  RomBarIndex = PCI_EXPANSION_ROM_BASE;
  if (IS_PCI_BRIDGE (&(PciDevice->Pci))) {
    //
    // if is ppb
    //

    //
    // 0x38
    //
    RomBarIndex = PCI_BRIDGE_ROMBAR;
  }
  //
  // Allocate memory for Rom header and PCIR
  //
  RomHeader = AllocatePool (sizeof (PCI_EXPANSION_ROM_HEADER));
  if (RomHeader == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  RomPcir = AllocatePool (sizeof (PCI_DATA_STRUCTURE));
  if (RomPcir == NULL) {
    FreePool (RomHeader);
    return EFI_OUT_OF_RESOURCES;
  }

  RomBar = (UINT32) RomBase;

  //
  // Enable RomBar
  //
  RomDecode (PciDevice, RomBarIndex, RomBar, TRUE);

  RomBarOffset  = RomBar;
  RetStatus     = EFI_NOT_FOUND;
  FirstCheck    = TRUE;
  LegacyImageLength = 0;
  HasEfiOpRom   = FALSE;

  do {
    PciDevice->PciRootBridgeIo->Mem.Read (
                                      PciDevice->PciRootBridgeIo,
                                      EfiPciWidthUint8,
                                      RomBarOffset,
                                      sizeof (PCI_EXPANSION_ROM_HEADER),
                                      (UINT8 *) RomHeader
                                      );

    if (RomHeader->Signature != PCI_EXPANSION_ROM_HEADER_SIGNATURE) {
      RomBarOffset = RomBarOffset + 512;
      if (FirstCheck) {
        break;
      } else {
        RomImageSize = RomImageSize + 512;
        continue;
      }
    }

    FirstCheck  = FALSE;
    OffsetPcir  = RomHeader->PcirOffset;
    //
    // If the pointer to the PCI Data Structure is invalid, no further images can be located. 
    // The PCI Data Structure must be DWORD aligned. 
    //
    if (OffsetPcir == 0 ||
        (OffsetPcir & 3) != 0 ||
        RomImageSize + OffsetPcir + sizeof (PCI_DATA_STRUCTURE) > RomSize) {
      break;
    }
    PciDevice->PciRootBridgeIo->Mem.Read (
                                      PciDevice->PciRootBridgeIo,
                                      EfiPciWidthUint8,
                                      RomBarOffset + OffsetPcir,
                                      sizeof (PCI_DATA_STRUCTURE),
                                      (UINT8 *) RomPcir
                                      );
    //
    // If a valid signature is not present in the PCI Data Structure, no further images can be located.
    //
    if (RomPcir->Signature != PCI_DATA_STRUCTURE_SIGNATURE) {
      break;
    }
    if (RomImageSize + RomPcir->ImageLength * 512 > RomSize) {
      break;
    }
    if (RomPcir->CodeType == PCI_CODE_TYPE_PCAT_IMAGE) {
      CodeType = PCI_CODE_TYPE_PCAT_IMAGE;
      LegacyImageLength = ((UINT32)((EFI_LEGACY_EXPANSION_ROM_HEADER *)RomHeader)->Size512) * 512;
    } else if (RomPcir->CodeType == PCI_CODE_TYPE_EFI_IMAGE) {
      HasEfiOpRom = TRUE;
    }
    Indicator     = RomPcir->Indicator;
    RomImageSize  = RomImageSize + RomPcir->ImageLength * 512;
    RomBarOffset  = RomBarOffset + RomPcir->ImageLength * 512;
  } while (((Indicator & 0x80) == 0x00) && ((RomBarOffset - RomBar) < RomSize));

  //
  // Some Legacy Cards do not report the correct ImageLength so used the maximum
  // of the legacy length and the PCIR Image Length
  //
  if (CodeType == PCI_CODE_TYPE_PCAT_IMAGE) {
    RomImageSize = MAX (RomImageSize, LegacyImageLength);
  }

  if (RomImageSize > 0) {
    RetStatus = EFI_SUCCESS;
    Image     = AllocatePool ((UINT32) RomImageSize);
    if (Image == NULL) {
      RomDecode (PciDevice, RomBarIndex, RomBar, FALSE);
      FreePool (RomHeader);
      FreePool (RomPcir);
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Copy Rom image into memory
    //
    PciDevice->PciRootBridgeIo->Mem.Read (
                                      PciDevice->PciRootBridgeIo,
                                      EfiPciWidthUint8,
                                      RomBar,
                                      (UINT32) RomImageSize,
                                      Image
                                      );
    RomInMemory = Image;
  }

  RomDecode (PciDevice, RomBarIndex, RomBar, FALSE);

  PciDevice->HasEfiOpRom    = HasEfiOpRom;
  PciDevice->EmbeddedRom    = TRUE;
  PciDevice->PciIo.RomSize  = RomImageSize;
  PciDevice->PciIo.RomImage = RomInMemory;

  //
  // For OpROM read from PCI device:
  //   Add the Rom Image to internal database for later PCI light enumeration
  //
  PciRomAddImageMapping (
    NULL,
    PciDevice->PciRootBridgeIo->SegmentNumber,
    PciDevice->BusNumber,
    PciDevice->DeviceNumber,
    PciDevice->FunctionNumber,
    (UINT64) (UINTN) PciDevice->PciIo.RomImage,
    PciDevice->PciIo.RomSize
    );

  //
  // Free allocated memory
  //
  FreePool (RomHeader);
  FreePool (RomPcir);

  return RetStatus;
}

/**
  Enable/Disable Option Rom decode.

  @param PciDevice    Pci device instance.
  @param RomBarIndex  The BAR index of the standard PCI Configuration header to use as the
                      base address for resource range. The legal range for this field is 0..5.
  @param RomBar       Base address of Option Rom.
  @param Enable       Flag for enable/disable decode.

**/
VOID
RomDecode (
  IN PCI_IO_DEVICE   *PciDevice,
  IN UINT8           RomBarIndex,
  IN UINT32          RomBar,
  IN BOOLEAN         Enable
  )
{
  UINT32              Value32;
  UINT32              Offset;
  UINT32              OffsetMax;
  EFI_PCI_IO_PROTOCOL *PciIo;

  PciIo = &PciDevice->PciIo;
  if (Enable) {
    //
    // Clear all bars
    //
    OffsetMax = 0x24;
    if (IS_PCI_BRIDGE(&PciDevice->Pci)) {
      OffsetMax = 0x14;
    }

    for (Offset = 0x10; Offset <= OffsetMax; Offset += sizeof (UINT32)) {
      PciIo->Pci.Write (PciIo, EfiPciIoWidthUint32, Offset, 1, &gAllZero);
    }

    //
    // set the Rom base address: now is hardcode
    // enable its decoder
    //
    Value32 = RomBar | 0x1;
    PciIo->Pci.Write (
                 PciIo,
                 (EFI_PCI_IO_PROTOCOL_WIDTH) EfiPciWidthUint32,
                 RomBarIndex,
                 1,
                 &Value32
                 );

    //
    // Programe all upstream bridge
    //
    ProgrameUpstreamBridgeForRom(PciDevice, RomBar, TRUE);

    //
    // Setting the memory space bit in the function's command register
    //
    PCI_ENABLE_COMMAND_REGISTER(PciDevice, EFI_PCI_COMMAND_MEMORY_SPACE);

  } else {

    //
    // disable command register decode to memory
    //
    PCI_DISABLE_COMMAND_REGISTER(PciDevice, EFI_PCI_COMMAND_MEMORY_SPACE);

    //
    // Destroy the programmed bar in all the upstream bridge.
    //
    ProgrameUpstreamBridgeForRom(PciDevice, RomBar, FALSE);

    //
    // disable rom decode
    //
    Value32 = 0xFFFFFFFE;
    PciIo->Pci.Write (
                 PciIo,
                 (EFI_PCI_IO_PROTOCOL_WIDTH) EfiPciWidthUint32,
                 RomBarIndex,
                 1,
                 &Value32
                 );

  }
}

/**
  Load and start the Option Rom image.

  @param PciDevice       Pci device instance.

  @retval EFI_SUCCESS    Successfully loaded and started PCI Option Rom image.
  @retval EFI_NOT_FOUND  Failed to process PCI Option Rom image.

**/
EFI_STATUS
ProcessOpRomImage (
  IN  PCI_IO_DEVICE   *PciDevice
  )
{
  UINT8                                    Indicator;
  UINT32                                   ImageSize;
  VOID                                     *RomBar;
  UINT8                                    *RomBarOffset;
  EFI_HANDLE                               ImageHandle;
  EFI_STATUS                               Status;
  EFI_STATUS                               RetStatus;
  EFI_PCI_EXPANSION_ROM_HEADER             *EfiRomHeader;
  PCI_DATA_STRUCTURE                       *Pcir;
  EFI_DEVICE_PATH_PROTOCOL                 *PciOptionRomImageDevicePath;
  MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH  EfiOpRomImageNode;
  VOID                                     *Buffer;
  UINTN                                    BufferSize;

  Indicator = 0;

  //
  // Get the Address of the Option Rom image
  //
  RomBar        = PciDevice->PciIo.RomImage;
  RomBarOffset  = (UINT8 *) RomBar;
  RetStatus     = EFI_NOT_FOUND;

  if (RomBar == NULL) {
    return RetStatus;
  }
  ASSERT (((EFI_PCI_EXPANSION_ROM_HEADER *) RomBarOffset)->Signature == PCI_EXPANSION_ROM_HEADER_SIGNATURE);

  do {
    EfiRomHeader = (EFI_PCI_EXPANSION_ROM_HEADER *) RomBarOffset;
    if (EfiRomHeader->Signature != PCI_EXPANSION_ROM_HEADER_SIGNATURE) {
      RomBarOffset += 512;
      continue;
    }

    Pcir        = (PCI_DATA_STRUCTURE *) (RomBarOffset + EfiRomHeader->PcirOffset);
    ASSERT (Pcir->Signature == PCI_DATA_STRUCTURE_SIGNATURE);
    ImageSize   = (UINT32) (Pcir->ImageLength * 512);
    Indicator   = Pcir->Indicator;

    //
    // Skip the image if it is not an EFI PCI Option ROM image
    //
    if (Pcir->CodeType != PCI_CODE_TYPE_EFI_IMAGE) {
      goto NextImage;
    }

    //
    // Skip the EFI PCI Option ROM image if its machine type is not supported
    //
    if (!EFI_IMAGE_MACHINE_TYPE_SUPPORTED (EfiRomHeader->EfiMachineType)) {
      goto NextImage;
    }

    //
    // Ignore the EFI PCI Option ROM image if it is an EFI application
    //
    if (EfiRomHeader->EfiSubsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
      goto NextImage;
    }

    //
    // Create Pci Option Rom Image device path header
    //
    EfiOpRomImageNode.Header.Type     = MEDIA_DEVICE_PATH;
    EfiOpRomImageNode.Header.SubType  = MEDIA_RELATIVE_OFFSET_RANGE_DP;
    SetDevicePathNodeLength (&EfiOpRomImageNode.Header, sizeof (EfiOpRomImageNode));
    EfiOpRomImageNode.StartingOffset  = (UINTN) RomBarOffset - (UINTN) RomBar;
    EfiOpRomImageNode.EndingOffset    = (UINTN) RomBarOffset + ImageSize - 1 - (UINTN) RomBar;

    PciOptionRomImageDevicePath = AppendDevicePathNode (PciDevice->DevicePath, &EfiOpRomImageNode.Header);
    ASSERT (PciOptionRomImageDevicePath != NULL);

    //
    // load image and start image
    //
    BufferSize  = 0;
    Buffer      = NULL;
    ImageHandle = NULL;

    DEBUG ((EFI_D_INFO, "ProcessOpRomImage: Loading image offset 0x%x, size = 0x%x", EfiOpRomImageNode.StartingOffset, ImageSize));
DEBUG ((EFI_D_INFO, "ProcessOpRomImage: LoadImage offset=0x%x size=0x%x", EfiOpRomImageNode.StartingOffset, ImageSize));
Status = gBS->LoadImage (
                    FALSE,
                    gPciBusDriverBinding.DriverBindingHandle,
                    PciOptionRomImageDevicePath,
                    Buffer,
                    BufferSize,
                    &ImageHandle
                    );

    FreePool (PciOptionRomImageDevicePath);

    if (!EFI_ERROR (Status)) {
      Status = gBS->StartImage (ImageHandle, NULL, NULL);
  DEBUG ((EFI_D_INFO, "ProcessOpRomImage: StartImage returned %r", Status));
  if (!EFI_ERROR(Status)) {
    DEBUG ((EFI_D_INFO, "ProcessOpRomImage: Started image for device %02x:%02x.%x", PciDevice->BusNumber, PciDevice->DeviceNumber, PciDevice->FunctionNumber));
  }
      if (!EFI_ERROR (Status)) {
        AddDriver (PciDevice, ImageHandle);
        PciRomAddImageMapping (
          ImageHandle,
          PciDevice->PciRootBridgeIo->SegmentNumber,
          PciDevice->BusNumber,
          PciDevice->DeviceNumber,
          PciDevice->FunctionNumber,
          (UINT64) (UINTN) PciDevice->PciIo.RomImage,
          PciDevice->PciIo.RomSize
          );
        RetStatus = EFI_SUCCESS;
      }
    }

NextImage:
    RomBarOffset += ImageSize;

  } while (((Indicator & 0x80) == 0x00) && ((UINTN) (RomBarOffset - (UINT8 *) RomBar) < PciDevice->RomSize));

  return RetStatus;
}

