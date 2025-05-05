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

  DxeCapsuleSecurity.c

Abstract:

  Quark capsule security routines.

--*/

#include "PlatformInitDxe.h"

#define  MAX_STAGE1_IN_MFH                MAX_IMAGES_PER_CAPSULE

//
// Hint PriorityElement
//
typedef struct {
  UINT32              FlashAddress;
  BOOLEAN             FixedAddress;
  UINTN               ImageLimit;
  UINT32              MfhType;
  MFH_FLASH_ITEM      **MfhItemList;
} HINT_PRIORITY;

MFH_FLASH_ITEM                      *mStage1MfhList[MAX_STAGE1_IN_MFH];
UINT32                              mNumberStage1InMfh;
MFH_FLASH_ITEM                      *mStage2MfhItem;

//
// Priority of images to update, Recovery must always be in list and also
// must be 1st image in list.
//
HINT_PRIORITY                       mPriorityHintList [] = {
  //FixedBaseAddress                                FixedAddress  ImageLimit MfhType                               MfhItemList
   {FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase),  TRUE,         0,         MFH_FLASH_ITEM_TYPE_INVALID,          NULL}
  ,{FLASH_REGION_PLATFORM_DATA_BASE_ADDRESS,        TRUE,         0,         MFH_FLASH_ITEM_TYPE_INVALID,          NULL}
  ,{FLASH_REGION_BIOS_NV_STORAGE_BASE,              TRUE,         0,         MFH_FLASH_ITEM_TYPE_INVALID,          NULL}
  ,{FLASH_REGION_MFH_BASE_ADDRESS,                  TRUE,         0,         MFH_FLASH_ITEM_TYPE_INVALID,          NULL}
  ,{0,                                              FALSE,        0,         MFH_FLASH_ITEM_TYPE_FW_STAGE1_SIGNED, NULL}
  ,{0,                                              FALSE,        0,         MFH_FLASH_ITEM_TYPE_FW_STAGE2_SIGNED, NULL}
};
UINTN                               mPriorityHintListSize;

//
// Routines local to this source module.
//

STATIC
VOID
ReadCurrentSvnArray (
  OUT UINT32                              *SvnArrayBuffer
  )
{
  CopyMem (
    SvnArrayBuffer,
    (VOID *) FLASH_REGION_SVN_BASE_ADDRESS,
    sizeof(UINT32) * QUARK_SVN_ARRAY_SIZE
    );
}

STATIC
EFI_STATUS
ValidateCriticalPlatformDataItems (
  IN  PDAT_AREA                           *PdatArea
  )
{
  PDAT_ITEM                         *Item;
  UINT16                            Type;
  PDAT_MRC_ITEM                     *MrcItemData;

  //
  // For now check we have enough for MRC to run so we can at least
  // recover the platform!
  //
  Type = (EFI_PLATFORM_TYPE) 0;
  Item = PDatLibFindItem (PdatArea, PDAT_ITEM_ID_PLATFORM_ID, FALSE, &Type);
  if (Item == NULL) {
     return EFI_NOT_FOUND;
  }

  if (!PlatformIsSupportedPlatformType ((EFI_PLATFORM_TYPE) Type)) {
    return EFI_UNSUPPORTED;
  }

  Item = PDatLibFindItem (PdatArea, PDAT_ITEM_ID_MRC_VARS, TRUE, NULL);
  if (Item == NULL) {
    return EFI_NOT_FOUND;
  }

  if (Item->Header.Version < PDAT_MRC_MIN_VERSION) {
    return EFI_INCOMPATIBLE_VERSION;
  }

  MrcItemData = (PDAT_MRC_ITEM *) Item->Data;

  //
  // Check PDAT_ITEM_ID_PLATFORM_ID & PDAT_ITEM_ID_MRC_VARS in sync.
  //
  if (Type != MrcItemData->PlatformId) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

STATIC
QuarkSecurityHeader_t *
FindCapsuleSecurityHeader (
  IN EFI_CAPSULE_HEADER                   *CapsuleHeader
  )
{
  EFI_HOB_GUID_TYPE                 *SecurityHeaderHob;

  SecurityHeaderHob = GetFirstGuidHob (&gEfiQuarkCapsuleSecurityHeaderGuid);
  if (SecurityHeaderHob != NULL) {
    return (QuarkSecurityHeader_t *) GET_GUID_HOB_DATA (SecurityHeaderHob);
  }

  return NULL;
}

STATIC
UINT8 *
CreateCapsuleBufferForWriting (
  IN UINT8                                *Capsule
  )
{
  UINT8                             *SignedCapsule;
  UINTN                             TempSize;
  EFI_CAPSULE_HEADER                *CapsuleHeader;
  QuarkSecurityHeader_t             *QuarkCapsuleSecHdr;
  UINTN                             SecHdrSize;

  SecHdrSize = (UINTN) FixedPcdGet32 (PcdFvSecurityHeaderSize);
  CapsuleHeader = (EFI_CAPSULE_HEADER *) Capsule;
  QuarkCapsuleSecHdr = (QuarkSecurityHeader_t *) (Capsule - SecHdrSize);

  TempSize =
    SecHdrSize +
    CapsuleHeader->HeaderSize +
    CapsuleHeader->CapsuleImageSize;

  SignedCapsule = AllocatePool (TempSize);
  if (SignedCapsule == NULL) {
    return NULL;
  }

  if (QuarkCapsuleSecHdr->CSH_Identifier == QUARK_CSH_IDENTIFIER && QuarkCapsuleSecHdr->SecurityVersionNumberIndex == QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE) {
    CopyMem (SignedCapsule, (UINT8 *) QuarkCapsuleSecHdr, TempSize);
  } else {
    TempSize -= SecHdrSize;
    CopyMem (&SignedCapsule[SecHdrSize], Capsule, TempSize);
    QuarkCapsuleSecHdr = FindCapsuleSecurityHeader (CapsuleHeader);
    if (QuarkCapsuleSecHdr != NULL) {
      CopyMem (SignedCapsule, (UINT8 *) QuarkCapsuleSecHdr, SecHdrSize);
    } else {
      ZeroMem (SignedCapsule, SecHdrSize);
    }
  }

  return SignedCapsule;
}

STATIC
VOID
SwapHint (
  IN UPDATE_HINT                          *Hint1,
  IN UPDATE_HINT                          *Hint2
  )
{
  UPDATE_HINT                       TempHint;

  if (Hint1 == Hint2) {
    return;
  }
  TempHint.TargetAddr = Hint1->TargetAddr;
  TempHint.Size = Hint1->Size;
  TempHint.SourceOffset = Hint1->SourceOffset;
  TempHint.Reserved = Hint1->Reserved;

  Hint1->TargetAddr = Hint2->TargetAddr;
  Hint1->Size = Hint2->Size;
  Hint1->SourceOffset = Hint2->SourceOffset;
  Hint1->Reserved = Hint2->Reserved;

  Hint2->TargetAddr = TempHint.TargetAddr;
  Hint2->Size = TempHint.Size;
  Hint2->SourceOffset = TempHint.SourceOffset;
  Hint2->Reserved = TempHint.Reserved;
}

STATIC
UINTN
MoveUpNextProrityElement (
  IN UPDATE_HINT                          *HintPos,
  IN UINTN                                HintsLeft,
  IN OUT UINTN                            *PriorityPosition
  )
{
  UINTN                             Index;
  UPDATE_HINT                       *HintToCheck;
  UINTN                             ImageLimit;
  UINTN                             HintPosIdx;
  HINT_PRIORITY                     *PriorityEle;
  UINTN                             MfhIndex;
  MFH_FLASH_ITEM                    *MfhItemList;

  HintPosIdx = 0;
  HintToCheck = HintPos;
  MfhIndex = 0;
  ImageLimit = 0;
  MfhItemList = NULL;

  //
  // Find next prioity element whose images need to be moved up.
  //
  while (*PriorityPosition < mPriorityHintListSize) {
    if (mPriorityHintList[*PriorityPosition].ImageLimit > 0) {
      ImageLimit = mPriorityHintList[*PriorityPosition].ImageLimit;
      break;
    }
    //
    // Priority Element not in capsule, try next.
    //
    *PriorityPosition = *PriorityPosition + 1;
  }
  //
  // Reached end of priority list, nothing to do.
  //
  if (*PriorityPosition == mPriorityHintListSize) {
    return 0;
  }
  PriorityEle = &mPriorityHintList[*PriorityPosition];
  if (PriorityEle->MfhItemList != NULL) {
    MfhItemList = *(PriorityEle->MfhItemList);
  }

  //
  // Move up images for priority element.
  //
  for (Index = 0; Index < HintsLeft && HintPosIdx < ImageLimit; Index++) {
    if (PriorityEle->FixedAddress) {
      if (PriorityEle->FlashAddress == HintToCheck[Index].TargetAddr) {
        SwapHint (&HintPos[HintPosIdx], &HintToCheck[Index]);
        HintPosIdx++;
        break;
      }
      continue;
    }
    if (MfhItemList != NULL && MfhIndex < PriorityEle->ImageLimit) {
      if (MfhItemList[MfhIndex].FlashAddress == HintToCheck[Index].TargetAddr) {
        SwapHint (&HintPos[HintPosIdx], &HintToCheck[Index]);
        MfhIndex++;
        HintPosIdx++;
      }
    }
  }

  *PriorityPosition = *PriorityPosition + 1;
  return HintPosIdx;
}

STATIC
HINT_PRIORITY *
CheckFixedInPriorityList (
  IN UPDATE_HINT                          *UpdateHint
  )
{
  UINTN                             Index;

  for (Index = 0; Index < mPriorityHintListSize; Index++) {
    if (mPriorityHintList[Index].FixedAddress == FALSE) {
      continue;
    }
    if (UpdateHint->TargetAddr == mPriorityHintList[Index].FlashAddress) {
      return &mPriorityHintList[Index];
    }
  }
  return NULL;
}

STATIC
EFI_STATUS
SetMfhGlobals (
  IN MFH_HEADER                           *MfhHeader
  )
{
  MFH_FLASH_ITEM                    *FlashItem;
  MFH_LIB_FINDCONTEXT               FindContext;

  mNumberStage1InMfh = 0;
  mStage2MfhItem = NULL;

  FlashItem = MfhLibFindFirstWithFilter (
                MfhHeader,
                MFH_FIND_ALL_SIGNED_STAGE1_STAGE2_FILTER,
                FALSE,
                &FindContext
                );
  while (FlashItem != NULL) {
    if (FlashItem->Type == MFH_FLASH_ITEM_TYPE_FW_STAGE2_SIGNED) {
      if (mStage2MfhItem != NULL) {
        //
        // Only support 1 Stage2 in MFH.
        //
        return EFI_UNSUPPORTED;
      }
      mStage2MfhItem = FlashItem;
    } else {
      if (FlashItem->FlashAddress != FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase)) {
        mStage1MfhList [mNumberStage1InMfh] = FlashItem;
        mNumberStage1InMfh++;
      }
    }
    FlashItem = MfhLibFindNextWithFilter (
                  MFH_FIND_ALL_SIGNED_STAGE1_STAGE2_FILTER,
                  &FindContext
                  );
  }
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
IsMfhStage1TargetAddress (
  IN CONST UINT32 TargetAddr
  )
{
  UINTN                             Index;

  for (Index =0; Index < mNumberStage1InMfh; Index++) {
    if (mStage1MfhList [Index]->FlashAddress == TargetAddr) {
      return TRUE;
    }
  }
  return FALSE;
}

STATIC
EFI_STATUS
UefiSecureBootCapsulePolicy (
  IN CONST BOOLEAN                        NvRamInCapsule,
  OUT BOOLEAN                             *NvramUpdatable,
  IN OUT PDAT_AREA                        *PdatAddress
  )
{
  EFI_STATUS                        Status;
  EFI_PLATFORM_TYPE_PROTOCOL        *PlatformType;
  UINTN                             NumberOfVarsMaintained;

  NumberOfVarsMaintained = 0;

  Status = gBS->LocateProtocol (&gEfiPlatformTypeProtocolGuid, NULL, (VOID **) &PlatformType);
  ASSERT_EFI_ERROR (Status);

  //
  // If
  // running recoveryDXE image (No NVRAM variable drivers in recoveryDXE image)
  // then
  // Return now and allow NVRAM to be updated.
  //
  if (PlatformType->BootingRecoveryDxe) {
    *NvramUpdatable = TRUE;
    return EFI_SUCCESS;
  }
  //
  // If UEFI Secure Boot disabled return now and allow NVRAM to be updated.
  //
  if (!QuarkIsUefiSecureBootEnabled()) {
    *NvramUpdatable = TRUE;
    return EFI_SUCCESS;
  }

  //
  // We are here with UEFI Secure boot enabled so NVRAM is not allowed
  // to be completely rewritten.
  //
  *NvramUpdatable = FALSE;

  if (NvRamInCapsule) {
    //
    // Maintain variables in current SpiFlash NVRAM that are listed
    // in SecureBoot Maintain Variable table.
    //
    Status = QuarkMaintainSecureBootVariables (&NumberOfVarsMaintained);

    //
    // If UEFI Secure Boot enabled the NumberOfVarsMaintained must be
    // greater then 0.
    //
    ASSERT (NumberOfVarsMaintained > 0);
  }

  //
  // See if PdatAddress has any UEFI Secure Boot keys to be exchanged.
  //
  if (PdatAddress != NULL) {
    QuarkAutoProvisionSecureBoot (PdatAddress);
  }

  return Status;
}

//
// Routines exported by this source module.
//

/** Capsule Security routine.

  This routine if returns success will always return a new capsule buffer that
  the capsule writer should use to program the flash. Caller must free this
  buffer when flash written.

  Given capsule buffer to validate this function will:
    1) Copy capsule for programming into a new buffer.
    2) Verify capsule properly signed.
    3) Do basic sanity checks on capsule images, especially MFH.
    4) Return with the new capsule buffer if not on secure sku HW.
    5) Verify Capsule embedded images have Svn Value >= Current Value.
    6) Return new Svn Area data if Svn Area needs to be updated.
    7) Inform caller when Svn Area has to be updated.
    8) Check that fixed Svn Index rules not broken by capsule embedded images.
    9) Do authentication of capsule images if relevant key known.
    10) Place update hints for critical embedded images first in hint array,
        recovery image always 1st image to be programmed.
    11) Do UEFI Secure boot capsule policy.
    12) If MFH in capsule then return offset to Mfh in capsule.
    13) Return pointer to capsule buffer to be programmed.

  @param[in out]   CapsulePtr           On input pointer to capsule to validate,
                                        on output pointer to capsule to program.
                                        Caller must free buffer.
  @param[out]      MfhSourceOffset      Offset to New Mfh in capsule.
  @param[out]      NewSvnArray          Caller allocated memory to receive new
                                        Svn Array.
  @param[out]      SvnAreaUpdPoint      When to update Svn Array,
                                        see SVN_UPDATE_POINT enum def.
  @param[out]      SvnAreaUpdTrigAddr   If SvnAreaUpdPoint==SvnUpdAtTrigAddr
                                        then update Svn area when this addr
                                        reached in capsule.
  @param[out]      NvramUpdatable       Set to TRUE if NVRAM is updatable.

  @retval EFI_SUCCESS           Capsule & SvnArray ok to be written.
  @retval EFI_INVALID_PARAMETER Function param or internal capsule data invalid.
  @retval EFI_UNSUPPORTED       Unsupported images found in capsule.
  @retval EFI_OUT_OF_RESOURCES  Not enough memory to complete operation.
  @retval EFI_VOLUME_CORRUPTED  Corrupted data found in capsule.

**/
EFI_STATUS
EFIAPI
PlatformCapsuleSecurity (
  IN UINT8                                **CapsulePtr,
  OUT UINTN                               *MfhSourceOffset,
  IN OUT UINT32                           *NewSvnArray,
  OUT SVN_UPDATE_POINT                    *SvnAreaUpdPoint,
  OUT UINT32                              *SvnAreaUpdTrigAddr,
  OUT BOOLEAN                             *NvramUpdatable
  )
{
  EFI_STATUS                        Status;
  MFH_HEADER                        *UseMfhHeader;
  UINTN                             Index;
  UPDATE_HINT                       *UpdateHint;
  EFI_CAPSULE_HEADER                *CapsuleHeader;
  HINT_PRIORITY                     *Stage1PriorityEle;
  HINT_PRIORITY                     *Stage2PriorityEle;
  UINT8                             *DataToWrite;
  QuarkSecurityHeader_t             *ImageSecHdr;
  UINTN                             UpdateHintCount;
  UINTN                             PriorityPosition;
  QuarkSecurityHeader_t             *QuarkCapsuleSecHdr;
  UINTN                             TargetAddr;
  UINTN                             SecHdrSize;
  UINTN                             SvnIndex;
  HINT_PRIORITY                     *CurrPriorityEle;
  UINT32                            SvnArray[QUARK_SVN_ARRAY_SIZE];
  UINT8                             *SignedCapsule;
  BOOLEAN                           Stage3PlusImage;
  BOOLEAN                           ValidMfhInCapsule;
  BOOLEAN                           SvnArrayUpdated;
  BOOLEAN                           SvnRecoveryUpdated;
  EFI_PLATFORM_TYPE_PROTOCOL        *PlatformType;
  BOOLEAN                           NvRamInCapsule;
  PDAT_AREA                         *PdatAddress;

  if (CapsulePtr == NULL || MfhSourceOffset == NULL || NvramUpdatable == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (SvnArray == NULL || SvnAreaUpdPoint == NULL || SvnAreaUpdTrigAddr == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Init locals.
  //
  UseMfhHeader = NULL;
  Stage1PriorityEle = NULL;
  Stage2PriorityEle = NULL;
  SvnIndex = 0;
  TargetAddr = 0;
  CurrPriorityEle = NULL;
  SvnArrayUpdated = FALSE;
  SvnRecoveryUpdated = FALSE;
  UpdateHintCount = 0;
  Stage3PlusImage = FALSE;
  NvRamInCapsule = FALSE;
  PdatAddress = NULL;

  Status = gBS->LocateProtocol (&gEfiPlatformTypeProtocolGuid, NULL, (VOID **) &PlatformType);
  ASSERT_EFI_ERROR (Status);

  //
  // Reset globals.
  //
  mPriorityHintListSize = sizeof(mPriorityHintList) / sizeof(HINT_PRIORITY);
  mNumberStage1InMfh = 0;
  mStage2MfhItem = NULL;

  //
  // Set Default output values.
  //
  *SvnAreaUpdPoint = SvnUpdNever;  // Assume Svn does not need to be updated.
  *SvnAreaUpdTrigAddr = 0;         // Invalid addr since SvnUpdNever assumed.
  *MfhSourceOffset = 0;            // Assume no Mfh In Capsule.
  *NvramUpdatable = FALSE;         // By default expect NVRAM not to be updateable.

  //
  // Copy capsule into signed area.
  //
  SignedCapsule = CreateCapsuleBufferForWriting (*CapsulePtr);
  if (SignedCapsule == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  *CapsulePtr = SignedCapsule;

  //
  // Init local derived from CreateCapsuleBufferForWriting.
  //
  SecHdrSize = FixedPcdGet32 (PcdFvSecurityHeaderSize);
  CapsuleHeader = (EFI_CAPSULE_HEADER *) &SignedCapsule[SecHdrSize];
  QuarkCapsuleSecHdr = (QuarkSecurityHeader_t *) SignedCapsule;

  //
  // From here if we fail then free SignedCapsule.
  //

  //
  // Read current Svn Array stored in flash.
  //
  ReadCurrentSvnArray (SvnArray);

  //
  // Verify capsule properly signed.
  //
  Status = SecurityAuthenticateImage (
             (VOID *) CapsuleHeader,
             NULL,
             TRUE,
             NULL,
             (QUARK_AUTH_ALLOC_POOL) AllocatePool,
             FreePool
             );
  if (EFI_ERROR(Status)) {
    FreePool (SignedCapsule);
    return Status;
  }

  //
  // Clear ImageLimit fields in mPriorityHintList;
  // Set pointers to stage1 & stage2 Priority hint elements.
  //
  for (Index = 0; Index < mPriorityHintListSize; Index++) {
    mPriorityHintList[Index].ImageLimit = 0;
    if (mPriorityHintList[Index].MfhType == MFH_FLASH_ITEM_TYPE_FW_STAGE1_SIGNED) {
      Stage1PriorityEle = &mPriorityHintList[Index];
    }
    if (mPriorityHintList[Index].MfhType == MFH_FLASH_ITEM_TYPE_FW_STAGE2_SIGNED) {
      Stage2PriorityEle = &mPriorityHintList[Index];
    }
  }

  //
  // 1st pass:-
  //  1) Get Hint Count
  //  2) Change UseMfhHeader if MFH in capsule.
  //  3) Check for known UNSUPPORTED images in capsules.
  //  4) Set ImageLimit to 1 in mPriorityHintList for Fixed address
  //     flash areas found in capsule.
  //  5) Do basic validation on MFH & platform data capsule sub images
  //     if found.
  //
  UpdateHint  = (UPDATE_HINT *) ((UINT8 *) CapsuleHeader + CapsuleHeader->HeaderSize);
  while (UpdateHint->Size != 0x00) {
    DataToWrite = ((UINT8*) CapsuleHeader + UpdateHint->SourceOffset);

    if (UpdateHint->TargetAddr == FLASH_REGION_QUARK_KEY_MODULE_BASE_ADDRESS) {
      //
      // Security policy doesn't support updateing signed key module.
      //
      Status = EFI_UNSUPPORTED;
      break;
    }

    if (UpdateHint->TargetAddr == FLASH_REGION_SVN_BASE_ADDRESS) {
      //
      // Security policy doesn't support merging with SvnArea in capsule.
      //
      Status = EFI_UNSUPPORTED;
      break;
    }

    if (UpdateHint->TargetAddr == FLASH_REGION_MFH_BASE_ADDRESS) {
      if (UseMfhHeader != NULL) {
        //
        // Should only be one MFH in capsule.
        //
        Status = EFI_INVALID_PARAMETER;
      }
      ValidMfhInCapsule = MfhLibValidateMfhBaseAddress (
                            (CONST UINT32) DataToWrite,
                            &UseMfhHeader,
                            NULL,
                            NULL,
                            NULL
                            );
      if (ValidMfhInCapsule == FALSE) {
        Status = EFI_VOLUME_CORRUPTED;
        break;
      }
      *MfhSourceOffset = UpdateHint->SourceOffset;
    }
    CurrPriorityEle = CheckFixedInPriorityList (UpdateHint);
    if (CurrPriorityEle) {
      if (CurrPriorityEle->ImageLimit > 0) {
        //
        // Should only be one Hint for priority hint element at fixed flash addresses.
        //
        Status = EFI_INVALID_PARAMETER;
        break;
      }
      //
      // Tell later reorder code to expect this image.
      //
      CurrPriorityEle->ImageLimit = 1;
    }

    if (UpdateHint->TargetAddr == FLASH_REGION_BIOS_NV_STORAGE_BASE) {
      NvRamInCapsule = TRUE;
    }

    if (UpdateHint->TargetAddr == FLASH_REGION_PLATFORM_DATA_BASE_ADDRESS) {
      PdatAddress = (PDAT_AREA *) DataToWrite;
      //
      // Validate struct.
      //
      Status = PDatLibValidateArea (PdatAddress, TRUE);
      if (EFI_ERROR(Status)) {
        Status = EFI_VOLUME_CORRUPTED;
        break;
      }
      //
      // Validate critical items.
      //
      Status = ValidateCriticalPlatformDataItems (PdatAddress);
      if (EFI_ERROR(Status)) {
        Status = EFI_INVALID_PARAMETER;
        break;
      }
    }

    UpdateHintCount++;
    UpdateHint++;
  }

  if (!EFI_ERROR(Status)) {
    //
    // If no hints return error.
    //
    if (UpdateHintCount == 0) {
      Status = EFI_INVALID_PARAMETER;
    } else {

      //
      // Not allowed to use SpiFlash Mfh if recovering SpiFlash!
      // so fail if no Mfh in Capsule on this condition.
      //
      if (UseMfhHeader == NULL && PlatformType->BootingRecoveryDxe) {
        Status = EFI_INVALID_PARAMETER;
      } else {
        //
        // Update MFH Information for future passes and validation.
        //
        Status = SetMfhGlobals (UseMfhHeader);
      }
    }
  }

  if (EFI_ERROR(Status)) {
    FreePool (SignedCapsule);
    return Status;
  }

  //
  // No need to update SVN Array or reorder hints if unprovisioned sku.
  //
  if (QncIsSecureProvisionedSku() == FALSE) {
    DEBUG ((EFI_D_INFO, "CapsuleSecurity SVN Update not Required on Un Provisioned Sku\n"));
    Status = EFI_SUCCESS;
  } else {

    //
    // Checking SVN values, Authenticating images & reordering hints only done
    // secure Soc skus.
    //

    //
    // Update capsule Svn.
    //
    if (QuarkCapsuleSecHdr->CSH_Identifier == QUARK_CSH_IDENTIFIER) {
      if (QuarkCapsuleSecHdr->SecurityVersionNumberIndex != QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE) {
        Status = EFI_UNSUPPORTED;
      }

      if (QuarkCapsuleSecHdr->SecurityVersionNumber > SvnArray [QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE]) {
        SvnArrayUpdated = TRUE;

        SvnArray [QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE] =
          QuarkCapsuleSecHdr->SecurityVersionNumber;
      }
    }

    //
    // Reset UpdateHint for future passes of HintList.
    //
    UpdateHint = (UPDATE_HINT *) ((UINT8 *) CapsuleHeader + CapsuleHeader->HeaderSize);

    //
    // 2nd pass:- Update Svn Array for capsule images as well as
    // validation of signed flash areas.
    //
    for (Index = 0; !EFI_ERROR (Status) && Index < UpdateHintCount; Index++) {
      TargetAddr = UpdateHint[Index].TargetAddr;
      //
      // Skip known unsigned data areas.
      //
      if (TargetAddr == FLASH_REGION_BIOS_NV_STORAGE_BASE || TargetAddr == FLASH_REGION_MFH_BASE_ADDRESS || TargetAddr == FLASH_REGION_PLATFORM_DATA_BASE_ADDRESS) {
        continue;
      }

      //
      // Reset vars. for this hint.
      //
      DataToWrite = ((UINT8*) CapsuleHeader + UpdateHint[Index].SourceOffset);
      ImageSecHdr = (QuarkSecurityHeader_t *) DataToWrite;

      //
      // Only update Svn if we have a Quark Security Header in image.
      //
      if (ImageSecHdr->CSH_Identifier != QUARK_CSH_IDENTIFIER) {
        continue;  // Not a signed image
      }
      Stage3PlusImage = FALSE;  // We don't expect Stage3 or later images by default.
      SvnIndex = ImageSecHdr->SecurityVersionNumberIndex;

      //
      // Validate Svn Index.
      //
      if (SvnIndex >= QUARK_FIXED_SVN_INDEX_CAPSULE_IMAGE) {
          Status = EFI_INVALID_PARAMETER;
      } else if (TargetAddr == FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase)) {
        if (SvnIndex != QUARK_FIXED_SVN_INDEX_RECOVERY_IMAGE) {
          Status = EFI_INVALID_PARAMETER;
        }
      } else if (IsMfhStage1TargetAddress (TargetAddr)) {
        //
        // Check valid index for stage1.
        //
        if (SvnIndex != QUARK_FIXED_SVN_INDEX_STAGE1_IMAGE) {
          Status = EFI_INVALID_PARAMETER;
        }
      } else {
        //
        // Check Svn Index valid for all other images.
        //
        if (SvnIndex <= QUARK_FIXED_SVN_INDEX_RECOVERY_IMAGE) {
          Status = EFI_INVALID_PARAMETER;
        }

        //
        // Check if we have a Stage3 or later signed asset.
        //
        if (mStage2MfhItem == NULL || TargetAddr != mStage2MfhItem->FlashAddress) {
          Stage3PlusImage = TRUE;
        }
      } 
      if (EFI_ERROR (Status)) {
        break;
      }

      if (Stage3PlusImage) {
        //
        // Quark requires signed images to be in Mfh.
        //
        if (MfhLibFindForFlashAddress(UseMfhHeader, TargetAddr) == NULL) {
          Status = EFI_UNSUPPORTED;
        }
        //
        // Do Multiple key support Authentication of non EDKII firmware images.
        //
      } else {
        //
        // Authenticate Stage1 or Stage2 image.
        //
        Status = SecurityAuthenticateImage (
                   (VOID *) &DataToWrite [SecHdrSize],
                   NULL,
                   TRUE,
                   NULL,
                   (QUARK_AUTH_ALLOC_POOL) AllocatePool,
                   FreePool
                   );
      }

      //
      // Final checks before updateing Svn Array.
      //
      if (!EFI_ERROR (Status) && ImageSecHdr->SecurityVersionNumber != SvnArray [SvnIndex]) {
        if (ImageSecHdr->SecurityVersionNumber < SvnArray [SvnIndex]) {
          Status = EFI_SECURITY_VIOLATION;  // Attempt to rollback.
        } else {
          SvnArray [SvnIndex] = ImageSecHdr->SecurityVersionNumber;
          SvnArrayUpdated = TRUE;
          if (TargetAddr == FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase)) {
            SvnRecoveryUpdated = TRUE;
          }
        }
      }
    }

    if (EFI_ERROR(Status)) {
      FreePool (SignedCapsule);
    } else {
      //
      // 3rd Pass Reorder Hints given mPriorityHintList.
      //
      if (Stage1PriorityEle != NULL) {
        Stage1PriorityEle->MfhItemList = mStage1MfhList;
        Stage1PriorityEle->ImageLimit = mNumberStage1InMfh;
      }
      if (Stage2PriorityEle != NULL && mStage2MfhItem != NULL) {
        Stage2PriorityEle->MfhItemList = &mStage2MfhItem;
        Stage2PriorityEle->ImageLimit = 1;
      }
      PriorityPosition = 0;
      Index = 0;
      while (PriorityPosition < mPriorityHintListSize && Index < (UpdateHintCount - 1)) {
        Index += MoveUpNextProrityElement (
                   &UpdateHint[Index],
                   UpdateHintCount - Index,
                   &PriorityPosition
                   );
      }

      //
      // Update caller's svn array buffer and tell caller when to write Svn Array.
      //
      if (!SvnArrayUpdated) {
        *SvnAreaUpdPoint = SvnUpdNever;
      } else {
        CopyMem (NewSvnArray, SvnArray, sizeof(SvnArray));
        if (SvnRecoveryUpdated) {
          //
          // Recovery image should always be 1st image to update.
          //
          ASSERT (UpdateHint[0].TargetAddr == FixedPcdGet32 (PcdFlashFvFixedStage1AreaBase));

          //
          // Recovery image in capsule with new Svn Value. Update Svn Array after
          // recovery image so that if fail after Svn Update the target can be
          // recovered.
          //
          if (UpdateHintCount == 1) {
            *SvnAreaUpdPoint = SvnUpdAtEnd; // Only recovery in capsule.
          } else {
            //
            // Update Svn before updateing image after recovery.
            //
            *SvnAreaUpdPoint = SvnUpdAtTrigAddr;
            *SvnAreaUpdTrigAddr = UpdateHint[1].TargetAddr;
          }
        } else {
          //
          // No recovery Svn Value change so update Svn Array 1st. If fail
          // recovery image can still run. Recovery will only recover flash
          // using the latest images.
          //
          *SvnAreaUpdPoint = SvnUpdAtStart;
        }
      }
    }
  }

  if (!EFI_ERROR(Status)) {
    Status = UefiSecureBootCapsulePolicy (
               NvRamInCapsule,
               NvramUpdatable,
               PdatAddress
               );
  }

  return Status;
}
