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

  PlatformSecureBoot.c

Abstract:

  Implementation of platform UEFI SecureBoot functionality.

--*/

#include "PlatformInitDxe.h"

STATIC EFI_GUID NullGuid = {0x00000000, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
STATIC BOOLEAN  mUefiSecureProvisioningActive = FALSE;

STATIC PLATFORM_VARIABLE_TABLE_ENTRY mSbMaintainVarTable[] = { SECURE_BOOT_MAINTAIN_VARIABLE_TABLE_DEFINITION };
STATIC CONST UINTN                   mSbMaintainVarTableLen = (sizeof(mSbMaintainVarTable) / sizeof(PLATFORM_VARIABLE_TABLE_ENTRY));

//
// Routines defined in other source modules of this component.
//

//
// Routines local to this source module.
//

STATIC
VOID
DeleteAutoProvisionSecureBootItems (
  OUT PDAT_AREA                           *UserPdatArea
  )
{
  EFI_STATUS                        Status;
  PDAT_AREA                         *SrcArea;
  PDAT_AREA                         *NewArea;
  UINT64                            SecureBootItemFilter;
  UINTN                             AreaSize;
  UINTN                             BlockCount;

  SrcArea = UserPdatArea;

  if (SrcArea == NULL) {
    Status = PDatLibGetSystemAreaPointer (TRUE, &SrcArea);

    if (Status == EFI_NOT_FOUND) {
      return;  // Allowed not to have any platform data.
    }
    ASSERT_EFI_ERROR (Status);  // Other errors not allowed.
    ASSERT (SrcArea != NULL);
  }

  //
  // Filter out SecureBoot Items from SrcArea into NewArea.
  //
  AreaSize = sizeof(PDAT_AREA) + SrcArea->Header.Length;
  NewArea = (PDAT_AREA *) AllocateZeroPool (AreaSize + FLASH_BLOCK_SIZE);
  ASSERT (NewArea != NULL);
  SecureBootItemFilter = ((UINT64)
    ((PDAT_ITEM_ID_MASK(PDAT_ITEM_ID_PK)) | (PDAT_ITEM_ID_MASK(PDAT_ITEM_ID_SB_RECORD))
    ));
  Status = PDatLibCopyAreaWithFilterOut (
             NewArea,
             SrcArea,
             SecureBootItemFilter
             );

  ASSERT_EFI_ERROR (Status);
  ASSERT (NewArea->Header.Length <= SrcArea->Header.Length);
  if (NewArea->Header.Length == SrcArea->Header.Length) {
    FreePool (NewArea);
    return;  // Nothing filtered out, return.
  }

  AreaSize = sizeof(PDAT_AREA) + NewArea->Header.Length;

  if (UserPdatArea == NULL) {

    //
    // Write NewArea to system area in flash if UserPdatArea == NULL.
    //

    //
    // Get number of Flash Blocks to Write.
    //
    BlockCount = (AreaSize / FLASH_BLOCK_SIZE);
    if ((AreaSize % FLASH_BLOCK_SIZE) != 0) {
      BlockCount++;
    }

    //
    // Write NewArea to Flash.
    //
    Status = PlatformFlashEraseWrite (
               NULL,
               (UINTN) PcdGet32(PcdPlatformDataBaseAddress),
               (UINT8 *) NewArea,
               BlockCount * FLASH_BLOCK_SIZE,
               TRUE,
               TRUE
               );
    ASSERT_EFI_ERROR (Status);
  } else {
    CopyMem ((UINT8 *) UserPdatArea, (UINT8 *) NewArea, AreaSize);
  }

  FreePool (NewArea);
}

STATIC
UINT8 *
FindPkCert (
  IN PDAT_AREA                            *UserPdatArea,
  IN CONST BOOLEAN                        ExchangingKeys,
  OUT UINTN                               *CertSizePtr
  )
{
  EFI_STATUS                        Status;
  PDAT_AREA                         *Area;
  PDAT_ITEM                         *PKItem;
  EFI_GUID                          *PkX509File;
  UINT8                             *CertData;

  ASSERT (CertSizePtr != NULL);
  CertData = NULL;
  Area = UserPdatArea;

  //
  // Try find Pk certificate in platform data first which takes precedence.
  //

  if (Area == NULL)  {
    //
    // If Area is null use system area in flash.
    // Validate Area with PDatLibGetSystemAreaPointer before using.
    //
    Status = PDatLibGetSystemAreaPointer (TRUE, &Area);
    if (EFI_ERROR (Status)) {
      if (Status == EFI_NOT_FOUND) {
        DEBUG ((EFI_D_INFO, "AutoProvisionSecureBoot: System Platform Data Area Signature not found.\n"));
      } else {
        DEBUG ((EFI_D_ERROR, "AutoProvisionSecureBoot: System Platform Data Area get failed error = %r.\n", Status));
        ASSERT_EFI_ERROR (Status);
      }
    }
  }

  PKItem = PDatLibFindItem (
             Area,  // Lib always uses sys flash area if arg == NULL.
             PDAT_ITEM_ID_PK,
             FALSE,
             NULL
             );
  if (PKItem) {
    ASSERT (PKItem->Header.Length > 0);
    *CertSizePtr = PKItem->Header.Length;
    return PKItem->Data;
  }
  DEBUG ((EFI_D_INFO, "AutoProvisionSecureBoot: PK X509 Public Cert not found in PDAT\n"));

  //
  // Only allow provisioning records in firmware volumes to be used
  // if not exchanging keys ie on 1st provisioning of system.
  //
  if (!ExchangingKeys) {
    return NULL;
  }

  //
  // Finally check to see if cert in Firmware volumes.
  //
  PkX509File = PcdGetPtr(PcdPkX509File);
  if (CompareGuid (&NullGuid, PkX509File) == FALSE) {
    Status = PlatformFindFvFileRawDataSection (
               NULL,
               PkX509File,
               (VOID **) &CertData,
               CertSizePtr
               );

    if (EFI_ERROR (Status)) {
      if (Status != EFI_NOT_FOUND) {
        ASSERT_EFI_ERROR (Status);
        CertData = NULL;
      }
    } else {
      ASSERT (CertData != NULL && *CertSizePtr > 0);
    }
  }

  return CertData;
}

STATIC
VOID
ProvisionFVRecords (
  IN SECUREBOOT_HELPER_PROTOCOL           *SecureBootHelperProtocol
  )
{
  EFI_STATUS                        Status;
  EFI_GUID                          *KekX509File;
  EFI_GUID                          *KekRsa2048File;
  EFI_GUID                          *DbX509File;
  EFI_GUID                          *DbxX509File;
  UINT8                             *CertData;
  UINTN                             CertSize;

  DEBUG ((EFI_D_INFO, ">>ProvisionFVRecords\n"));
  KekX509File = PcdGetPtr(PcdKekX509File);
  if (CompareGuid (&NullGuid, KekX509File) == FALSE) {
    Status = PlatformFindFvFileRawDataSection (
               NULL,
               KekX509File,
               (VOID **) &CertData,
               &CertSize
               );

    if (EFI_ERROR (Status)) {
      if (Status != EFI_NOT_FOUND) {
        ASSERT_EFI_ERROR (Status);
      }
    } else {
      ASSERT (CertData != NULL && CertSize > 0);
      DEBUG ((EFI_D_INFO, "Enroll X509 Cert into KEK 0x%04x:%g\n", CertSize, KekX509File));
      Status = SecureBootHelperProtocol->SetupEnrollX509 (
                 SecureBootHelperProtocol,
                 KEKStore,
                 NULL,
                 CertData,
                 CertSize,
                 KekX509File
                 );
      ASSERT_EFI_ERROR (Status);
    }
  }

  KekRsa2048File = PcdGetPtr(PcdKekRsa2048File);
  if (CompareGuid (&NullGuid, KekRsa2048File) == FALSE) {
    Status = PlatformFindFvFileRawDataSection (
               NULL,
               KekRsa2048File,
               (VOID **) &CertData,
               &CertSize
               );

    if (EFI_ERROR (Status)) {
      if (Status != EFI_NOT_FOUND) {
        ASSERT_EFI_ERROR (Status);
      }
    } else {
      ASSERT (CertData != NULL && CertSize > 0);
      DEBUG ((EFI_D_INFO, "Enroll Rsa2048 storing file (*.pbk) into KEK database 0x%04x:%g\n", CertSize, KekRsa2048File));
      Status = SecureBootHelperProtocol->SetupEnrollKekRsa2048 (
                 SecureBootHelperProtocol,
                 NULL,
                 CertData,
                 CertSize,
                 KekRsa2048File
                 );
      ASSERT_EFI_ERROR (Status);
    }
  }

  DbX509File = PcdGetPtr(PcdDbX509File);
  if (CompareGuid (&NullGuid, DbX509File) == FALSE) {
    Status = PlatformFindFvFileRawDataSection (
               NULL,
               DbX509File,
               (VOID **) &CertData,
               &CertSize
               );

    if (EFI_ERROR (Status)) {
      if (Status != EFI_NOT_FOUND) {
        ASSERT_EFI_ERROR (Status);
      }
    } else {
      ASSERT (CertData != NULL && CertSize > 0);
      DEBUG ((EFI_D_INFO, "Enroll X509 Cert into Db 0x%04x:%g\n", CertSize, DbX509File));
      Status = SecureBootHelperProtocol->SetupEnrollX509 (
                 SecureBootHelperProtocol,
                 DBStore,
                 NULL,
                 CertData,
                 CertSize,
                 DbX509File
                 );
      ASSERT_EFI_ERROR (Status);
    }
  }

  DbxX509File = PcdGetPtr(PcdDbxX509File);
  if (CompareGuid (&NullGuid, DbxX509File) == FALSE) {
    Status = PlatformFindFvFileRawDataSection (
               NULL,
               DbxX509File,
               (VOID **) &CertData,
               &CertSize
               );

    if (EFI_ERROR (Status)) {
      if (Status != EFI_NOT_FOUND) {
        ASSERT_EFI_ERROR (Status);
      }
    } else {
      ASSERT (CertData != NULL && CertSize > 0);
      DEBUG ((EFI_D_INFO, "Enroll X509 Cert into Dbx 0x%04x:%g\n", CertSize, DbxX509File));
      Status = SecureBootHelperProtocol->SetupEnrollX509 (
                 SecureBootHelperProtocol,
                 DBXStore,
                 NULL,
                 CertData,
                 CertSize,
                 DbxX509File
                 );
      ASSERT_EFI_ERROR (Status);
    }
  }

  DEBUG ((EFI_D_INFO, "<<ProvisionFVRecords\n"));
}

STATIC
VOID
ProvisionPlatformDataRecords (
  IN SECUREBOOT_HELPER_PROTOCOL           *SecureBootHelperProtocol,
  IN PDAT_AREA                            *UserPdatArea,
  IN CONST BOOLEAN                        ExchangingKeys,
  IN CONST SECUREBOOT_VARIABLE_STATS      *PreExchangeStats
  )
{
  EFI_STATUS                        Status;
  PDAT_ITEM                         *CurrItem;
  PDAT_LIB_FINDCONTEXT              PDatFindContext;
  SECUREBOOT_STORE_TYPE             StoreType;
  EFI_GUID                          *SignatureOwner;
  PDAT_SB_PAYLOAD_HEADER            *SbHeader;
  UINT8                             *CertData;
  UINTN                             CertSize;
  UINTN                             KekEnrollCount;
  UINTN                             DbEnrollCount;
  UINTN                             DbxEnrollCount;
  UINTN                             *EnrollCntPtr;
  BOOLEAN                           DeleteStoreOnExchange;

  KekEnrollCount = 0;
  DbEnrollCount = 0;
  DbxEnrollCount = 0;
  EnrollCntPtr = NULL;
  DeleteStoreOnExchange = FALSE;

  DEBUG ((EFI_D_INFO, ">>ProvisionPlatformDataRecords\n"));

  CurrItem = PDatLibFindFirstWithFilter (
               UserPdatArea,  // If NULL the lib will use flash area.
               PDAT_ITEM_ID_MASK (PDAT_ITEM_ID_SB_RECORD),
               &PDatFindContext,
               NULL
               );

  if (CurrItem == NULL) {
    return;  // No records do nothing.
  }
  DEBUG ((EFI_D_INFO, "ProvisionPlatformDataRecords: Items of id '0x%04x' found to provision\n", (UINTN) PDAT_ITEM_ID_SB_RECORD ));
  do {
    ASSERT (CurrItem->Header.Length > (sizeof(SbHeader) + 1));
    SbHeader = (PDAT_SB_PAYLOAD_HEADER *) CurrItem->Data;
    StoreType = (SECUREBOOT_STORE_TYPE) SbHeader->StoreType;
    CertData  = &CurrItem->Data[sizeof(SbHeader)];
    CertSize = CurrItem->Header.Length - sizeof(SbHeader);
    if ((SbHeader->Flags & PDAT_SB_FLAG_HAVE_GUID) != 0) {
      ASSERT (CurrItem->Header.Length > (sizeof(PDAT_SB_PAYLOAD_HEADER) + sizeof(EFI_GUID) + 1));
      SignatureOwner = (EFI_GUID *) CertData;
      CertData += sizeof(EFI_GUID);
      CertSize -= sizeof(EFI_GUID);
    } else {
      SignatureOwner = NULL;
    }
    DEBUG ((
      EFI_D_INFO, "SbRec TotLen '0x%04x' Store '%02x' Type '%02x' Flags '0x%04x' GUID '%g'\n",
      CurrItem->Header.Length,
      StoreType,
      SbHeader->CertType,
      SbHeader->Flags,
      SignatureOwner
      ));

    //
    // Only Delete Uefi Secure Boot Variable if exchanging keys
    // for the particular variable.
    //

    DeleteStoreOnExchange = FALSE;
    if (StoreType == KEKStore) {
      if (KekEnrollCount == 0) {
        DeleteStoreOnExchange = PreExchangeStats->KekEnrolled;
      }
      EnrollCntPtr = &KekEnrollCount;
    } else if (StoreType == DBStore) {
      if (DbEnrollCount == 0) {
        DeleteStoreOnExchange = PreExchangeStats->DbEnrolled;
      }
      EnrollCntPtr = &DbEnrollCount;
    } else if (StoreType == DBXStore) {
      if (DbxEnrollCount == 0) {
        DeleteStoreOnExchange = PreExchangeStats->DbxEnrolled;
      }
      EnrollCntPtr = &DbxEnrollCount;
    } else {
      DEBUG ((EFI_D_ERROR, "ProvisionPlatformDataRecords: Unsupported StoreType = '%d'.\n", (UINTN) StoreType));
      ASSERT_EFI_ERROR (EFI_UNSUPPORTED);
    }
    if (ExchangingKeys && DeleteStoreOnExchange) {
      DEBUG ((
        EFI_D_INFO,
        "<<ProvisionPlatformDataRecords: SetupDeleteStoreRecord All %d\n",
         StoreType
        ));
      Status = SecureBootHelperProtocol->SetupDeleteStoreRecord (
                                           SecureBootHelperProtocol,
                                           StoreType,
                                           TRUE,
                                           NULL
                                           );
      ASSERT_EFI_ERROR (Status);
    }

    if (SbHeader->CertType == PDAT_SB_CERT_TYPE_X509) {
      ASSERT ((StoreType == DBStore) || (StoreType == KEKStore) || (StoreType == DBXStore));
      Status = SecureBootHelperProtocol->SetupEnrollX509 (
                 SecureBootHelperProtocol,
                 StoreType,
                 NULL,
                 CertData,
                 CertSize,
                 SignatureOwner
                 );
    } else if (SbHeader->CertType == PDAT_SB_CERT_TYPE_SHA256) {
      ASSERT ((StoreType == DBStore) || (StoreType == DBXStore));
      Status = SecureBootHelperProtocol->SetupEnrollImageSignature (
                 SecureBootHelperProtocol,
                 StoreType,
                 NULL,
                 CertData,
                 CertSize,
                 SignatureOwner
                 );
    } else if (SbHeader->CertType == PDAT_SB_CERT_TYPE_RSA2048) {
      ASSERT (StoreType == KEKStore);
      Status = SecureBootHelperProtocol->SetupEnrollKekRsa2048 (
                 SecureBootHelperProtocol,
                 NULL,
                 CertData,
                 CertSize,
                 SignatureOwner
                 );
    } else {
      DEBUG ((EFI_D_ERROR, "ProvisionPlatformDataRecords: Unsupported Cert Type = '%d'.\n", (UINTN) SbHeader->CertType));
      Status = EFI_UNSUPPORTED;
    }
    ASSERT_EFI_ERROR (Status);

    //
    // Count number records enrolled in this secure boot variable.
    //
    *EnrollCntPtr = *EnrollCntPtr + 1;

    CurrItem = PDatLibFindNextWithFilter (
      PDAT_ITEM_ID_MASK (PDAT_ITEM_ID_SB_RECORD),
      &PDatFindContext,
      NULL
      );
  } while (CurrItem != NULL);

  DEBUG ((
    EFI_D_INFO,
    "<<ProvisionPlatformDataRecords: Enrolled Kek:%d Db:%d Dbx:%d\n",
      KekEnrollCount,
      DbEnrollCount,
      DbxEnrollCount
    ));
}

//
// Routines exported by this source module.
//

/** Auto provision Secure Boot Resources.

  Provision from platform data, and only provision if PK public cert found.

  if (UserPdatArea) == NULL routine uses flash Pdat area to find items to enrol

  @param[in out]   UserPdatArea On input take SB records to provision from here.
                                On output remove SB record from here (or remove
                                flash if UserPdatArea == NULL).

  @retval  TRUE    UEFI Secure Boot enabled.
  @retval  FALSE   UEFI Secure Boot Disabled.

**/
BOOLEAN
EFIAPI
QuarkAutoProvisionSecureBoot (
  IN OUT PDAT_AREA                        *UserPdatArea
  )
{
  EFI_STATUS                        Status;
  SECUREBOOT_HELPER_PROTOCOL        *SecureBootHelperProtocol;
  UINT8                             *PkX509Data;
  UINTN                             PkX509DataSize;
  BOOLEAN                           SecureBootEnabled;
  BOOLEAN                           ExchangingKeys;
  SECUREBOOT_VARIABLE_STATS         PreExchangeStats;

  SecureBootEnabled = FALSE;
  ExchangingKeys = FALSE;

  if (FeaturePcdGet (PcdSupportSecureBoot)) {
    Status = gBS->LocateProtocol (
               &gSecureBootHelperProtocolGuid,
               NULL,
               (VOID**) &SecureBootHelperProtocol
               );
    ASSERT_EFI_ERROR (Status);

    SecureBootEnabled = SecureBootHelperProtocol->IsSecureBootEnabled (
                                                 SecureBootHelperProtocol
                                                 );
    Status = SecureBootHelperProtocol->GetSecureBootVarStats (
                                         SecureBootHelperProtocol,
                                         &PreExchangeStats
                                         );

    ASSERT_EFI_ERROR (Status);
    DEBUG ((
      EFI_D_INFO,
      "ProvisionPlatformDataRecords: Already Enrolled Pk:%a Kek:%a:%d Db:%a:%d Dbx:%a:%d\n",
      PreExchangeStats.PkEnrolled ? "YES" : "NO",
      PreExchangeStats.KekEnrolled ? "YES" : "NO",
      PreExchangeStats.KekTotalCertCount,
      PreExchangeStats.DbEnrolled ? "YES" : "NO",
      PreExchangeStats.DbTotalCertCount,
      PreExchangeStats.DbxEnrolled ? "YES" : "NO",
      PreExchangeStats.DbxTotalCertCount
      ));

    if (SecureBootEnabled && UserPdatArea != NULL) {
      //
      // We can  exchange keys if secure boot already enabled and we have
      // UserPdatArea in memory which may have new keys for the system.
      //
      ExchangingKeys = TRUE;

      DEBUG ((EFI_D_INFO, "AutoProvisionSecureBoot: System already provisioned, Exchange Keys.\n"));

      ASSERT_EFI_ERROR (Status);
      ASSERT (PreExchangeStats.PkEnrolled);
    } else {
      DEBUG ((EFI_D_INFO, "AutoProvisionSecureBoot: attempt 1st provisioning of system\n"));
    }

    PkX509Data = FindPkCert (UserPdatArea, ExchangingKeys, &PkX509DataSize);

    //
    // One 1st provisioning we need PK to provison else
    // we can exchange keys if already provisioned.
    //
    if (PkX509Data != NULL || ExchangingKeys) {

      //
      // mUefiSecureProvisioningActive set to TRUE only
      // while writing to UEFI Secure Boot variables to allow
      // physically present user check to return TRUE.
      //
      mUefiSecureProvisioningActive = TRUE;

      //
      // Set custom mode.
      //
      Status = SecureBootHelperProtocol->SetupSetSecureBootCustomMode (
                                                      SecureBootHelperProtocol
                                                      );
      ASSERT_EFI_ERROR (Status);

      //
      // Provision auto provisioning records stored in platform data.
      //
      ProvisionPlatformDataRecords (
        SecureBootHelperProtocol,
        UserPdatArea,
        ExchangingKeys,
        &PreExchangeStats
        );

      //
      // Only allow provisioning records in firmware volumes to be used
      // if not exchanging keys ie on 1st provisioning of system.
      //
      if (!ExchangingKeys) {
        ProvisionFVRecords (SecureBootHelperProtocol);
      }

      if (PkX509Data != NULL) {

        //
        // Delete old PK if we have a new one and we are exchanging keys.
        //
        if (ExchangingKeys) {
          Status = SecureBootHelperProtocol->SetupDeleteStoreRecord (
                                               SecureBootHelperProtocol,
                                               PKStore,
                                               TRUE,
                                               NULL
                                               );
          ASSERT_EFI_ERROR (Status);
        }

        //
        // Now enable secure boot by enrolling PK public cert.
        //
        Status = SecureBootHelperProtocol->SetupEnrollX509 (
                   SecureBootHelperProtocol,
                   PKStore,
                   NULL,
                   PkX509Data,
                   PkX509DataSize,
                   NULL
                   );
        ASSERT_EFI_ERROR (Status);

        SecureBootEnabled = SecureBootHelperProtocol->IsSecureBootEnabled (
                                                      SecureBootHelperProtocol
                                                      );
        ASSERT (SecureBootEnabled);

        //
        // Take secure boot out of custom mode and return to default mode.
        //
        Status = SecureBootHelperProtocol->SetupSetSecureBootDefaultMode (
                                                      SecureBootHelperProtocol
                                                      );
        ASSERT_EFI_ERROR (Status);

        mUefiSecureProvisioningActive = FALSE;
     }
    }

    //
    // No matter what happens always delete SB items before returning on
    // UEFI Secure Boot systems.
    //
    DeleteAutoProvisionSecureBootItems (UserPdatArea);
  }
  return SecureBootEnabled;
}

/**
  Return TRUE if UEFI Secure Boot Auto Provisioning is active.

  @retval TRUE                    UEFI Secure boot provisioning active.
  @retval FALSE                   UEFI Secure Boot provisioning inactive.

**/
BOOLEAN
EFIAPI
QuarkIsUefiSecureBootProvisioningActive (
  VOID
  )
{
  return mUefiSecureProvisioningActive;
}

/** Maintain UEFI Secure boot variables will deleting the rest.

  @param[out]      MaintainCountPtr Output number of variables maintained.

  @retval EFI_SUCCESS           Uefi Secure boot variables maintained.
  @return *MaintainCountPtr the number of variables maintained.
**/
EFI_STATUS
EFIAPI
QuarkMaintainSecureBootVariables (
  OUT UINTN                               *MaintainCountPtr OPTIONAL
  )
{
  EFI_STATUS                        Status;
  BOOLEAN                           SomethingToMaintain;

  if (MaintainCountPtr != NULL) {
    *MaintainCountPtr = 0;
  }

  Status = EFI_SUCCESS;
  SomethingToMaintain = FALSE;

  if (!QuarkIsUefiSecureBootEnabled ()) {
    //
    // Nothing to do if secure boot disabled, not an error.
    //
    return EFI_SUCCESS;
  }

  SomethingToMaintain = PlatformIsVariableTableEntryInVariableStore (
                          mSbMaintainVarTable,
                          mSbMaintainVarTableLen
                          );

  if (SomethingToMaintain) {
    Status = PlatformDeleteVariables (
               mSbMaintainVarTable,
               mSbMaintainVarTableLen,
               NULL,
               MaintainCountPtr
               );
    if (Status == EFI_NOT_FOUND) {
      //
      // Not an error for what we want to do if nothing deleted.
      //
      Status = EFI_SUCCESS;
    }
    ASSERT_EFI_ERROR (Status);
  }
  return Status;
}

/**
  Return TRUE if UEFI Secure Boot is enabled.

  @retval TRUE                    UEFI Secure boot enabled.
  @retval FALSE                   UEFI Secure Boot disabled or not supported.

**/
BOOLEAN
EFIAPI
QuarkIsUefiSecureBootEnabled (
  VOID
  )
{
  EFI_STATUS                        Status;
  SECUREBOOT_HELPER_PROTOCOL        *SecureBootHelperProtocol;
  BOOLEAN                           SecureBootEnabled;

  Status = EFI_SUCCESS;
  SecureBootHelperProtocol = NULL;
  SecureBootEnabled = FALSE;

  if (FeaturePcdGet (PcdSupportSecureBoot)) {
    Status = gBS->LocateProtocol(
               &gSecureBootHelperProtocolGuid,
               NULL,
               (VOID**) &SecureBootHelperProtocol
               );
    ASSERT_EFI_ERROR (Status);
    SecureBootEnabled = SecureBootHelperProtocol->IsSecureBootEnabled (
                                                    SecureBootHelperProtocol
                                                    );
  }

  return SecureBootEnabled;
}