/** @file
  The header file for TPM PEI driver.

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

#ifndef _TPM_COMM_H_
#define _TPM_COMM_H_

#include <IndustryStandard/Tpm12.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/TpmCommLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

#pragma pack(1)

typedef struct {
  TPM_RQU_COMMAND_HDR   Hdr;
  TPM_STARTUP_TYPE      TpmSt;
} TPM_CMD_START_UP;

typedef struct {
  TPM_RQU_COMMAND_HDR   Hdr;
} TPM_CMD_SELF_TEST;

typedef struct {
  TPM_RQU_COMMAND_HDR   Hdr;
  UINT32                Capability;
  UINT32                CapabilityFlagSize;
  UINT32                CapabilityFlag;
} TPM_CMD_GET_CAPABILITY;

typedef struct {
  TPM_RQU_COMMAND_HDR   Hdr;
  TPM_PCRINDEX          PcrIndex;
  TPM_DIGEST            TpmDigest;
} TPM_CMD_EXTEND;

typedef struct {
  TPM_RQU_COMMAND_HDR   Hdr;
  TPM_PHYSICAL_PRESENCE PhysicalPresence;
} TPM_CMD_PHYSICAL_PRESENCE;

#pragma pack()

/**
  Send TPM_Startup command to TPM.

  @param[in] PeiServices        Describes the list of possible PEI Services.
  @param[in] TpmHandle          TPM handle.
  @param[in] BootMode           Boot mode.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_TIMEOUT           The register can't run into the expected status in time.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.

**/
EFI_STATUS
TpmCommStartup (
  IN      EFI_PEI_SERVICES          **PeiServices,
  IN      TIS_TPM_HANDLE            TpmHandle,
  IN      EFI_BOOT_MODE             BootMode
  );

/**
  Send TPM_ContinueSelfTest command to TPM.

  @param[in] PeiServices        Describes the list of possible PEI Services.
  @param[in] TpmHandle          TPM handle.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_TIMEOUT           The register can't run into the expected status in time.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.

**/
EFI_STATUS
TpmCommContinueSelfTest (
  IN      EFI_PEI_SERVICES          **PeiServices,
  IN      TIS_TPM_HANDLE            TpmHandle
  );

/**
  Get TPM capability flags.

  @param[in]  PeiServices       Describes the list of possible PEI Services.
  @param[in]  TpmHandle         TPM handle.
  @param[out] Deactivated       Returns deactivated flag.
  @param[out] LifetimeLock      Returns physicalPresenceLifetimeLock permanent flag.
  @param[out] CmdEnable         Returns physicalPresenceCMDEnable permanent flag.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_TIMEOUT           The register can't run into the expected status in time.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.

**/
EFI_STATUS
TpmCommGetCapability (
  IN      EFI_PEI_SERVICES          **PeiServices,
  IN      TIS_TPM_HANDLE            TpmHandle,
     OUT  BOOLEAN                   *Deactivated, OPTIONAL
     OUT  BOOLEAN                   *LifetimeLock, OPTIONAL
     OUT  BOOLEAN                   *CmdEnable OPTIONAL
  );

/**
  Extend a TPM PCR.

  @param[in]  PeiServices       Describes the list of possible PEI Services.
  @param[in]  TpmHandle         TPM handle.
  @param[in]  DigestToExtend    The 160 bit value representing the event to be recorded.
  @param[in]  PcrIndex          The PCR to be updated.
  @param[out] NewPcrValue       New PCR value after extend.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_TIMEOUT           The register can't run into the expected status in time.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.

**/
EFI_STATUS
TpmCommExtend (
  IN      EFI_PEI_SERVICES          **PeiServices,
  IN      TIS_TPM_HANDLE            TpmHandle,
  IN      TPM_DIGEST                *DigestToExtend,
  IN      TPM_PCRINDEX              PcrIndex,
     OUT  TPM_DIGEST                *NewPcrValue
  );


/**
  Send TSC_PhysicalPresence command to TPM.

  @param[in] PeiServices        Describes the list of possible PEI Services.
  @param[in] TpmHandle          TPM handle.
  @param[in] PhysicalPresence   The state to set the TPMs Physical Presence flags.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_TIMEOUT           The register can't run into the expected status in time.
  @retval EFI_BUFFER_TOO_SMALL  Response data buffer is too small.
  @retval EFI_DEVICE_ERROR      Unexpected device behavior.

**/
EFI_STATUS
TpmCommPhysicalPresence (
  IN      EFI_PEI_SERVICES          **PeiServices,
  IN      TIS_TPM_HANDLE            TpmHandle,
  IN      TPM_PHYSICAL_PRESENCE     PhysicalPresence
  );

/**
  Writes single byte data to TPM specified by I2c address.

  Write access to TPM is MMIO or I2C (based on platform type).

  @param  Address The register to write.
  @param  Data    The data to write to the register.

**/
VOID
TpmWriteByte (
  IN UINTN  Address,
  IN UINT8  Data
  );


/**
  Reads single byte data from TPM specified by I2c address.

  Read access to TPM is via MMIO or I2C (based on platform type).

  Due to stability issues when using I2C combined write/read transfers (with
  RESTART) to TPM (specifically read from status register), a single write is
  performed followed by single read (with STOP condition in between).

  @param  Address of the I2c mapped register to read.

  @return The value read.

**/
UINT8
EFIAPI
TpmReadByte (
  IN  UINTN  Address
  );

#endif  // _TPM_COMM_H_
