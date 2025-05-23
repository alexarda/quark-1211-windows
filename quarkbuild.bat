@REM
@REM Copyright (c) 2013-2016 Intel Corporation.
@REM
@REM Redistribution and use in source and binary forms, with or without
@REM modification, are permitted provided that the following conditions
@REM are met:
@REM
@REM * Redistributions of source code must retain the above copyright
@REM notice, this list of conditions and the following disclaimer.
@REM * Redistributions in binary form must reproduce the above copyright
@REM notice, this list of conditions and the following disclaimer in
@REM the documentation and/or other materials provided with the
@REM distribution.
@REM * Neither the name of Intel Corporation nor the names of its
@REM contributors may be used to endorse or promote products derived
@REM from this software without specific prior written permission.
@REM
@REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
@REM "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
@REM LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
@REM A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
@REM OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
@REM SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
@REM LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
@REM DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
@REM THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
@REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
@REM OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
@REM

@echo off

@REM Make sure you fully understand (the lack of) delayedexpansion
@REM in batch files before you try to use error reporting
set MY_ERROR_LVL=0


@if /I "%1"=="" goto Usage
@if /I "%1"=="-h" goto Usage
@if /I "%1"=="-clean" goto Clean
@if /I "%2"=="" goto Usage
@if /I "%3"=="" goto Usage

@REM
@REM Windows build environment traditionally has problems with long path names.
@REM most notably the MAX_PATH limit.
@REM Substitute the source code root to avoid these problems.
@REM
set CURRENTDIR=%~dp0
set CURRENTDIR=%CURRENTDIR:~0,-1%
set CURRENTDRIVE=%~d1
set SUBSTDRIVE=%2:

subst /d %SUBSTDRIVE%
subst %SUBSTDRIVE% %CURRENTDIR%
%SUBSTDRIVE%

@REM ###########################################################################
@REM ########################    PreSetup-processing      ######################
@REM ###########################################################################
if NOT exist %SUBSTDRIVE%\Conf (
  mkdir %SUBSTDRIVE%\Conf
)

if NOT exist %SUBSTDRIVE%\Conf\tools_def.txt (
  echo copying ... tools_def.template to %SUBSTDRIVE%\Conf\tools_def.txt
  copy /Y %SUBSTDRIVE%\QuarkPlatformPkg\Override\BaseTools\Conf\tools_def.template %SUBSTDRIVE%\Conf\tools_def.txt > nul
)
if NOT exist %SUBSTDRIVE%\Conf\build_rule.txt (
  echo copying ... build_rule.template to %SUBSTDRIVE%\Conf\build_rule.txt
  copy /Y %SUBSTDRIVE%QuarkPlatformPkg\Override\BaseTools\Conf\build_rule.template %SUBSTDRIVE%\Conf\build_rule.txt > nul
)  

@if not defined WORKSPACE (
  call %SUBSTDRIVE%\edksetup.bat
)

@echo off

if /I "%1"=="-r32" (
  set TARGET=RELEASE
  set DEBUG_PRINT_ERROR_LEVEL=-DDEBUG_PRINT_ERROR_LEVEL=0x80000000
  set DEBUG_PROPERTY_MASK=-DDEBUG_PROPERTY_MASK=0x23
  goto CheckParameter3
)

if /I "%1"=="-d32" (
  set TARGET=DEBUG
  set DEBUG_PRINT_ERROR_LEVEL=-DDEBUG_PRINT_ERROR_LEVEL=0x80000042
  set DEBUG_PROPERTY_MASK=-DDEBUG_PROPERTY_MASK=0x27
  goto CheckParameter3
) else (
  goto Usage
)

:CheckParameter3
  set PLATFORM=%3
  goto BuildAll

:Clean
echo Removing Build/Conf directories ... 
if exist Build rmdir Build /s /q
if exist Conf  rmdir Conf  /s /q
if exist *.log  del *.log /q /f
set WORKSPACE=
set EDK_TOOLS_PATH=
goto End

:BuildAll
@echo off

@REM Add all arguments after the 3rd to the EDK_PARAMS variable
@REM tokens=1-3 puts the 1st, 2nd and 3rd arguments in %%a, %%b and %%c
@REM All remaining arguments are in %%d


for /f "tokens=1-3*" %%a in ("%*") do (
    set EDK_PARAMS=%%d
)

if NOT exist %WORKSPACE%\BaseTools (
  echo Error: SVN directories missing - please run svn update to download
  goto End
)

if exist %WORKSPACE%\QuarkSocPkg\QuarkNorthCluster\Binary\QuarkMicrocode\RMU.bin  goto GotCMC
echo Trying to fetch Chipset Microcode...
%WORKSPACE%\fetchCMCBinary.py
if %ERRORLEVEL% NEQ 0 (
    set MY_ERROR_LVL=%ERRORLEVEL%
    echo Error: Chipset Microcode is missing
    goto End
)

:GotCMC

@REM ###########################################################################
@REM ########################   PreBuild-processing       ######################
@REM ###########################################################################
if NOT exist %WORKSPACE%\Conf (
  echo Error: Missing folder %WORKSPACE%\Conf\
  goto End
)

@REM Find installed version of Visual Studio
if not defined VS_VERSION (
  set VS_VERSION=
  set VSCOMNTOOLS=

  if defined VS120COMNTOOLS (
    set VS_VERSION=VS2013
    set VSCOMNTOOLS="%VS120COMNTOOLS%"
  ) else (
    if defined VS110COMNTOOLS (
      set VS_VERSION=VS2012
      set VSCOMNTOOLS="%VS110COMNTOOLS%"
    ) else (
      if defined VS100COMNTOOLS (
        set VS_VERSION=VS2010
        set VSCOMNTOOLS="%VS100COMNTOOLS%"
      ) else (
        if defined VS90COMNTOOLS (
          set VS_VERSION=VS2008
          set VSCOMNTOOLS="%VS90COMNTOOLS%"
        ) else (
          if defined VS80COMNTOOLS (
            set VS_VERSION=VS2005
            set VSCOMNTOOLS="%VS80COMNTOOLS%"
          ) else (
            if defined VS71COMNTOOLS (
              set VS_VERSION=VS2003
              set VSCOMNTOOLS="%VS71COMNTOOLS%"
            ) else (
              echo.
              echo !!! WARNING !!! Cannot find Visual Studio !!!
              echo.
              goto End
            )
          )
        )
      )
    )
  )
)

set VS_X86=
set VSCOMNTOOLS_TMP=%VSCOMNTOOLS:(x86)=%
if  %VSCOMNTOOLS_TMP% == %VSCOMNTOOLS% goto ParseContinue
set VS_X86=x86xASL

:ParseContinue
@if not exist Build\%PLATFORM%\%TARGET%_%VS_VERSION%%VS_X86%\IA32 (
  mkdir Build\%PLATFORM%\%TARGET%_%VS_VERSION%%VS_X86%\IA32
)

@REM ####################################################################################################################
@REM ######                                Perform the actual build                                         #############
@REM ######   Warning: parameters here are supposed to override any corresponding value in Conf/target.txt  #############
@REM ####################################################################################################################
build  -p %PLATFORM%Pkg\%PLATFORM%Pkg.dsc -b %TARGET% -a IA32 -n 4 -t %VS_VERSION%%VS_X86% -y Report.log %EDK_PARAMS% %DEBUG_PRINT_ERROR_LEVEL% %DEBUG_PROPERTY_MASK%
if %ERRORLEVEL% NEQ 0   ( set MY_ERROR_LVL=%ERRORLEVEL% & Goto End )

@REM ###############################################################################
@REM ########################       PostBuild-processing       #####################
@REM ###############################################################################
.\QuarkPlatformPkg\Tools\QuarkSpiFixup\QuarkSpiFixup.py %PLATFORM% %TARGET% %VS_VERSION%%VS_X86%

@REM ####################################################################################################################
@REM ######         Perform EDKII build again after QuarkSpiFixup so that output .fd file usable.           #############
@REM ######   Warning: parameters here are supposed to override any corresponding value in Conf/target.txt  #############
@REM ####################################################################################################################
build  -p %PLATFORM%Pkg\%PLATFORM%Pkg.dsc -b %TARGET% -a IA32 -n 4 -t %VS_VERSION%%VS_X86% -y Report.log %EDK_PARAMS% %DEBUG_PRINT_ERROR_LEVEL% %DEBUG_PROPERTY_MASK%
if %ERRORLEVEL% NEQ 0   ( set MY_ERROR_LVL=%ERRORLEVEL% & Goto End )

set OutputModulesDir=%WORKSPACE%\Build\%PLATFORM%\%TARGET%_%VS_VERSION%%VS_X86%\FV

@REM Copy build output .fd file int0 FlashModules directory.
@REM Use similar name to full Quark Spi Flash tools but emphasise only EDKII assets in bin file.
copy /Y %OutputModulesDir%\QUARK.fd %OutputModulesDir%\FlashModules\Flash-EDKII-missingPDAT.bin

REM ==== Original build steps ====
REM (your existing build commands go here)
REM ...

REM ==== Run signature tool ====
REM Ensure Python is available
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found in PATH. Aborting signing step.
    exit /b 1
)

REM Call signtool.py from SignTool directory
echo [INFO] Running signature tool...
pushd SignTool
python signtool.py
popd

echo [INFO] Signing complete.

copy Report.log Build\%PLATFORM%\%TARGET%_%VS_VERSION%%VS_X86%\ > nul
if ERRORLEVEL 1 exit /b 1
goto End

:Usage
  echo.
  echo  Usage: "%0 [-h | -r32 | -d32 | -clean] [subst drive letter] [PlatformName] [-DSECURE_LD(optional)] [-DSECURE_BOOT(optional)]"
  echo.

:End
%CURRENTDRIVE%
subst /d %SUBSTDRIVE%
echo.
exit /b %MY_ERROR_LVL%