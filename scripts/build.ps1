# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

param(
    [string]$BuildDir = 'C:\buildfiles\radshark',
    [string]$Config = 'RelWithDebInfo',
    [switch]$Plugins,
    [switch]$Test,
    [string[]]$CmakeArgs = @()
)
$ErrorActionPreference = 'Stop'
$sharkRoot = Split-Path $PSScriptRoot -Parent
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw 'Visual Studio C++ tools are required' }
Import-Module (Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64' | Out-Null
$pluginFlag = if ($Plugins) { 'ON' } else { 'OFF' }
cmake -S $sharkRoot -B $BuildDir -G Ninja "-DCMAKE_BUILD_TYPE=$Config" "-DRADSHARK_BUILD_FWGUI_PLUGIN=$pluginFlag" @CmakeArgs
if ($LASTEXITCODE) { exit $LASTEXITCODE }
cmake --build $BuildDir
if ($LASTEXITCODE) { exit $LASTEXITCODE }
if ($Test) {
    ctest --test-dir $BuildDir --output-on-failure
    exit $LASTEXITCODE
}
