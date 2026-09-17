# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

param(
    [Parameter(Mandatory=$true)][string]$HostDir,
    [string]$BuildDir='C:\buildfiles\radshark'
)
$ErrorActionPreference='Stop'
$sharkPlugin=Join-Path $BuildDir 'plugins\fwgui_radshark.dll'
if(-not (Test-Path -LiteralPath $sharkPlugin)) { throw 'Build the FreeWili GUI plugin first (-Plugins).' }
if(-not (Test-Path -LiteralPath $HostDir -PathType Container)) { throw 'HostDir must be an existing host installation directory.' }
$sharkDestination=Join-Path $HostDir 'plugins'
New-Item -ItemType Directory -Path $sharkDestination -Force | Out-Null
Copy-Item -LiteralPath $sharkPlugin -Destination $sharkDestination -Force
$sharkDecoder=Join-Path $BuildDir 'wirespy'
if(Test-Path -LiteralPath $sharkDecoder) {
    $sharkRuntimeDestination=Join-Path $HostDir 'wirespy'
    New-Item -ItemType Directory -Path $sharkRuntimeDestination -Force | Out-Null
    Get-ChildItem -LiteralPath $sharkDecoder | Copy-Item -Destination $sharkRuntimeDestination -Recurse -Force
}
Write-Output "Installed RadShark in $HostDir. Restart the host and open Tools > RadShark."
