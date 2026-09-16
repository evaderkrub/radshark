# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

param(
    [string]$BuildDir='C:\buildfiles\vspyshark',
    [string]$FreeWiliGuiBuildDir='C:\buildfiles\fwcom\visual-studio\Release'
)
$ErrorActionPreference='Stop'
$sharkDll=Join-Path $BuildDir 'plugins\fwgui_vspyshark.dll'
$sharkFwTest=Join-Path $FreeWiliGuiBuildDir 'plugin_portability_tests.exe'
$sharkCompanion=Join-Path $FreeWiliGuiBuildDir 'plugins\example_canvas.dll'
foreach($sharkFile in @($sharkDll,$sharkFwTest,$sharkCompanion)) {
    if(-not (Test-Path -LiteralPath $sharkFile)) {throw "Build the required host test or plugin: $sharkFile"}
}
$sharkOldServer=$env:WIRESPY_SERVER
Push-Location $BuildDir
try {
    $env:WIRESPY_SERVER=Join-Path $BuildDir 'wirespy\wirespy_server.exe'
    & $sharkFwTest $sharkDll $sharkCompanion
    if($LASTEXITCODE) {throw 'FreeWili GUI public plugin load/frame/view checks failed'}
    Write-Output 'VSpy Shark loaded and executed in FreeWili GUI.'
} finally {$env:WIRESPY_SERVER=$sharkOldServer;Pop-Location}
