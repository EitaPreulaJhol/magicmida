# Builds the internal 32-bit worker and the final 64-bit magicmida.exe
# with MinGW-w64 on Windows.
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -Clean
#   .\build.ps1 -MinGW32 C:\msys64\mingw32\bin -MinGW64 C:\msys64\mingw64\bin
#
# If the MinGW-w64 toolchains are not on PATH, pass their bin directories
# with -MinGW32/-MinGW64. CMake, Ninja (or mingw32-make), and both
# toolchains are required.

param(
    [switch]$Clean,
    [string]$Generator = "",
    [string]$MinGW32 = "",
    [string]$MinGW64 = ""
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    throw "cmake was not found in PATH. Install CMake and reopen the terminal."
}

function Resolve-Toolchain {
    param(
        [string]$BinDir,
        [string]$Prefix,
        [string]$Label
    )

    $result = [ordered]@{}
    foreach ($tool in @("gcc", "g++", "windres")) {
        $command = $null
        if (-not [string]::IsNullOrWhiteSpace($BinDir)) {
            $candidate = Join-Path $BinDir ("$tool.exe")
            if (-not (Test-Path -LiteralPath $candidate)) {
                throw "$Label toolchain: '$candidate' does not exist."
            }
            $command = $candidate
        } else {
            foreach ($name in @("$Prefix-$tool.exe", "$Prefix-$tool")) {
                $found = Get-Command $name -ErrorAction SilentlyContinue
                if ($found) {
                    $command = $found.Source
                    break
                }
            }
        }

        if ($null -eq $command) {
            throw ("$Label MinGW-w64 toolchain not found. " +
                   "Install MinGW-w64 (MSYS2: pacman -S mingw-w64-i686-gcc " +
                   "mingw-w64-x86_64-gcc) and put its bin directory on PATH, " +
                   "or pass -MinGW32/-MinGW64 with the toolchain bin directory.")
        }
        $result[$tool] = $command
    }
    return [pscustomobject]$result
}

if ([string]::IsNullOrWhiteSpace($Generator)) {
    if (Get-Command ninja.exe -ErrorAction SilentlyContinue) {
        $Generator = "Ninja"
    } elseif (Get-Command mingw32-make.exe -ErrorAction SilentlyContinue) {
        $Generator = "MinGW Makefiles"
    } else {
        throw "Neither Ninja nor mingw32-make was found. Install one of them (or add it to PATH)."
    }
}

if (-not [string]::IsNullOrWhiteSpace($MinGW32)) {
    $env:PATH = "$MinGW32;$env:PATH"
}
if (-not [string]::IsNullOrWhiteSpace($MinGW64)) {
    $env:PATH = "$MinGW64;$env:PATH"
}

$toolchain32 = Resolve-Toolchain -BinDir $MinGW32 -Prefix "i686-w64-mingw32" -Label "32-bit"
$toolchain64 = Resolve-Toolchain -BinDir $MinGW64 -Prefix "x86_64-w64-mingw32" -Label "64-bit"

Write-Host "Generator: $Generator"
Write-Host "32-bit C compiler:   $($toolchain32.gcc)"
Write-Host "64-bit C compiler:   $($toolchain64.gcc)"

if ($Clean) {
    Write-Host "Removing build/..."
    Remove-Item -Recurse -Force (Join-Path $root "build") -ErrorAction SilentlyContinue
}

function Invoke-CMake {
    param([string[]]$Arguments)
    & cmake @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cmake failed with exit code $LASTEXITCODE."
    }
}

# 1. Internal 32-bit worker (not a standalone application).
$config32 = @(
    "-S", ".",
    "-B", "build/x86",
    "-G", $Generator,
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_C_COMPILER=$($toolchain32.gcc)",
    "-DCMAKE_CXX_COMPILER=$($toolchain32.'g++')",
    "-DCMAKE_RC_COMPILER=$($toolchain32.windres)"
)
Invoke-CMake -Arguments $config32
Invoke-CMake -Arguments @("--build", "build/x86", "--parallel")

$worker = Join-Path $root "build/worker/magicmida_worker.exe"
if (-not (Test-Path -LiteralPath $worker)) {
    throw "The 32-bit worker was not produced at $worker."
}

# 2. 64-bit application with the 32-bit worker embedded.
$config64 = @(
    "-S", ".",
    "-B", "build/x64",
    "-G", $Generator,
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_C_COMPILER=$($toolchain64.gcc)",
    "-DCMAKE_CXX_COMPILER=$($toolchain64.'g++')",
    "-DCMAKE_RC_COMPILER=$($toolchain64.windres)",
    "-DMAGICMIDA_32BIT_WORKER=$worker"
)
Invoke-CMake -Arguments $config64
Invoke-CMake -Arguments @("--build", "build/x64", "--parallel")

$final = Join-Path $root "build/magicmida.exe"
if (-not (Test-Path -LiteralPath $final)) {
    throw "The final executable was not produced at $final."
}

Write-Host ""
Write-Host "Built:"
Write-Host "  $final"
Write-Host "  internal worker: $worker"
