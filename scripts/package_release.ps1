param(
    [string]$BuildDir = "build-release",
    [ValidateSet("Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Release",
    [string]$DistDir = "dist",
    [string]$QtPrefixPath = "",
    [string]$ExePath = "",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host ("==> " + $Message)
}

function Get-ProjectVersion([string]$CmakeListsPath) {
    if (!(Test-Path $CmakeListsPath)) { return "0.0.0" }
    $text = Get-Content -Raw $CmakeListsPath
    $pattern = 'project\s*\(\s*VisualSafety\s+VERSION\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'
    $m = [Regex]::Match($text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value }
    return "0.0.0"
}

function Import-MsvcEnv {
    if (Get-Command cl.exe -ErrorAction SilentlyContinue) { return }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\\Installer\\vswhere.exe"
    if (!(Test-Path $vswhere)) { return }

    $vsPath = & $vswhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ([string]::IsNullOrWhiteSpace($vsPath)) { return }

    $vsDevCmd = Join-Path $vsPath "Common7\\Tools\\VsDevCmd.bat"
    if (!(Test-Path $vsDevCmd)) { return }

    Write-Step "Loading MSVC environment via VsDevCmd.bat"
    $envLines = cmd /c "`"$vsDevCmd`" -arch=x64 -host_arch=x64 >nul && set"
    foreach ($line in $envLines) {
        $idx = $line.IndexOf("=")
        if ($idx -le 0) { continue }
        $key = $line.Substring(0, $idx)
        $val = $line.Substring($idx + 1)
        Set-Item -Path ("Env:" + $key) -Value $val
    }
}

function Find-Windeployqt([string]$QtPrefixPath) {
    $cmd = Get-Command windeployqt.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }
    if (![string]::IsNullOrWhiteSpace($QtPrefixPath)) {
        $candidate = Join-Path $QtPrefixPath "bin\\windeployqt.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    return ""
}

if ($Clean) {
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
}

$windeployqt = Find-Windeployqt $QtPrefixPath
if ([string]::IsNullOrWhiteSpace($windeployqt)) {
    throw "windeployqt.exe not found. Add Qt6 bin to PATH or pass -QtPrefixPath (e.g. C:\\Qt\\6.8.0\\msvc2022_64)."
}

$version = Get-ProjectVersion "CMakeLists.txt"
$staging = Join-Path $DistDir ("VisualSafety-" + $version + "-win64")

New-Item -ItemType Directory -Force -Path $staging | Out-Null

if (![string]::IsNullOrWhiteSpace($ExePath)) {
    Write-Step "Using existing exe"
    if (!(Test-Path $ExePath)) {
        throw "ExePath not found: $ExePath"
    }
    $exe = Get-Item $ExePath
} else {
    Import-MsvcEnv
    if (!(Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw "MSVC not found (cl.exe). Install Visual Studio Build Tools (C++), or run this script inside a Developer PowerShell for VS."
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    Write-Step "Configuring ($Config)"
    $cmakeArgs = @("-S", ".", "-B", $BuildDir, "-G", "Visual Studio 17 2022", "-A", "x64")
    if (![string]::IsNullOrWhiteSpace($QtPrefixPath)) {
        $cmakeArgs += @("-D", ("CMAKE_PREFIX_PATH=" + $QtPrefixPath))
    }
    & cmake @cmakeArgs

    Write-Step "Building ($Config)"
    & cmake --build $BuildDir --config $Config -- /m

    Write-Step "Locating built exe"
    $exe = Get-ChildItem -Path $BuildDir -Recurse -Filter "appVisualSafety.exe" -File |
        Where-Object { $_.FullName -match ("\\\\{0}\\\\" -f [Regex]::Escape($Config)) } |
        Select-Object -First 1
    if (!$exe) {
        $exe = Get-ChildItem -Path $BuildDir -Recurse -Filter "appVisualSafety.exe" -File | Select-Object -First 1
    }
    if (!$exe) {
        throw "appVisualSafety.exe not found under $BuildDir. Check build output paths."
    }
}

Copy-Item -Force $exe.FullName (Join-Path $staging $exe.Name)
if (Test-Path "LICENSE") { Copy-Item -Force "LICENSE" (Join-Path $staging "LICENSE") }
if (Test-Path "README.md") { Copy-Item -Force "README.md" (Join-Path $staging "README.md") }

Write-Step "Running windeployqt"
$qmlDir = (Resolve-Path "qml").Path
& $windeployqt --release --qmldir $qmlDir --dir $staging (Join-Path $staging $exe.Name)

Write-Step "Creating zip"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
$zipPath = Join-Path $DistDir ("VisualSafety-" + $version + "-win64.zip")
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zipPath -Force

Write-Host ""
Write-Host "OK:"
Write-Host ("- Staging: " + $staging)
Write-Host ("- Zip:     " + $zipPath)
