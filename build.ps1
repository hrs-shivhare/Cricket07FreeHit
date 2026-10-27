param(
    [string]$Zig,
    [string]$GameDirectory = 'E:\Cricket07',
    [switch]$Install
)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
if (-not $Zig) { $Zig = Join-Path $projectRoot '..\..\work\toolchains\zig-x86_64-windows-0.15.2\zig.exe' }
$Zig = (Resolve-Path -LiteralPath $Zig).Path
$dist = Join-Path $projectRoot 'dist'
$testDir = Join-Path $projectRoot 'tests\bin'
New-Item -ItemType Directory -Force -Path $dist,$testDir | Out-Null
$env:ZIG_GLOBAL_CACHE_DIR = Join-Path $projectRoot '..\..\work\toolchains\zig-cache'
$src = Join-Path $projectRoot 'src'
$plugin = Join-Path $dist 'Cricket07FreeHit.asi'
$exe = Join-Path $GameDirectory 'Cricket07.exe'
$initialExeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
if ($initialExeHash -ne 'D776DBA0CC506B968F7D228E036CF42AEB4ABE45A8D1AD0D7226CDEBF91553A2') {
    Write-Warning 'Game hash differs from reference. Required PE/layout and instruction signatures decide compatibility.'
}
& $Zig cc -target x86-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror -shared `
    (Join-Path $src 'plugin.c') (Join-Path $src 'patch.c') (Join-Path $src 'exports.def') `
    -ladvapi32 -lkernel32 -o $plugin
if ($LASTEXITCODE) { throw 'ASI compilation failed.' }
$test = Join-Path $testDir 'native_test.exe'
& $Zig cc -target x86-windows-gnu -std=c11 -O2 -Wall -Wextra -Werror `
    (Join-Path $projectRoot 'tests\native_test.c') (Join-Path $src 'patch.c') -lkernel32 -o $test
if ($LASTEXITCODE) { throw 'Native test compilation failed.' }
$testLog = Join-Path $dist 'Cricket07FreeHit.log'
$initialLogBytes = if (Test-Path -LiteralPath $testLog) { (Get-Item -LiteralPath $testLog).Length } else { 0 }
$testOutput = & $test $plugin $exe
$testExit = $LASTEXITCODE
$testOutput | Tee-Object -FilePath (Join-Path $testDir 'results.txt')
if ($testExit) { throw 'Native execution/compatibility tests failed.' }
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $initialExeHash) {
    throw 'Executable changed during build/validation.'
}
if (Test-Path -LiteralPath $testLog) {
    $logBytes = [IO.File]::ReadAllBytes($testLog)
    if ($logBytes.Length -le $initialLogBytes) { throw 'The ASI did not append a new test initialization log.' }
    $logText = [Text.Encoding]::UTF8.GetString($logBytes, [int]$initialLogBytes, [int]($logBytes.Length - $initialLogBytes))
    if ($logText -notmatch 'WARNING: executable SHA-256 differs' -or $logText -notmatch 'NOT APPLIED') {
        throw 'Expected modified-hash warning and safe host-rejection log entries were not observed.'
    }
    [IO.File]::WriteAllText((Join-Path $testDir 'loader-rejection.log'), $logText, [Text.UTF8Encoding]::new($false))
} else {
    throw 'The ASI did not create the expected test initialization log.'
}
Get-FileHash -LiteralPath $plugin -Algorithm SHA256
if ($Install) {
    if (Get-Process Cricket07 -ErrorAction SilentlyContinue) { throw 'Close Cricket07 before installing the ASI.' }
    $destination = Join-Path $GameDirectory 'Cricket07FreeHit.asi'
    if (Test-Path -LiteralPath $destination) {
        if ((Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $plugin).Hash) {
            throw 'A different Cricket07FreeHit.asi already exists. Preserve it before installing this build.'
        }
        Write-Output 'This exact build is already installed.'
    } else {
        Copy-Item -LiteralPath $plugin -Destination $destination
        Write-Output "Installed $destination"
    }
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $initialExeHash) {
        throw 'Executable changed during installation.'
    }
    Get-FileHash -LiteralPath $destination -Algorithm SHA256
}
