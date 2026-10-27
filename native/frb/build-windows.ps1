# Build the isolated official Windows client; never install or launch it.
# Each -File invocation owns only its process environment. Source/patch identity
# and fresh client/engine staging are checked by sync-client-to-windows.sh.
# Flutter configuration follows Flutter 3.24.5's cmake.dart,
# windows/build_windows.dart and BuildInfo.toEnvironmentConfig(). The upstream
# windows/flutter/CMakeLists.txt and tool_backend.bat perform assemble/AOT/assets.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('preflight', 'kernel', 'client')]
    [string] $Stage,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $ClientDirectory,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $BridgeDirectory,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $FlutterRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $RustToolchain,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $VisualStudioRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $CMakePath,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $CMakeToolchainFile,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $LibvpxPrefix,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string] $EngineDll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = 'x86_64-pc-windows-msvc'
$generator = 'Visual Studio 17 2022'
$approvedLockHash = 'bc58506b80464e5b3f6c73669c79ef270949b3cbc85401c290aa92e4573df7f7'

function Get-WindowsPath([string] $Value, [string] $Name) {
    # These inputs enter cmd.exe, CMake and MSBuild. Accept ordinary absolute
    # drive paths (including spaces, parentheses and package-version '+'), not expressions.
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value -notmatch '^[A-Za-z]:[\\/][A-Za-z0-9 _().+/\\-]+$') {
        throw "$Name must be an absolute Windows drive path without metacharacters."
    }
    $path = $Value.Replace('\', '/').TrimEnd('/')
    foreach ($part in $path.Substring(3).Split('/')) {
        if ($part.Length -eq 0 -or $part -in @('.', '..') -or
            $part -ne $part.Trim() -or $part.EndsWith('.') -or
            $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw "$Name contains an invalid Windows path component."
        }
    }
    return [IO.Path]::GetFullPath($path).Replace('\', '/').TrimEnd('/')
}

function Require-File([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is absent: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "Required file is empty: $Path"
    }
}

function Require-Directory([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Required directory is absent: $Path"
    }
}

function Stop-NativeFailure([string] $Program, [int] $Code) {
    $failure = [System.Exception]::new("$Program failed with exit code $Code.")
    $failure.Data['ExitCode'] = $Code
    throw $failure
}

function Require-TextureExport([string] $Dll, [string] $Dumpbin) {
    $exports = Invoke-Native $Dumpbin @('/exports', $Dll) -Capture
    if ($exports -notmatch '(?m)^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+rd_engine_windows_texture_wait_progress(?:\s|$)') {
        throw 'Engine DLL lacks the required rd_engine_windows_texture_wait_progress export.'
    }
    Write-Host 'Static DLL export check: rd_engine_windows_texture_wait_progress present.'
}

function Invoke-Native {
    param([string] $Program, [string[]] $Arguments, [switch] $Capture)
    # Arguments here are validated paths or fixed switches, never shell text.
    $quoted = foreach ($argument in $Arguments) {
        if ($argument.Contains('"') -or $argument -match '[\r\n]' -or $argument.EndsWith('\')) {
            throw 'Unsupported native command argument.'
        }
        '"' + $argument + '"'
    }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Program
    $info.Arguments = $quoted -join ' '
    if ($Program.EndsWith('.bat', [StringComparison]::OrdinalIgnoreCase)) {
        $info.FileName = $script:cmdExe
        $info.Arguments = '/d /v:off /s /c ""' + $Program + '" ' + ($quoted -join ' ') + '"'
    }
    $info.WorkingDirectory = (Get-Location).ProviderPath
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $Capture.IsPresent
    $info.RedirectStandardError = $Capture.IsPresent
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw "Could not start $Program" }
        if ($Capture) {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
        }
        $process.WaitForExit()
        if ($Capture) {
            $text = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        }
        if ($process.ExitCode -ne 0) {
            if ($Capture -and $text.Length -gt 0) { [Console]::Error.Write($text) }
            Stop-NativeFailure $Program $process.ExitCode
        }
        if ($Capture) { return $text.Trim() }
    } finally {
        $process.Dispose()
    }
}

function Import-VcVars64([string] $BatchFile) {
    # Capture, never log, the environment produced by vcvars64. /u preserves
    # Unicode values; /d and /v:off prevent AutoRun/delayed-expansion surprises.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $script:cmdExe
    $info.Arguments = '/u /d /v:off /s /c "call "' + $BatchFile + '" >nul && set"'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::Unicode
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Could not enter the selected vcvars64 environment.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $environmentText = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            if ($errorText.Length -gt 0) { [Console]::Error.Write($errorText) }
            Stop-NativeFailure 'vcvars64.bat' $process.ExitCode
        }
        foreach ($line in ($environmentText -split '\r?\n')) {
            if ($line -match '^([^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            }
        }
    } finally {
        $process.Dispose()
    }
}

function Clear-NativeDependencyEnvironment {
    # cmake-rs accepts target-qualified variants before the unqualified names.
    # Clear these process-local overrides before selecting the kernel inputs;
    # the client must not inherit any Cargo/vcpkg dependency configuration.
    foreach ($name in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        if ($name -match '^(?:(?:HOST_|TARGET_)?CMAKE(?:_|$)|ZLIB(?:_|$)|LIBVPX(?:_|$)|VCPKG(?:_|$))') {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
}

function Get-Hash([string] $Path) {
    Require-File $Path
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Require-Hash([string] $Path, [string] $Expected) {
    if ((Get-Hash $Path) -cne $Expected) { throw "SHA-256 mismatch: $Path" }
}

function Read-MetadataValue([string] $Text, [string] $Key, [string] $Source) {
    $rows = [regex]::Matches($Text, '(?m)^[ \t]*' + [regex]::Escape($Key) + '[ \t]*:[^\r\n]*')
    if ($rows.Count -ne 1) { throw "Expected exactly one $Key in $Source" }
    $prefix = $Key + ': '
    $row = $rows[0].Value
    if (-not $row.StartsWith($prefix, [StringComparison]::Ordinal)) {
        throw "Malformed $Key in $Source"
    }
    $value = $row.Substring($prefix.Length)
    if ($value.Length -eq 0 -or $value -cne $value.Trim()) { throw "Malformed $Key in $Source" }
    return $value
}

function Read-OfficialVersionPin([string] $Bridge) {
    $metadataPath = "$Bridge/UPSTREAM.txt"
    $lockPath = "$Bridge/UPSTREAM.lock"
    Require-File $metadataPath
    Require-File $lockPath
    $metadata = [IO.File]::ReadAllText($metadataPath)
    $lockText = [IO.File]::ReadAllText($lockPath)
    if ((Read-MetadataValue $lockText 'Lock' $lockPath) -cne 'rd-engine-native-provenance 1' -or
        (Read-MetadataValue $metadata 'Repository' $metadataPath) -cne 'https://github.com/rustdesk/rustdesk' -or
        (Read-MetadataValue $lockText 'Upstream' $lockPath) -cne 'https://github.com/rustdesk/rustdesk') {
        throw 'Staged provenance does not identify the official RustDesk source and supported lock format.'
    }
    $digestRows = [regex]::Matches($lockText, '(?m)^[^\r\n]*[ \t]native/frb/UPSTREAM\.txt[ \t]*\r?$')
    if ($digestRows.Count -ne 1) { throw 'Expected exactly one UPSTREAM.txt digest in the staged provenance lock.' }
    $digest = [regex]::Match($digestRows[0].Value, '\A([0-9a-f]{64})  native/frb/UPSTREAM\.txt\r?\z')
    if (-not $digest.Success) { throw 'Malformed UPSTREAM.txt digest in the staged provenance lock.' }
    Require-Hash $metadataPath $digest.Groups[1].Value
    $pin = @{
        ProductVersion = Read-MetadataValue $metadata 'Official product version' $metadataPath
        FlutterVersion = Read-MetadataValue $metadata 'Official Flutter package version' $metadataPath
        ClientRevision = Read-MetadataValue $metadata 'Commit' $metadataPath
        MetadataHash = $digest.Groups[1].Value
        LockHash = Get-Hash $lockPath
    }
    if ($pin.ClientRevision -cnotmatch '\A[0-9a-f]{40}\z' -or
        $pin.ProductVersion -cnotmatch '\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\z' -or
        $pin.FlutterVersion -cnotmatch ('\A' + [regex]::Escape($pin.ProductVersion) + '\+(?:0|[1-9][0-9]*)\z')) {
        throw 'Staged official versions must be numeric product X.Y.Z and matching Flutter X.Y.Z+N with an exact Git revision.'
    }
    foreach ($field in @(@('Official product version', 'ProductVersion'),
        @('Official Flutter package version', 'FlutterVersion'), @('Upstream commit', 'ClientRevision'))) {
        if ((Read-MetadataValue $lockText $field[0] $lockPath) -cne $pin[$field[1]]) {
            throw "Staged UPSTREAM.txt and UPSTREAM.lock disagree on $($field[0])."
        }
    }
    return $pin
}

function Require-OfficialBuildVersion([string] $BuildRecords, [hashtable] $Pin) {
    Require-Directory $BuildRecords
    # The FRB crate owns these env values, not rd-engine's separate VPx record.
    $records = @(Get-ChildItem -LiteralPath $BuildRecords -Directory | Where-Object {
        $_.Name -cmatch '^rd-engine-flutter-[0-9a-f]+$' -and (Test-Path -LiteralPath "$($_.FullName)/output" -PathType Leaf)
    })
    if ($records.Count -ne 1) { throw 'Expected exactly one current rd-engine-flutter build-script output.' }
    $outputPath = $records[0].FullName.Replace('\', '/') + '/output'
    Require-File $outputPath
    $lines = [IO.File]::ReadAllLines($outputPath)
    foreach ($field in @(@('RD_OFFICIAL_PRODUCT_VERSION', $Pin.ProductVersion),
        @('RD_OFFICIAL_FLUTTER_VERSION', $Pin.FlutterVersion), @('RD_OFFICIAL_CLIENT_REVISION', $Pin.ClientRevision))) {
        $declarations = @($lines | Where-Object { $_ -cmatch ('^cargo:{1,2}rustc-env=' + $field[0] + '(?:=|$)') })
        if ($declarations.Count -ne 1 -or $declarations[0] -cne "cargo:rustc-env=$($field[0])=$($field[1])") {
            throw "Current rd-engine-flutter output does not establish exactly the pinned $($field[0])."
        }
    }
    return $outputPath
}

function Get-VersionIdentity([hashtable] $Pin, [string] $DllHash) {
    return (@(
        'Identity: rd-engine-flutter-official-version 1'
        "Official product version: $($Pin.ProductVersion)"
        "Official Flutter package version: $($Pin.FlutterVersion)"
        "Official client revision: $($Pin.ClientRevision)"
        "UPSTREAM.txt SHA256: $($Pin.MetadataHash)"
        "UPSTREAM.lock SHA256: $($Pin.LockHash)"
        "DLL SHA256: $DllHash"
    ) -join "`n") + "`n"
}

function Read-OfficialClientVersion([string] $Path, [string] $Expected) {
    Require-File $Path
    $rows = [regex]::Matches([IO.File]::ReadAllText($Path), '(?m)^version[ \t]*:[^\r\n]*')
    if ($rows.Count -ne 1) { throw 'Expected exactly one version declaration in the staged client pubspec.yaml.' }
    $version = [regex]::Match($rows[0].Value,
        '\Aversion:[ \t]*((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\+(0|[1-9][0-9]*))[ \t]*(?:#[^\r\n]*)?\z')
    if (-not $version.Success -or $version.Groups[1].Value -cne $Expected) {
        throw "The staged client pubspec.yaml must match Official Flutter package version $Expected."
    }
    return $version
}

function Read-PluginLists([string] $Path) {
    Require-File $Path
    $text = [IO.File]::ReadAllText($Path)
    $lists = @{}
    foreach ($name in @('FLUTTER_PLUGIN_LIST', 'FLUTTER_FFI_PLUGIN_LIST')) {
        $blocks = [regex]::Matches($text, "(?ms)^list\(APPEND\s+$name\s*(.*?)\)")
        if ($blocks.Count -ne 1) { throw "Expected one $name in $Path" }
        $plugins = @($blocks[0].Groups[1].Value.Trim() -split '\s+' | Where-Object { $_.Length -gt 0 })
        foreach ($plugin in $plugins) {
            if ($plugin -cnotmatch '^[a-z][a-z0-9_]*$') { throw "Invalid plugin entry in $Path" }
        }
        $lists[$name] = $plugins
    }
    $all = @($lists['FLUTTER_PLUGIN_LIST']) + @($lists['FLUTTER_FFI_PLUGIN_LIST'])
    if ($lists['FLUTTER_PLUGIN_LIST'].Count -eq 0 -or
        @($all | Sort-Object -Unique).Count -ne $all.Count) {
        throw "Empty method-channel list or duplicate native plugins in $Path"
    }
    return $lists
}

function Read-PluginRegistrations([string] $Path) {
    Require-File $Path
    $text = [IO.File]::ReadAllText($Path)
    return @([regex]::Matches($text,
        '(\w+RegisterWithRegistrar)\(\s*registry->GetRegistrarForPlugin\("(\w+)"\)\);') |
        ForEach-Object { $_.Groups[1].Value + ':' + $_.Groups[2].Value })
}

$initialEnvironment = [Environment]::GetEnvironmentVariables('Process')
$initialLocation = Get-Location
$exitCode = 0
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This driver requires native Windows PowerShell/PowerShell on Windows.'
    }
    $ClientDirectory = Get-WindowsPath $ClientDirectory 'ClientDirectory'
    $BridgeDirectory = Get-WindowsPath $BridgeDirectory 'BridgeDirectory'
    $FlutterRoot = Get-WindowsPath $FlutterRoot 'FlutterRoot'
    $VisualStudioRoot = Get-WindowsPath $VisualStudioRoot 'VisualStudioRoot'
    $CMakePath = Get-WindowsPath $CMakePath 'CMakePath'
    $CMakeToolchainFile = Get-WindowsPath $CMakeToolchainFile 'CMakeToolchainFile'
    $LibvpxPrefix = Get-WindowsPath $LibvpxPrefix 'LibvpxPrefix'
    $EngineDll = Get-WindowsPath $EngineDll 'EngineDll'
    if ($RustToolchain -cnotmatch '^1\.95(?:\.0)?-x86_64-pc-windows-msvc$') {
        throw 'RustToolchain must name the installed 1.95/1.95.0 x86_64-pc-windows-msvc toolchain.'
    }
    $targetDirectory = "$BridgeDirectory/target"
    if ($EngineDll -ine "$targetDirectory/$target/release/rd_engine_flutter.dll") {
        throw 'EngineDll must be the exact bridge/target/x86_64-pc-windows-msvc/release/rd_engine_flutter.dll.'
    }
    $versionIdentity = "$targetDirectory/$target/release/official-version-identity.txt"
    $bundledCmake = "$VisualStudioRoot/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
    if ($CMakePath -ine $bundledCmake) { throw 'Select the verified VS2022 bundled CMake, not global CMake.' }
    if ($LibvpxPrefix -notmatch '/installed/x64-windows-static-md$') {
        throw 'LibvpxPrefix must select the isolated installed/x64-windows-static-md dependency prefix.'
    }
    # cmd.exe parses its own command line: a forward-slash /cmd.exe path is
    # mistaken for /c and executes the remaining text instead of our command.
    $script:cmdExe = (Get-WindowsPath ([IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe')) 'cmd.exe').Replace('/', '\')
    $flutter = "$FlutterRoot/bin/flutter.bat"
    $dart = "$FlutterRoot/bin/cache/dart-sdk/bin/dart.exe"
    $backend = "$FlutterRoot/packages/flutter_tools/bin/tool_backend.bat"
    $vcvars64 = "$VisualStudioRoot/VC/Auxiliary/Build/vcvars64.bat"
    foreach ($file in @($script:cmdExe, $flutter, $dart, $backend, $vcvars64, $CMakePath, $CMakeToolchainFile)) {
        Require-File $file
    }

    # No client/engine directory is read, created or modified by these checks.
    Set-Location -LiteralPath $FlutterRoot
    Clear-NativeDependencyEnvironment
    Import-VcVars64 $vcvars64
    if ($env:VisualStudioVersion -notmatch '^17\.' -or
        $env:VSCMD_ARG_HOST_ARCH -ine 'x64' -or $env:VSCMD_ARG_TGT_ARCH -ine 'x64') {
        throw 'vcvars64 did not select the VS2022 x64 host/target toolchain.'
    }
    $vcTools = Get-WindowsPath $env:VCToolsInstallDir 'VCToolsInstallDir'
    if (-not $vcTools.StartsWith("$VisualStudioRoot/VC/Tools/MSVC/14.", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'vcvars64 selected compiler tools outside the requested VS2022 instance.'
    }
    $compiler = "$vcTools/bin/Hostx64/x64/cl.exe"
    $linker = "$vcTools/bin/Hostx64/x64/link.exe"
    $librarian = "$vcTools/bin/Hostx64/x64/lib.exe"
    $dumpbin = "$vcTools/bin/Hostx64/x64/dumpbin.exe"
    foreach ($file in @($compiler, $linker, $librarian, $dumpbin)) { Require-File $file }
    foreach ($toolPath in @($compiler, $linker)) {
        $resolved = @(Get-Command ([IO.Path]::GetFileName($toolPath)) -CommandType Application -ErrorAction Stop)[0].Source
        if ((Get-WindowsPath $resolved 'MSVC executable') -ine $toolPath) {
            throw 'The selected vcvars64 environment does not resolve the real MSVC compiler/linker.'
        }
    }
    $compilerInfo = Invoke-Native $compiler @('/?') -Capture
    if ($compilerInfo -notmatch '19\.\d+\.\d+' -or $compilerInfo -notmatch 'x64') {
        throw 'The selected compiler did not identify an x64 MSVC compiler.'
    }
    $compilerVersion = [regex]::Match($compilerInfo, '19\.\d+\.\d+(?:\.\d+)?').Value
    $cmakeInfo = Invoke-Native $CMakePath @('--version') -Capture
    if ($cmakeInfo -notmatch '(?m)^cmake version 3\.31\.6-msvc6\s*$') {
        throw 'The selected CMake must report the verified 3.31.6-msvc6 version.'
    }
    $flutterInfo = (Invoke-Native $flutter @('--version', '--machine') -Capture) | ConvertFrom-Json
    if ($flutterInfo.frameworkVersion -cne '3.24.5' -or $flutterInfo.dartSdkVersion -cne '3.5.4' -or
        $flutterInfo.repositoryUrl -notmatch '^https://github\.com/flutter/flutter(?:\.git)?$') {
        throw 'The selected SDK is not official Flutter 3.24.5 / Dart 3.5.4.'
    }
    $dartInfo = Invoke-Native $dart @('--version') -Capture
    if ($dartInfo -notmatch '^Dart SDK version: 3\.5\.4(?:\s|$)') {
        throw 'The selected SDK Dart executable does not report 3.5.4.'
    }
    $rustup = Get-WindowsPath @(Get-Command rustup.exe -CommandType Application -ErrorAction Stop)[0].Source 'rustup.exe'
    $cargoLauncher = ([IO.Path]::GetDirectoryName($rustup)).Replace('\', '/') + '/cargo.exe'
    Require-File $cargoLauncher
    # `which` fails for a missing toolchain before a proxy could install one.
    $rustc = Get-WindowsPath (Invoke-Native $rustup @('which', '--toolchain', $RustToolchain, 'rustc') -Capture) 'selected rustc'
    $cargo = Get-WindowsPath (Invoke-Native $rustup @('which', '--toolchain', $RustToolchain, 'cargo') -Capture) 'selected cargo'
    Require-File $rustc
    Require-File $cargo
    $rustInfo = Invoke-Native $rustc @('-vV') -Capture
    $cargoInfo = Invoke-Native $cargo @('--version') -Capture
    if ($rustInfo -notmatch '(?m)^release: 1\.95\.0\s*$' -or
        $rustInfo -notmatch '(?m)^host: x86_64-pc-windows-msvc\s*$' -or
        $cargoInfo -notmatch '^cargo 1\.95\.0(?:\s|$)') {
        throw 'The selected Rust/cargo must report 1.95.0 with the native x86_64-pc-windows-msvc host.'
    }

    foreach ($relative in @('include/vpx/vpx_decoder.h', 'lib/vpx.lib', 'lib/pkgconfig/vpx.pc',
        'include/zlib.h', 'lib/zs.lib', 'share/zlib/vcpkg-cmake-wrapper.cmake')) {
        Require-File "$LibvpxPrefix/$relative"
    }
    $vpxPc = [IO.File]::ReadAllText("$LibvpxPrefix/lib/pkgconfig/vpx.pc")
    $vpxVersions = [regex]::Matches($vpxPc, '(?m)^Version:[ \t]*([^\r\n]+)')
    if ($vpxVersions.Count -ne 1 -or $vpxVersions[0].Groups[1].Value.Trim() -cne '1.15.2') {
        throw 'The installed vpx.pc must report exactly libvpx 1.15.2.'
    }
    $zlibHeader = [IO.File]::ReadAllText("$LibvpxPrefix/include/zlib.h")
    if ($zlibHeader -notmatch '(?m)^#define[ \t]+ZLIB_VERSION[ \t]+"1\.3\.2"[ \t]*\r?$') {
        throw 'The selected Zlib headers must report 1.3.2.'
    }
    # Accept only the recorded three-command wrapper, not a text mention of the
    # right prefix followed by commands that select a different installed root.
    $wrapper = [IO.File]::ReadAllText($CMakeToolchainFile).TrimStart([char]0xFEFF)
    $wrapper = [regex]::Replace($wrapper, '(?m)^[ \t]*#[^\r\n]*\r?\n?', '')
    $wrapperPattern = '\A\s*set\(\s*VCPKG_TARGET_TRIPLET\s+"x64-windows-static-md"\s+CACHE\s+STRING\s+""(?:\s+FORCE)?\s*\)\s*' +
        'set\(\s*VCPKG_INSTALLED_DIR\s+"(?<installed>[^"]+)"\s+CACHE\s+PATH\s+""(?:\s+FORCE)?\s*\)\s*' +
        'include\(\s*"(?<toolchain>[^"]+)"\s*\)\s*\z'
    $wrapperMatch = [regex]::Match($wrapper, $wrapperPattern)
    if (-not $wrapperMatch.Success) { throw 'Dependency wrapper differs from the recorded static-md installed-root contract.' }
    $installedRoot = Get-WindowsPath $wrapperMatch.Groups['installed'].Value 'VCPKG_INSTALLED_DIR'
    $vcpkgToolchain = Get-WindowsPath $wrapperMatch.Groups['toolchain'].Value 'vcpkg toolchain include'
    if ("$installedRoot/x64-windows-static-md" -ine $LibvpxPrefix -or
        $vcpkgToolchain -notmatch '/scripts/buildsystems/vcpkg\.cmake$') {
        throw 'Dependency wrapper does not select the actual requested installed prefix/toolchain.'
    }
    Require-File $vcpkgToolchain
    Write-Host "Flutter 3.24.5 / Dart 3.5.4: $FlutterRoot"
    Write-Host "Rust/cargo 1.95.0 ($RustToolchain): $rustc ; $cargo"
    Write-Host "VS2022 x64 MSVC $compilerVersion`: $compiler ; linker: $linker"
    Write-Host "CMake 3.31.6-msvc6: $CMakePath"
    Write-Host "libvpx 1.15.2 / Zlib 1.3.2 static-md: $LibvpxPrefix"
    Write-Host "Dependency wrapper: $CMakeToolchainFile ; installed root: $installedRoot ; include: $vcpkgToolchain"

    switch ($Stage) {
        'preflight' {
            Write-Host 'Preflight complete; client/engine source directories were not required or modified.'
        }
        'kernel' {
            Require-File "$BridgeDirectory/Cargo.toml"
            Require-File "$BridgeDirectory/Cargo.lock"
            $officialPin = Read-OfficialVersionPin $BridgeDirectory
            if (Test-Path -LiteralPath $targetDirectory) {
                throw 'Kernel requires a fresh bridge/target. Retain the failed tree and stage a new isolated build; nothing was deleted.'
            }
            Clear-NativeDependencyEnvironment
            $env:CMAKE = $CMakePath
            $env:CMAKE_GENERATOR = $generator
            $env:CMAKE_GENERATOR_INSTANCE = $VisualStudioRoot
            $env:CMAKE_GENERATOR_TOOLSET = 'v143'
            $env:CMAKE_GENERATOR_PLATFORM = 'x64'
            $env:CMAKE_TOOLCHAIN_FILE = $CMakeToolchainFile
            $env:LIBVPX_PREFIX = $LibvpxPrefix
            $env:ZLIB_ROOT = $LibvpxPrefix
            $env:RUSTUP_TOOLCHAIN = $RustToolchain
            $env:RUSTC = $rustc
            $env:CARGO_BUILD_RUSTC = $rustc
            $env:CARGO_BUILD_BUILD_DIR = $targetDirectory
            $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $linker
            foreach ($entry in @(@('CC', $compiler), @('CXX', $compiler), @('AR', $librarian))) {
                foreach ($key in @($entry[0], "$($entry[0])_$target", "$($entry[0])_x86_64_pc_windows_msvc", "HOST_$($entry[0])", "TARGET_$($entry[0])")) {
                    [Environment]::SetEnvironmentVariable($key, $entry[1], 'Process')
                }
            }
            Set-Location -LiteralPath $BridgeDirectory
            Invoke-Native $cargoLauncher @("+$RustToolchain", 'build', '--locked', '--release', '--target', $target, '--target-dir', $targetDirectory)
            Require-File $EngineDll
            Require-TextureExport $EngineDll $dumpbin
            $buildRecords = "$targetDirectory/$target/release/build"
            Require-Directory $buildRecords
            $engineRecords = @(Get-ChildItem -LiteralPath $buildRecords -Directory | Where-Object {
                $_.Name -match '^rd-engine-[0-9a-f]+$' -and (Test-Path -LiteralPath "$($_.FullName)/output" -PathType Leaf)
            })
            if ($engineRecords.Count -ne 1) { throw 'Expected exactly one current rd-engine build-script output.' }
            $recordRoot = $engineRecords[0].FullName.Replace('\', '/')
            $output = [IO.File]::ReadAllText("$recordRoot/output").Replace('\', '/') -split '\r?\n'
            $provenance = "cargo:rustc-env=RD_LIBVPX_PROVENANCE=static via LIBVPX_PREFIX: headers $LibvpxPrefix/include library $LibvpxPrefix/lib (1.15.2)"
            foreach ($required in @('cargo:rustc-link-lib=static=vpx', 'cargo:rustc-cfg=rd_vpx_linked',
                "cargo:rustc-link-search=native=$LibvpxPrefix/lib", $provenance)) {
                if ($output -notcontains $required) { throw "Current build does not establish required VPx linkage: $required" }
            }
            if ($output -match '^cargo:rustc-env=RD_LIBVPX_PROVENANCE=unavailable:') {
                throw 'Current build reports an unavailable VPx backend.'
            }
            $zlibReport = "$recordRoot/out/build/rd_vnc_zlib_Release.txt"
            Require-File $zlibReport
            $linkedZlib = Get-WindowsPath ([IO.File]::ReadAllText($zlibReport).Trim()) 'VNC Zlib report'
            if ($linkedZlib -ine "$LibvpxPrefix/lib/zs.lib") {
                throw 'The current VNC CMake report does not name the selected static-md Zlib library.'
            }
            $frbVersionOutput = Require-OfficialBuildVersion $buildRecords $officialPin
            Require-Hash "$BridgeDirectory/UPSTREAM.txt" $officialPin.MetadataHash
            Require-Hash "$BridgeDirectory/UPSTREAM.lock" $officialPin.LockHash
            $engineHash = Get-Hash $EngineDll
            [IO.File]::WriteAllText($versionIdentity, (Get-VersionIdentity $officialPin $engineHash), [Text.UTF8Encoding]::new($false))
            Write-Host "Official product version: $($officialPin.ProductVersion) ; official Flutter package version: $($officialPin.FlutterVersion)"
            Write-Host "Official client revision: $($officialPin.ClientRevision) ; FRB build-script evidence: $frbVersionOutput"
            Write-Host "Version identity record: $versionIdentity ; provenance lock SHA256=$($officialPin.LockHash)"
            Write-Host 'Runtime implementation: rd-engine via rd-engine-flutter; official product identity is not upstream runtime feature parity.'
            Write-Host "Build-script evidence: $recordRoot/output"
            Write-Host $provenance
            Write-Host "VNC Zlib evidence: $zlibReport -> $linkedZlib"
            Write-Host "Fresh engine DLL: $EngineDll ; SHA256=$engineHash"
        }
        'client' {
            $officialPin = Read-OfficialVersionPin $BridgeDirectory
            $frbVersionOutput = Require-OfficialBuildVersion "$targetDirectory/$target/release/build" $officialPin
            $frbVersionOutputHash = Get-Hash $frbVersionOutput
            Require-File $EngineDll
            Require-TextureExport $EngineDll $dumpbin
            $engineHash = Get-Hash $EngineDll
            Require-File $versionIdentity
            if ([IO.File]::ReadAllText($versionIdentity) -cne (Get-VersionIdentity $officialPin $engineHash)) {
                throw 'The current DLL, official version tuple or provenance digests differ from the fresh kernel identity record.'
            }
            $versionIdentityHash = Get-Hash $versionIdentity
            $lock = "$ClientDirectory/pubspec.lock"
            $pubspec = "$ClientDirectory/pubspec.yaml"
            $flutterCmake = "$ClientDirectory/windows/flutter/CMakeLists.txt"
            $pluginCmake = "$ClientDirectory/windows/flutter/generated_plugins.cmake"
            $registrant = "$ClientDirectory/windows/flutter/generated_plugin_registrant.cc"
            $registrantHeader = "$ClientDirectory/windows/flutter/generated_plugin_registrant.h"
            foreach ($file in @($pubspec, $flutterCmake, "$ClientDirectory/windows/CMakeLists.txt")) {
                Require-File $file
            }
            Read-OfficialClientVersion $pubspec $officialPin.FlutterVersion | Out-Null
            Require-Hash $lock $approvedLockHash
            if (Test-Path -LiteralPath "$ClientDirectory/build") {
                throw 'Client requires a fresh client/build. Retain the failed tree and stage a new isolated build; nothing was deleted.'
            }
            $flutterCmakeHash = Get-Hash $flutterCmake
            $backendHash = Get-Hash $backend
            Clear-NativeDependencyEnvironment
            # tool_backend.dart reads these optional build overrides directly.
            # The recorded desktop configuration has none; do not inherit an
            # ambient custom engine, Dart defines or extra compiler switches.
            foreach ($key in @('FLUTTER_ENGINE', 'LOCAL_ENGINE', 'LOCAL_ENGINE_HOST', 'DART_DEFINES',
                'FRONTEND_SERVER_STARTER_PATH', 'EXTRA_FRONT_END_OPTIONS', 'EXTRA_GEN_SNAPSHOT_OPTIONS',
                'SPLIT_DEBUG_INFO', 'BUNDLE_SKSL_PATH', 'CODE_SIZE_DIRECTORY', 'FLUTTER_TOOL_ARGS')) {
                [Environment]::SetEnvironmentVariable($key, $null, 'Process')
            }
            $env:FLUTTER_ROOT = $FlutterRoot
            # Do not consume a shared cache that another Flutter/OHOS SDK may
            # have patched in place. Keep this build's locked packages private.
            $env:PUB_CACHE = "$ClientDirectory/.pub-cache"
            Set-Location -LiteralPath $ClientDirectory
            Invoke-Native $flutter @('precache', '--windows')
            Invoke-Native $flutter @('pub', 'get', '--enforce-lockfile')
            Require-Hash $lock $approvedLockHash
            Require-Hash $flutterCmake $flutterCmakeHash
            Require-Hash $backend $backendHash
            $actualPlugins = Read-PluginLists $pluginCmake
            Require-File $registrantHeader
            if ([IO.File]::ReadAllText($registrantHeader) -notmatch 'void RegisterPlugins\(flutter::PluginRegistry\* registry\);') {
                throw 'Regenerated Windows plugin registrant header is invalid.'
            }
            $registrations = @(Read-PluginRegistrations $registrant)
            if ($registrations.Count -ne $actualPlugins['FLUTTER_PLUGIN_LIST'].Count) {
                throw 'Regenerated Windows method-channel registrations do not match the resolved plugin list.'
            }
            $registrantText = [IO.File]::ReadAllText($registrant)
            foreach ($plugin in $actualPlugins['FLUTTER_PLUGIN_LIST']) {
                if ($registrantText -notmatch ("(?m)^#include\s+<" + [regex]::Escape($plugin) + '/[^>]+>\s*$')) {
                    throw "Regenerated registrant does not include $plugin."
                }
            }
            $pluginMetadata = "$ClientDirectory/.flutter-plugins-dependencies"
            Require-File $pluginMetadata
            $metadata = [IO.File]::ReadAllText($pluginMetadata) | ConvertFrom-Json
            if ($metadata.version -cne '3.24.5') { throw 'Plugin metadata was not generated by Flutter 3.24.5.' }
            $nativePlugins = @($metadata.plugins.windows | Where-Object { $_.native_build -eq $true })
            $allPlugins = @($actualPlugins['FLUTTER_PLUGIN_LIST']) + @($actualPlugins['FLUTTER_FFI_PLUGIN_LIST'])
            if ((@($nativePlugins.name | Sort-Object) -join "`n") -cne (@($allPlugins | Sort-Object) -join "`n")) {
                throw 'Generated CMake omits or adds a Windows native plugin from the resolved metadata.'
            }
            foreach ($plugin in $allPlugins) {
                $link = "$ClientDirectory/windows/flutter/ephemeral/.plugin_symlinks/$plugin"
                Require-Directory "$link/windows"
                Require-File "$link/windows/CMakeLists.txt"
                $pluginEntry = @($nativePlugins | Where-Object { $_.name -ceq $plugin })
                if ($pluginEntry.Count -ne 1) { throw "Ambiguous resolved Windows plugin: $plugin" }
                # Metadata escapes Windows backslashes for the legacy path
                # representation; it is not a shell expression.
                $source = Get-WindowsPath ($pluginEntry[0].path.Replace('\\', '\')) "plugin $plugin"
                Require-Directory "$source/windows"
                Require-File "$source/windows/CMakeLists.txt"
                Require-Hash "$link/windows/CMakeLists.txt" (Get-Hash "$source/windows/CMakeLists.txt")
            }
            Require-File "$ClientDirectory/.dart_tool/package_config.json"
            Require-Hash "$BridgeDirectory/UPSTREAM.txt" $officialPin.MetadataHash
            Require-Hash "$BridgeDirectory/UPSTREAM.lock" $officialPin.LockHash
            Require-Hash $versionIdentity $versionIdentityHash
            Require-Hash $frbVersionOutput $frbVersionOutputHash
            Require-Hash $EngineDll $engineHash
            $version = (Read-OfficialClientVersion $pubspec $officialPin.FlutterVersion).Groups
            $pubspecHash = Get-Hash $pubspec
            $ephemeral = "$ClientDirectory/windows/flutter/ephemeral"
            $generatedConfig = @"
# Generated build configuration; do not copy from another host.
file(TO_CMAKE_PATH "$FlutterRoot" FLUTTER_ROOT)
file(TO_CMAKE_PATH "$ClientDirectory" PROJECT_DIR)
set(FLUTTER_VERSION "$($version[1].Value)" PARENT_SCOPE)
set(FLUTTER_VERSION_MAJOR $($version[2].Value) PARENT_SCOPE)
set(FLUTTER_VERSION_MINOR $($version[3].Value) PARENT_SCOPE)
set(FLUTTER_VERSION_PATCH $($version[4].Value) PARENT_SCOPE)
set(FLUTTER_VERSION_BUILD $($version[5].Value) PARENT_SCOPE)
list(APPEND FLUTTER_TOOL_ENVIRONMENT
  "FLUTTER_ROOT=$FlutterRoot"
  "PROJECT_DIR=$ClientDirectory"
  "FLUTTER_EPHEMERAL_DIR=$ephemeral"
  "FLUTTER_TARGET=lib/main.dart"
  "DART_OBFUSCATION=false"
  "TRACK_WIDGET_CREATION=true"
  "TREE_SHAKE_ICONS=true"
  "PACKAGE_CONFIG=$ClientDirectory/.dart_tool/package_config.json"
)
"@
            [void][IO.Directory]::CreateDirectory($ephemeral)
            [IO.File]::WriteAllText("$ephemeral/generated_config.cmake", $generatedConfig + "`n", [Text.UTF8Encoding]::new($false))
            $buildDirectory = "$ClientDirectory/build/windows/x64"
            $bundle = "$buildDirectory/runner/Release"
            Invoke-Native $CMakePath @('-S', "$ClientDirectory/windows", '-B', $buildDirectory,
                '-G', $generator, '-A', 'x64', '-T', 'v143',
                "-DCMAKE_GENERATOR_INSTANCE:STRING=$VisualStudioRoot", '-DFLUTTER_TARGET_PLATFORM=windows-x64',
                "-DRUSTDESK_LIB_OVERRIDE:FILEPATH=$EngineDll", "-DCMAKE_INSTALL_PREFIX:PATH=$bundle")
            Invoke-Native $CMakePath @('--build', $buildDirectory, '--config', 'Release', '--target', 'INSTALL')
            foreach ($relative in @('rustdesk.exe', 'flutter_windows.dll', 'librustdesk.dll', 'data/app.so', 'data/icudtl.dat')) {
                Require-File "$bundle/$relative"
            }
            Require-Directory "$bundle/data/flutter_assets"
            # INSTALL's manifest includes plugin/FFI bundled libraries as well
            # as Flutter assets. Check actual install outputs, not guessed DLL
            # filenames derived from package names.
            $manifest = "$buildDirectory/install_manifest.txt"
            Require-File $manifest
            foreach ($entry in [IO.File]::ReadAllLines($manifest)) {
                $installed = [IO.Path]::GetFullPath($entry).Replace('\', '/')
                if (-not $installed.StartsWith("$bundle/", [StringComparison]::OrdinalIgnoreCase)) {
                    throw "CMake INSTALL escaped the private bundle: $installed"
                }
                if (-not (Test-Path -LiteralPath $installed -PathType Leaf)) {
                    throw "CMake INSTALL manifest names a missing file: $installed"
                }
            }
            Require-Hash $EngineDll $engineHash
            Require-Hash "$bundle/librustdesk.dll" $engineHash
            Require-Hash $lock $approvedLockHash
            Require-Hash $flutterCmake $flutterCmakeHash
            Require-Hash $backend $backendHash
            Require-Hash "$BridgeDirectory/UPSTREAM.txt" $officialPin.MetadataHash
            Require-Hash "$BridgeDirectory/UPSTREAM.lock" $officialPin.LockHash
            Require-Hash $versionIdentity $versionIdentityHash
            Require-Hash $frbVersionOutput $frbVersionOutputHash
            Require-Hash $pubspec $pubspecHash
            Write-Host "Official product version: $($officialPin.ProductVersion) ; official Flutter package version: $($version[1].Value)"
            Write-Host "Official client revision: $($officialPin.ClientRevision) ; enforced pub lock SHA256=$approvedLockHash"
            Write-Host "Version identity record: $versionIdentity ; provenance lock SHA256=$($officialPin.LockHash)"
            Write-Host 'Runtime implementation: rd-engine via rd-engine-flutter; official product identity is not upstream runtime feature parity.'
            Write-Host "Windows method-channel plugins: $($actualPlugins['FLUTTER_PLUGIN_LIST'] -join ', ')"
            Write-Host "Windows FFI plugins: $($actualPlugins['FLUTTER_FFI_PLUGIN_LIST'] -join ', ')"
            Write-Host "Private Release bundle: $bundle ; installed files: $manifest"
            Write-Host "Engine/bundle DLL SHA256=$engineHash"
            Write-Host 'Compilation/linkage/package checks only; no application launch, installation, functional or performance claim.'
        }
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $exitCode = 1
    if ($_.Exception.Data.Contains('ExitCode')) { $exitCode = [int]$_.Exception.Data['ExitCode'] }
} finally {
    Set-Location -LiteralPath $initialLocation.ProviderPath
    foreach ($name in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        if (-not $initialEnvironment.Contains($name)) {
            [Environment]::SetEnvironmentVariable($name, $null, 'Process')
        }
    }
    foreach ($name in $initialEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $initialEnvironment[$name], 'Process')
    }
}
exit $exitCode
