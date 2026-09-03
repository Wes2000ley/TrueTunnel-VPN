param(
    [Parameter(Mandatory = $true)]
    [string]$Executable,

    [Parameter(Mandatory = $true)]
    [string]$WintunDll
)

$ErrorActionPreference = 'Stop'

$executablePath = [IO.Path]::GetFullPath($Executable)
$wintunPath = [IO.Path]::GetFullPath($WintunDll)
$outputDirectory = [IO.Path]::GetDirectoryName($executablePath)
$testDirectory = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($outputDirectory, 'wintun-pin-negative-test'))
$expectedPrefix = $outputDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar

if (-not $testDirectory.StartsWith(
        $expectedPrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a test directory outside the executable output directory"
}

try {
    if (Test-Path -LiteralPath $testDirectory) {
        Remove-Item -LiteralPath $testDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $testDirectory | Out-Null

    $testExecutable = Join-Path $testDirectory ([IO.Path]::GetFileName($executablePath))
    $testWintun = Join-Path $testDirectory 'wintun.dll'
    Copy-Item -LiteralPath $executablePath -Destination $testExecutable
    Copy-Item -LiteralPath $wintunPath -Destination $testWintun

    # Appending an overlay byte leaves the PE loadable but changes the complete
    # file digest, so this specifically exercises the runtime integrity pin.
    (Get-Item -LiteralPath $testWintun).IsReadOnly = $false
    $stream = [IO.File]::Open($testWintun, [IO.FileMode]::Append,
        [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $stream.WriteByte([byte]0xA5)
    } finally {
        $stream.Dispose()
    }

    $process = Start-Process -FilePath $testExecutable `
        -ArgumentList '--wintun-load-only' `
        -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        throw "Tampered wintun.dll was accepted"
    }

    Write-Output '[PASS] Tampered adjacent Wintun runtime was rejected'

    # A second directory entry can otherwise mutate the same verified file
    # object through an alias. The production loader requires a regular file
    # with exactly one link, so exercise that identity check as well.
    Remove-Item -LiteralPath $testWintun -Force
    New-Item -ItemType HardLink -Path $testWintun -Target $wintunPath | Out-Null
    $hardLinkProcess = Start-Process -FilePath $testExecutable `
        -ArgumentList '--wintun-load-only' `
        -NoNewWindow -Wait -PassThru
    if ($hardLinkProcess.ExitCode -eq 0) {
        throw "Hard-linked wintun.dll was accepted"
    }

    Write-Output '[PASS] Hard-linked adjacent Wintun runtime was rejected'
} finally {
    if (Test-Path -LiteralPath $testDirectory) {
        $resolvedTestDirectory = [IO.Path]::GetFullPath($testDirectory)
        if ($resolvedTestDirectory.StartsWith(
                $expectedPrefix,
                [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedTestDirectory -Recurse -Force
        }
    }
}
