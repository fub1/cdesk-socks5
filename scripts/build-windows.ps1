$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
$buildKeys = @('CGO_ENABLED', 'GOOS', 'GOARCH', 'GOAMD64')
$savedBuildEnv = @{}
foreach ($key in $buildKeys) { $savedBuildEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process') }
try {
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOAMD64 = 'v1'
    $revision = git rev-parse --short HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source revision' }
    $dirty = git status --porcelain
    if ($dirty) { $revision += '-dirty' }
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    go build -trimpath -ldflags "-s -w -X main.version=0.2.0-$revision" -o dist/cdesk-socks5-windows-amd64.exe ./cmd/cdesk-socks5
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
    Copy-Item -LiteralPath config.example.json -Destination dist/config.example.json
    Copy-Item -LiteralPath config.oss.example.json -Destination dist/config.oss.example.json
    Copy-Item -LiteralPath LICENSE -Destination dist/LICENSE
    Copy-Item -LiteralPath docs/windows-quickstart.md -Destination dist/QUICKSTART.md
    Copy-Item -LiteralPath docs/rustdesk-oss-bridge.md -Destination dist/OSS-BRIDGE.md
    $artifact = Get-Item -LiteralPath dist/cdesk-socks5-windows-amd64.exe
    $hash = Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256
    "$($hash.Hash.ToLower())  $($artifact.Name)" | Set-Content -LiteralPath dist/SHA256SUMS.txt -Encoding ascii
    Write-Output "Built $($artifact.Name): $($artifact.Length) bytes, SHA256 $($hash.Hash.ToLower())"
} finally {
    foreach ($key in $buildKeys) { [Environment]::SetEnvironmentVariable($key, $savedBuildEnv[$key], 'Process') }
    Pop-Location
}
