<#
.SYNOPSIS
  테스트를 실행하고 배포용 dist\NikkeCheck.exe(+ SHA-256)를 만듭니다.
.EXAMPLE
  .\build.ps1
  .\build.ps1 -SkipTests
#>
param([switch] $SkipTests)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $SkipTests) {
    dotnet test tests\NikkeCheck.Tests\NikkeCheck.Tests.csproj -c Release -nologo
    if ($LASTEXITCODE -ne 0) { throw "테스트 실패" }
}

dotnet build src\NikkeCheck\NikkeCheck.csproj -c Release -nologo
if ($LASTEXITCODE -ne 0) { throw "빌드 실패" }

$dist = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item src\NikkeCheck\bin\Release\net48\NikkeCheck.exe $dist -Force

$exe = Join-Path $dist 'NikkeCheck.exe'
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  NikkeCheck.exe" | Out-File (Join-Path $dist 'NikkeCheck.exe.sha256') -Encoding ascii
Write-Output "완료: $exe"
Write-Output "SHA-256: $hash"
