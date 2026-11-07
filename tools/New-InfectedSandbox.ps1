<#
.SYNOPSIS
  가짜 "감염된 PC" 환경을 만들어 NikkeCheck 화면과 복구 흐름을 시험합니다 (개발·QA용).
  실제 악성코드는 전혀 없습니다. 공개된 침해 지표와 모양만 같은 더미 파일·레지스트리 값입니다.

.EXAMPLE
  .\tools\New-InfectedSandbox.ps1 -Path C:\temp\nikke-sandbox
  $env:NIKKECHECK_SANDBOX = 'C:\temp\nikke-sandbox'; .\dist\NikkeCheck.exe

.EXAMPLE
  .\tools\New-InfectedSandbox.ps1 -Path C:\temp\nikke-sandbox -Remove
#>
param(
    [Parameter(Mandatory = $true)] [string] $Path,
    [switch] $Remove
)
$ErrorActionPreference = 'Stop'
$regRoot = 'HKCU:\Software\NikkeCheckSandbox'

if ($Remove) {
    if (Test-Path $regRoot) { Remove-Item $regRoot -Recurse -Force }
    if (Test-Path $Path) { Remove-Item $Path -Recurse -Force }
    Write-Output "샌드박스를 삭제했습니다."
    return
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-Bytes([string]$file, [byte[]]$bytes) {
    New-Item -ItemType Directory -Force -Path (Split-Path $file) | Out-Null
    [IO.File]::WriteAllBytes($file, $bytes)
}
function Write-Text([string]$file, [string]$text) { Write-Bytes $file $utf8.GetBytes($text) }

$install = Join-Path $Path 'NIKKE'
$roaming = Join-Path $Path 'AppData\Roaming'
$local = Join-Path $Path 'AppData\Local'
$temp = Join-Path $Path 'Temp'
New-Item -ItemType Directory -Force -Path $install, $roaming, $local, $temp | Out-Null
Write-Text (Join-Path $Path 'hosts') "127.0.0.1 localhost`r`n"

# Launcher log with the official indicator
Write-Text "$install\Launcher\intl_service\debug.log" ((
    '[2026-11-03 09:47:01] intl_service start',
    '[2026-11-03 09:47:05] lua downloaded to log\tinyget\tinyget.20261103-004700.log',
    '[2026-11-03 09:47:05] k2f_chan registered',
    '[2026-11-03 09:47:06] adopted 6f1c2a3b-1d2e-4f5a-9b8c-7d6e5f4a3b2c',
    '[2026-11-03 09:47:06] agent started as DESKTOP-SANDBOX login_ticket=FAKE_TICKET'
) -join "`r`n")

# 205,135-byte "payload" that starts with the LuaJIT magic (rest is zeros)
$payload = New-Object byte[] 205135
$payload[0] = 0x1B; $payload[1] = 0x4C; $payload[2] = 0x4A; $payload[3] = 0x01
Write-Bytes "$install\Launcher\log\tinyget\tinyget.20261103-004700.log" $payload
Write-Text "$install\Launcher\log\tinyget\tinyget.mem.log" "HTTP/1.1 200 OK`r`nReferer: https://analytics.insightjs.com/`r`n"

# Launcher cache
$cache = "$roaming\nikke_launcher\tbs_cache"
Write-Text "$cache\Local Storage\leveldb\000003.log" ("_https://launcher" + [char]0 + [char]1 + 'k2f.agent.state{"agent_id":"sandbox"}')
$ms = New-Object IO.MemoryStream
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
$js = $utf8.GetBytes('!function(){var h=String.fromCharCode(111,114,103);}();')
$gz.Write($js, 0, $js.Length); $gz.Close()
[byte[]]$entry = $utf8.GetBytes("1/0/https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js" + [char]0) + $ms.ToArray()
Write-Bytes "$cache\Cache\Cache_Data\f_000123" $entry
Write-Text "$cache\Code Cache\js\dd65fa4d61079e7e_0" '_keyhttps://insightjs.com/l.js?f=aegis'

# Chrome DLL persistence + legit Chrome files that must survive
$peh = "$local\Google\Chrome\User Data\PlatformExperienceHelper"
$hex = '3f9a1c0b7d2e4f6a8b9c0d1e2f3a4b5c6d7e8f9012345678abcdef0123456789'
Write-Text "$peh\$hex\platform_experience_helper.dll" 'MZ (sandbox dummy, not a real DLL)'
Write-Bytes "$peh\LoadFeatures" (New-Object byte[] 0)

# Agent temp files
Write-Text "$temp\k2f_screen_1762130000_1.jpg" 'dummy'
Write-Text "$temp\k2f-bcreds-1762130000-ab12.db" 'dummy'

# Registry (isolated under HKCU\Software\NikkeCheckSandbox)
$key = "$regRoot\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name '(default)' -Value "$peh\$hex\platform_experience_helper.dll"

Write-Output "샌드박스 생성: $Path"
Write-Output "실행: `$env:NIKKECHECK_SANDBOX = '$Path'; NikkeCheck.exe"
