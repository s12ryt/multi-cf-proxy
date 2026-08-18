# 構建腳本：產出 linux/amd64 單一二進制
# 用法：pwsh ./build.ps1 [輸出目錄，默認 .\dist]
param([string]$OutDir = ".\dist")

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"

go build -trimpath -ldflags="-s -w" -o "$OutDir/multi-cf-proxy" .
if ($LASTEXITCODE -ne 0) { throw "構建失敗" }

Write-Host "已產出 $OutDir/multi-cf-proxy (linux/amd64)" -ForegroundColor Green
Get-Item "$OutDir/multi-cf-proxy" | Select-Object Name, Length
