<#
.SYNOPSIS
  Installs the Noema agent as a Windows service.

.EXAMPLE
  .\install-agent.ps1 -Binary .\publish\Noema.Agent.exe -Server https://noema.example.com -Token nmt_... -Allow 192.168.1.0/24

.NOTES
  Run from an elevated PowerShell. The service runs as LocalService, which can send ping and nothing more.
  The credential is stored under ProgramData and locked down to administrators, the system and LocalService.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $Binary,
  [Parameter(Mandatory)] [string] $Server,
  [Parameter(Mandatory)] [string] $Token,
  [string] $Name,
  [string[]] $Allow = @()
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Run as administrator).'
}
if (-not (Test-Path $Binary)) { throw "Cannot find $Binary" }

$serviceName = 'NoemaAgent'
$installDir  = Join-Path $env:ProgramFiles 'Noema\Agent'
$dataDir     = Join-Path $env:ProgramData 'Noema\Agent'
$exe         = Join-Path $installDir 'Noema.Agent.exe'

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Write-Host 'Stopping the existing service...'
  Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
}

Write-Host "Installing the program to $installDir..."
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Path $Binary -Destination $exe -Force

Write-Host "Preparing the data folder $dataDir..."
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
# Remove inherited access, then allow only administrators, the system and the service account.
icacls $dataDir /inheritance:r | Out-Null
icacls $dataDir /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-19:(OI)(CI)M' | Out-Null

Write-Host "Enrolling with $Server..."
$enrollArgs = @('enroll', '--server', $Server, '--token', $Token, '--data-dir', $dataDir)
if ($Name) { $enrollArgs += @('--name', $Name) }
foreach ($range in $Allow) { $enrollArgs += @('--allow', $range) }

& $exe @enrollArgs
if ($LASTEXITCODE -ne 0) { throw "Enrollment failed with exit code $LASTEXITCODE. The service was not installed." }

if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
  Write-Host 'Creating the service...'
  New-Service -Name $serviceName `
    -BinaryPathName "`"$exe`"" `
    -DisplayName 'Noema network scanning agent' `
    -Description 'Scans authorized network ranges for Noema and reports what it finds.' `
    -StartupType Automatic | Out-Null
  sc.exe config $serviceName obj= 'NT AUTHORITY\LocalService' | Out-Null
  sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
}

# Make sure the service knows where its data lives.
$environment = @("NOEMA_AGENT_DATA_DIR=$dataDir")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name Environment -Value $environment -Type MultiString

Write-Host 'Starting the service...'
Start-Service -Name $serviceName
Get-Service -Name $serviceName | Format-Table Name, Status, StartType -AutoSize

Write-Host 'Done. Logs are in Event Viewer under Windows Logs > Application, source NoemaAgent.'
