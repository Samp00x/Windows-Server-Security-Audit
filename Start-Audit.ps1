#requires -Version 5.1
<#
.SYNOPSIS
Runs discovery, dependency scanning and risk checks automatically for the computer's AD domain.
.EXAMPLE
.\Start-Audit.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = 'C:\scriptsDC',
    [string]$Server,
    [string[]]$ComputerName,
    [switch]$ScanProcesses,
    [pscredential]$Credential
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/Scripts/Audit.Common.ps1"
Import-Module ActiveDirectory -ErrorAction Stop
if (!$Server) { $Server = (Get-ADDomain -Current LocalComputer -ErrorAction Stop).DNSRoot }
New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction Stop | Out-Null
$reportNames = @('01-PrivilegedUsers.csv','04-PrivilegedGroupSummary.csv','DiscoveryStatus.csv','05-PrivilegedAccountDependencies.csv','06-ServerScanStatus.csv','DependencyInventory.csv','07-PrivilegedAccountRisks.csv','RiskQueryStatus.csv','ServerDiscovery.csv','RunStatus.csv')
$outputRoot = (Resolve-Path -LiteralPath $OutputFolder).Path
$archive = Join-Path $outputRoot ('History/' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))
foreach ($name in $reportNames) {
    $previous = Join-Path $outputRoot $name
    if (Test-Path -LiteralPath $previous -PathType Leaf) {
        New-Item -ItemType Directory -Path $archive -Force | Out-Null
        Move-Item -LiteralPath $previous -Destination (Join-Path $archive $name) -ErrorAction Stop
    }
}
$stages = [System.Collections.Generic.List[object]]::new()
Write-Host "Dominio: $Server | Resultados: $OutputFolder"
# Previous reports are archived so a failed run cannot display stale results.
Export-AuditCsv -Rows @() -Columns Stage,Status,Message -Path (Join-Path $OutputFolder 'RunStatus.csv')
foreach ($stage in @('Discovery','Dependencies','Risks')) {
    Write-Host "Executando: $stage"
    try {
        switch ($stage) {
            'Discovery' { & "$PSScriptRoot/Scripts/Get-PrivilegedUsers.ps1" -Server $Server -OutputFolder $OutputFolder }
            'Dependencies' {
                $parameters = @{ Server = $Server; OutputFolder = $OutputFolder; ScanProcesses = $ScanProcesses }
                if ($ComputerName) { $parameters.ComputerName = $ComputerName }
                if ($Credential) { $parameters.Credential = $Credential }
                & "$PSScriptRoot/Scripts/Get-PrivilegedAccountDependencies.ps1" @parameters
            }
            'Risks' { & "$PSScriptRoot/Scripts/Get-PrivilegedAccountRisks.ps1" -OutputFolder $OutputFolder }
        }
        $stages.Add([pscustomobject]@{ Stage = $stage; Status = 'Completed'; Message = 'Review detailed coverage reports; Completed does not mean every query succeeded.' })
    }
    catch {
        $stages.Add([pscustomobject]@{ Stage = $stage; Status = 'Failed'; Message = $_.Exception.Message })
        Write-Warning "$stage : $($_.Exception.Message)"
        if ($stage -eq 'Discovery') { break }
    }
    finally {
        Export-AuditCsv -Rows $stages.ToArray() -Columns Stage,Status,Message -Path (Join-Path $OutputFolder 'RunStatus.csv')
    }
}
Write-Host "Execucao encerrada. Resultados: $OutputFolder. Confira RunStatus.csv e os relatorios de cobertura."
if (@($stages | Where-Object Status -eq 'Failed').Count) { throw 'Audit has failed stages. Review RunStatus.csv.' }
