# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""WinRM-Rückbau- und Prüfplaybooks.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    base64,
    binascii,
    datetime,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    ssl,
    subprocess,
    tempfile,
    timezone,
)



def _winrm_reset_play(
    *,
    root_thumbprint: str,
    root_certificate_der_base64: str = "",
    expected_fqdn: str = "",
    bootstrap_root_certificates_der_base64: list[str] | None = None,
    disable_openssh: bool = False,
    public_key_prefix: str = "",
    key_marker: str = "",
    openssh_firewall_rule: str = "",
    openssh_config_backup: str = "",
) -> list[dict[str, Any]]:
    """Mavi-WinRM über den unabhängigen OpenSSH-Kanal auf Stand 0 setzen."""

    from .remote import (
        _bootstrap_certificate_identities,
    )

    bootstrap_identities = _bootstrap_certificate_identities(
        list(bootstrap_root_certificates_der_base64 or [])
    )
    normalized_bootstrap_certificates = [
        encoded for _thumbprint, encoded in bootstrap_identities
    ]
    powershell = r'''[CmdletBinding()]
param(
    [string]$RootThumbprint = '',
    [string]$RootCertificateDerBase64 = '',
    [string]$ExpectedFqdn = '',
    [string[]]$BootstrapRootCertificatesDerBase64 = @(),
    [int]$DisableOpenSshValue = 0,
    [string]$CurrentKeyPrefix = '',
    [string]$CurrentKeyMarker = '',
    [string]$OpenSshFirewallRuleName = '',
    [string]$OpenSshConfigBackupPath = ''
)

$ErrorActionPreference = 'Stop'
$disableOpenSsh = ($DisableOpenSshValue -eq 1)
$RootThumbprint = ($RootThumbprint -replace '\s', '').ToUpperInvariant()
$ExpectedFqdn = $ExpectedFqdn.Trim().TrimEnd('.')
if (-not [string]::IsNullOrWhiteSpace($RootThumbprint) -and $RootThumbprint -notmatch '^[A-F0-9]{40}$') {
    throw 'Mavi WinRM Reset: Der Root-CA-Fingerabdruck ist ungültig.'
}
$OpenSshConfigBackupPath = $OpenSshConfigBackupPath.Trim().Replace('/', '\')
if ($disableOpenSsh) {
    $backupPathPattern = '^MaviProvisioner\\bootstrap\\(?<InstanceId>[a-z0-9-]{1,64})\\sshd_config[.]pre-mavi[.]bak$'
    $backupPathMatch = [regex]::Match(
        $OpenSshConfigBackupPath,
        $backupPathPattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $backupPathMatch.Success) {
        throw 'Mavi Remote-Aus: Der instanzgebundene OpenSSH-Sicherungspfad ist ungültig.'
    }
    $expectedOpenSshFirewallRuleName = (
        'Mavi-OpenSSH-' + $backupPathMatch.Groups['InstanceId'].Value + '-Ansible-In-TCP'
    )
    if (-not $OpenSshFirewallRuleName.Equals(
        $expectedOpenSshFirewallRuleName,
        [System.StringComparison]::Ordinal
    )) {
        throw 'Mavi Remote-Aus: Die OpenSSH-Firewallregel gehört nicht zur angegebenen Bootstrap-Instanz.'
    }
}
$expectedBootstrapRoots = [ordered]@{}
foreach ($encodedBootstrapRoot in @($BootstrapRootCertificatesDerBase64)) {
    try {
        [byte[]]$expectedBootstrapDer = [Convert]::FromBase64String(
            ([string]$encodedBootstrapRoot).Trim()
        )
        if ($expectedBootstrapDer.Count -eq 0 -or $expectedBootstrapDer.Count -gt 1MB) {
            throw 'ungültige DER-Größe'
        }
        $expectedBootstrapCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $expectedBootstrapDer
        )
    }
    catch {
        throw 'Mavi Remote-Aus: Eine controllerseitige Bootstrap-CA ist kein gültiges DER-Zertifikat.'
    }
    $bootstrapRootThumbprint = (
        ([string]$expectedBootstrapCertificate.Thumbprint) -replace '\s', ''
    ).ToUpperInvariant()
    if ($bootstrapRootThumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'Mavi Remote-Aus: Eine controllerseitige Bootstrap-CA besitzt keinen gültigen Fingerabdruck.'
    }
    $bootstrapBasicConstraints = @(
        $expectedBootstrapCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    ) | Select-Object -First 1
    if ($null -eq $bootstrapBasicConstraints) {
        throw 'Mavi Remote-Aus: Eine erwartete Bootstrap-CA besitzt keine CA-BasicConstraints.'
    }
    $decodedBootstrapConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
    $decodedBootstrapConstraints.CopyFrom($bootstrapBasicConstraints)
    if (-not $decodedBootstrapConstraints.CertificateAuthority) {
        throw 'Mavi Remote-Aus: Ein erwartetes Bootstrap-Zertifikat ist keine CA.'
    }
    $canonicalBootstrapDerBase64 = [Convert]::ToBase64String(
        $expectedBootstrapCertificate.RawData
    )
    if ($expectedBootstrapRoots.Contains($bootstrapRootThumbprint)) {
        if ([string]$expectedBootstrapRoots[$bootstrapRootThumbprint] -cne $canonicalBootstrapDerBase64) {
            throw 'Mavi Remote-Aus: Zwei Controller-Zertifikate kollidieren unter demselben Thumbprint.'
        }
        continue
    }
    $expectedBootstrapRoots[$bootstrapRootThumbprint] = $canonicalBootstrapDerBase64
}
$BootstrapRootThumbprints = @($expectedBootstrapRoots.Keys)
if ($disableOpenSsh -and @($BootstrapRootThumbprints).Count -eq 0) {
    throw 'Mavi Remote-Aus: Die controllergebundenen Mavi-Bootstrap-CA-Zertifikate fehlen.'
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Mavi WinRM Reset benötigt einen erhöhten lokalen Administrator-Token; aktuell: $($identity.Name)"
}

$firewallNames = @(
    'Mavi-WinRM-HTTPS-Ansible-In-TCP',
    'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP',
    'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
)
$workDirectory = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
$removedListeners = 0
$removedCertificates = 0
$removedFirewallRules = 0
$removedOpenSshKeys = 0
$removedOpenSshFirewallRules = 0
$removedOpenSshConfigBackups = 0
$removedBootstrapCertificates = 0
$bootstrapScopeVerified = $false
$openSshDisableScheduled = $false
$openSshStartupDisabled = $false
$openSshStoppedVerified = $false
$openSshState = ''
$openSshStartMode = ''
$remainingMaviListeners = -1
$remainingMaviCertificates = -1
$preservedWinRmListeners = -1
$winRmListenersCleared = $false
$cleanupError = $null
$winRmMutationStarted = $false
$winRmMaintenanceAttempted = $false
$winRmListenerSnapshots = @()
$winRmFirewallSnapshots = @()
$winRmCertificateSnapshots = @()
$workDirectoryFileSnapshots = @()
$workDirectoryDirectories = @()
$workDirectorySnapshotCreated = $false
$workDirectoryRemovalAttempted = $false
$taskName = ''
$taskRegistered = $false
$openSshMutationStarted = $false
$keyRewriteAttempted = $false
$configBackupRemovalAttempted = $false
$winRmServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM'
$winRmPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
$resetHttpIsolationRuleName = 'Mavi-WinRM-Reset-HTTP-Isolation-TCP'
$resetHttpsIsolationRuleName = 'Mavi-WinRM-Reset-HTTPS-Isolation-TCP'
$originalWinRmService = Get-Service -Name WinRM -ErrorAction Stop
$originalWinRmStatus = [string]$originalWinRmService.Status
$originalWinRmStartValue = [int](Get-ItemPropertyValue `
    -LiteralPath $winRmServicePath `
    -Name Start `
    -ErrorAction Stop
)
$originalWinRmDelayedAutoStart = 0
$originalWinRmDelayedAutoStartExists = $false
try {
    $originalWinRmDelayedAutoStart = [int](Get-ItemPropertyValue `
        -LiteralPath $winRmServicePath `
        -Name DelayedAutoStart `
        -ErrorAction Stop
    )
    $originalWinRmDelayedAutoStartExists = $true
}
catch {
    $originalWinRmDelayedAutoStart = 0
    $originalWinRmDelayedAutoStartExists = $false
}

$originalAllowNegotiateExists = $false
$originalAllowNegotiate = 0
if (Test-Path -LiteralPath $winRmPolicyPath) {
    $originalWinRmPolicy = Get-ItemProperty `
        -LiteralPath $winRmPolicyPath `
        -ErrorAction Stop
    $originalAllowNegotiateProperty = $originalWinRmPolicy.PSObject.Properties[
        'AllowNegotiate'
    ]
    if ($null -ne $originalAllowNegotiateProperty) {
        $originalAllowNegotiateExists = $true
        $originalAllowNegotiate = [int]$originalAllowNegotiateProperty.Value
    }
}

function Get-MaviResetIsolationRule {
    param(
        [string]$Name,
        [int]$Port
    )

    $rules = @(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)
    if ($rules.Count -gt 1) {
        throw "Mavi WinRM Reset: Die Wartungs-Firewallregel $Name ist nicht eindeutig."
    }
    if ($rules.Count -eq 0) {
        return $null
    }

    $rule = $rules[0]
    $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $localPorts = @($portFilters[0].LocalPort | ForEach-Object { [string]$_ })
    $remoteAddresses = @($addressFilters[0].RemoteAddress | ForEach-Object { [string]$_ })
    if (
        [string]$rule.Group -cne 'Mavi Provisioner' -or
        [string]$rule.Enabled -ne 'True' -or
        [string]$rule.Direction -ne 'Inbound' -or
        [string]$rule.Action -ne 'Block' -or
        $portFilters.Count -ne 1 -or
        [string]$portFilters[0].Protocol -ne 'TCP' -or
        $localPorts.Count -ne 1 -or
        $localPorts[0] -ne [string]$Port -or
        $addressFilters.Count -ne 1 -or
        $remoteAddresses.Count -ne 1 -or
        $remoteAddresses[0] -ne 'Any'
    ) {
        throw "Mavi WinRM Reset: Die reservierte Wartungs-Firewallregel $Name kollidiert mit einer unerwarteten Regel."
    }
    return $rule
}

function Enable-MaviResetIsolationRule {
    param(
        [string]$Name,
        [int]$Port
    )

    $rule = Get-MaviResetIsolationRule -Name $Name -Port $Port
    if ($null -eq $rule) {
        New-NetFirewallRule `
            -Name $Name `
            -DisplayName $Name `
            -Group 'Mavi Provisioner' `
            -Enabled True `
            -Direction Inbound `
            -Action Block `
            -Profile Any `
            -Protocol TCP `
            -LocalPort $Port `
            -RemoteAddress Any `
            -EdgeTraversalPolicy Block `
            -ErrorAction Stop | Out-Null
    }
    [void](Get-MaviResetIsolationRule -Name $Name -Port $Port)
}

function Remove-MaviResetIsolationRules {
    foreach ($isolationRule in @(
        @{ Name = $resetHttpIsolationRuleName; Port = 5985 },
        @{ Name = $resetHttpsIsolationRuleName; Port = 5986 }
    )) {
        $rule = Get-MaviResetIsolationRule `
            -Name $isolationRule.Name `
            -Port $isolationRule.Port
        if ($null -ne $rule) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
        }
    }
}

function Restore-MaviAllowNegotiatePolicy {
    if ($originalAllowNegotiateExists) {
        New-Item -Path $winRmPolicyPath -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty `
            -LiteralPath $winRmPolicyPath `
            -Name AllowNegotiate `
            -Type DWord `
            -Value $originalAllowNegotiate `
            -Force `
            -ErrorAction Stop
    }
    elseif (Test-Path -LiteralPath $winRmPolicyPath) {
        $currentPolicy = Get-ItemProperty `
            -LiteralPath $winRmPolicyPath `
            -ErrorAction Stop
        if ($null -ne $currentPolicy.PSObject.Properties['AllowNegotiate']) {
            Remove-ItemProperty `
                -LiteralPath $winRmPolicyPath `
                -Name AllowNegotiate `
                -ErrorAction Stop
        }
    }

    $restoredAllowNegotiateProperty = $null
    if (Test-Path -LiteralPath $winRmPolicyPath) {
        $restoredPolicy = Get-ItemProperty `
            -LiteralPath $winRmPolicyPath `
            -ErrorAction Stop
        $restoredAllowNegotiateProperty = $restoredPolicy.PSObject.Properties[
            'AllowNegotiate'
        ]
    }
    if (
        ($originalAllowNegotiateExists -and (
            $null -eq $restoredAllowNegotiateProperty -or
            [int]$restoredAllowNegotiateProperty.Value -ne $originalAllowNegotiate
        )) -or
        (-not $originalAllowNegotiateExists -and $null -ne $restoredAllowNegotiateProperty)
    ) {
        throw 'Mavi WinRM Reset: Die ursprüngliche AllowNegotiate-Richtlinie wurde nicht exakt wiederhergestellt.'
    }
}

function Enable-MaviWinRmProviderMaintenance {
    # Block-Regeln haben Vorrang vor allen Allow-Regeln. Erst wenn sowohl HTTP
    # als auch HTTPS von außen isoliert sind, darf Negotiate kurzzeitig für den
    # ausschließlich lokalen WSMan:-Provider wieder aktiviert werden.
    Enable-MaviResetIsolationRule -Name $resetHttpIsolationRuleName -Port 5985
    Enable-MaviResetIsolationRule -Name $resetHttpsIsolationRuleName -Port 5986
    New-Item -Path $winRmPolicyPath -Force -ErrorAction Stop | Out-Null
    Set-ItemProperty `
        -LiteralPath $winRmPolicyPath `
        -Name AllowNegotiate `
        -Type DWord `
        -Value 1 `
        -Force `
        -ErrorAction Stop
    Set-Service -Name WinRM -StartupType Manual -ErrorAction Stop
    Restart-Service -Name WinRM -Force -ErrorAction Stop

    $providerDeadline = (Get-Date).AddSeconds(20)
    do {
        try {
            [void]@(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop)
            return
        }
        catch {
            $providerError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $providerDeadline)
    throw "Mavi WinRM Reset: Der lokal isolierte WSMan-Provider wurde nicht bereit: $providerError"
}

function Restore-MaviWinRmServiceState {
    param(
        [string]$OriginalStatus,
        [int]$OriginalStartValue,
        [int]$OriginalDelayedAutoStart,
        [bool]$OriginalDelayedAutoStartExists
    )

    $startupType = switch ($OriginalStartValue) {
        2 { 'Automatic' }
        3 { 'Manual' }
        4 { 'Disabled' }
        default { throw "Mavi WinRM Reset: Unbekannter ursprünglicher WinRM-Startwert: $OriginalStartValue" }
    }

    # Ein deaktivierter Dienst kann nicht direkt gestartet werden. Deshalb
    # zunächst Manual, den Laufzustand wiederherstellen und erst dann den
    # ursprünglichen Starttyp setzen.
    Set-Service -Name WinRM -StartupType Manual -ErrorAction Stop
    if ($OriginalStatus -eq 'Running') {
        Start-Service -Name WinRM -ErrorAction Stop
        (Get-Service -Name WinRM -ErrorAction Stop).WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(20)
        )
    }
    else {
        Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
        (Get-Service -Name WinRM -ErrorAction Stop).WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(20)
        )
    }
    Set-Service -Name WinRM -StartupType $startupType -ErrorAction Stop
    if ($OriginalStartValue -eq 2) {
        if ($OriginalDelayedAutoStartExists) {
            Set-ItemProperty `
                -LiteralPath $winRmServicePath `
                -Name DelayedAutoStart `
                -Value $OriginalDelayedAutoStart `
                -ErrorAction Stop
        }
        else {
            Remove-ItemProperty `
                -LiteralPath $winRmServicePath `
                -Name DelayedAutoStart `
                -ErrorAction SilentlyContinue
        }
    }

    $restoredService = Get-Service -Name WinRM -ErrorAction Stop
    $restoredStartValue = [int](Get-ItemPropertyValue `
        -LiteralPath $winRmServicePath `
        -Name Start `
        -ErrorAction Stop
    )
    if (
        [string]$restoredService.Status -ne $OriginalStatus -or
        $restoredStartValue -ne $OriginalStartValue
    ) {
        throw 'Mavi WinRM Reset: Der ursprüngliche WinRM-Dienstzustand konnte nicht vollständig wiederhergestellt werden.'
    }
}

$RootCertificateDerBase64 = $RootCertificateDerBase64.Trim()
$effectiveRootThumbprint = $RootThumbprint
$expectedRootCertificate = $null
$controllerRootDerBase64 = ''
if (
    -not [string]::IsNullOrWhiteSpace($effectiveRootThumbprint) -and
    [string]::IsNullOrWhiteSpace($RootCertificateDerBase64)
) {
    throw 'Mavi WinRM Reset: Ein Inventory-Thumbprint ohne controllerseitiges Root-DER ist keine Löschberechtigung.'
}

function New-MaviCertificateRollbackSnapshot {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $providerPath = [string]$Certificate.PSPath
    if ($providerPath -notmatch 'Certificate::LocalMachine\\(?<StoreName>[^\\]+)\\[A-Fa-f0-9]{40}$') {
        throw "Mavi WinRM Reset: Zertifikatspfad kann nicht rollback-sicher abgebildet werden: $providerPath"
    }
    return [PSCustomObject]@{
        Certificate = $Certificate
        ProviderPath = $providerPath
        StoreName = [string]$Matches['StoreName']
        Thumbprint = (([string]$Certificate.Thumbprint) -replace '\s', '').ToUpperInvariant()
        HadPrivateKey = [bool]$Certificate.HasPrivateKey
        MutationAttempted = $false
    }
}

function Restore-MaviWinRmArtifacts {
    # Der Provider benoetigt einen laufenden Dienst, bevor Zertifikate und
    # Listener wieder an ihren exakten urspruenglichen Platz gesetzt werden.
    Set-Service -Name WinRM -StartupType Manual -ErrorAction Stop
    Start-Service -Name WinRM -ErrorAction Stop

    foreach ($snapshot in @($winRmCertificateSnapshots | Where-Object MutationAttempted)) {
        $certificatePath = "Cert:\LocalMachine\$($snapshot.StoreName)\$($snapshot.Thumbprint)"
        $currentCertificate = Get-Item -LiteralPath $certificatePath -ErrorAction SilentlyContinue
        if ($null -eq $currentCertificate) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [string]$snapshot.StoreName,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
            )
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                # Das Zertifikat wurde in der Mutationsphase bewusst ohne
                # -DeleteKey entfernt. Das gehaltene X509Certificate2-Objekt
                # traegt dadurch weiterhin die Bindung zum nicht exportierbaren
                # Mavi-Schluessel und kann sie im Rollback exakt restaurieren.
                $store.Add($snapshot.Certificate)
            }
            finally {
                $store.Close()
            }
            $currentCertificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
        }
        if (
            $snapshot.HadPrivateKey -and
            -not [bool]$currentCertificate.HasPrivateKey
        ) {
            throw "Mavi WinRM Reset: Der private Schluessel von $($snapshot.Thumbprint) wurde beim Rollback nicht wieder angebunden."
        }
    }

    foreach ($snapshot in @($winRmFirewallSnapshots | Where-Object MutationAttempted)) {
        $currentRules = @(
            Get-NetFirewallRule -Name $snapshot.Name -ErrorAction SilentlyContinue
        )
        if ($currentRules.Count -gt 1) {
            throw "Mavi WinRM Reset: Firewallregel $($snapshot.Name) ist beim Rollback nicht eindeutig."
        }
        if ($currentRules.Count -eq 1) {
            Remove-NetFirewallRule -InputObject $currentRules[0] -ErrorAction Stop
        }
        New-NetFirewallRule `
            -Name $snapshot.Name `
            -DisplayName $snapshot.DisplayName `
            -Group $snapshot.Group `
            -Enabled $snapshot.Enabled `
            -Direction $snapshot.Direction `
            -Action $snapshot.Action `
            -Profile $snapshot.Profile `
            -Protocol $snapshot.Protocol `
            -LocalPort $snapshot.LocalPort `
            -RemotePort $snapshot.RemotePort `
            -LocalAddress $snapshot.LocalAddress `
            -RemoteAddress $snapshot.RemoteAddress `
            -EdgeTraversalPolicy $snapshot.EdgeTraversalPolicy `
            -ErrorAction Stop | Out-Null
    }

    foreach ($snapshot in @($winRmListenerSnapshots | Where-Object MutationAttempted)) {
        $matchingListeners = @(
            Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
            Where-Object {
                $_.Keys -contains "Transport=$($snapshot.Transport)" -and
                $_.Keys -contains "Address=$($snapshot.Address)"
            }
        )
        if ($matchingListeners.Count -eq 0) {
            New-WSManInstance `
                -ResourceURI 'winrm/config/Listener' `
                -SelectorSet @{
                    Transport = $snapshot.Transport
                    Address = $snapshot.Address
                } `
                -ValueSet @{
                    Hostname = $snapshot.Hostname
                    CertificateThumbprint = $snapshot.CertificateThumbprint
                } `
                -ErrorAction Stop | Out-Null
        }
        elseif ($matchingListeners.Count -ne 1) {
            throw 'Mavi WinRM Reset: Ein Listener ist beim Rollback nicht eindeutig.'
        }
        else {
            $restoredListenerValues = @{}
            foreach ($listenerValue in @(
                Get-ChildItem -LiteralPath $matchingListeners[0].PSPath -ErrorAction Stop
            )) {
                $restoredListenerValues[[string]$listenerValue.Name] = [string]$listenerValue.Value
            }
            $restoredThumbprint = (
                ([string]$restoredListenerValues['CertificateThumbprint']) -replace '\s', ''
            ).ToUpperInvariant()
            if (
                [string]$restoredListenerValues['Hostname'] -cne $snapshot.Hostname -or
                $restoredThumbprint -cne $snapshot.CertificateThumbprint
            ) {
                throw 'Mavi WinRM Reset: Der Listener weicht nach dem Rollback vom Snapshot ab.'
            }
        }
    }

    if ($workDirectorySnapshotCreated -and $workDirectoryRemovalAttempted) {
        if (Test-Path -LiteralPath $workDirectory) {
            Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction Stop
        }
        New-Item -ItemType Directory -Path $workDirectory -Force -ErrorAction Stop | Out-Null
        foreach ($relativeDirectory in @($workDirectoryDirectories | Sort-Object Length)) {
            New-Item `
                -ItemType Directory `
                -Path (Join-Path $workDirectory $relativeDirectory) `
                -Force `
                -ErrorAction Stop | Out-Null
        }
        foreach ($fileSnapshot in $workDirectoryFileSnapshots) {
            $restoredFile = Join-Path $workDirectory $fileSnapshot.RelativePath
            $restoredParent = Split-Path -Parent $restoredFile
            New-Item -ItemType Directory -Path $restoredParent -Force -ErrorAction Stop | Out-Null
            [System.IO.File]::WriteAllBytes($restoredFile, $fileSnapshot.Bytes)
        }
    }
}
if (-not [string]::IsNullOrWhiteSpace($RootCertificateDerBase64)) {
    try {
        $controllerRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [Convert]::FromBase64String($RootCertificateDerBase64)
        )
    }
    catch {
        throw 'Mavi WinRM Reset: Das erwartete Mavi-Root-Zertifikat ist ungültig.'
    }
    $controllerRootThumbprint = ([string]$controllerRoot.Thumbprint).ToUpperInvariant()
    if (
        -not [string]::IsNullOrWhiteSpace($RootThumbprint) -and
        -not $controllerRootThumbprint.Equals(
            $RootThumbprint,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw 'Mavi WinRM Reset: Root-Zertifikat und Root-CA-Fingerabdruck stimmen nicht überein.'
    }
    $effectiveRootThumbprint = $controllerRootThumbprint
    $expectedRootCertificate = $controllerRoot
    $controllerRootDerBase64 = [Convert]::ToBase64String($controllerRoot.RawData)
}

if ($effectiveRootThumbprint -match '^[A-F0-9]{40}$' -and $null -eq $expectedRootCertificate) {
    throw 'Mavi WinRM Reset: Die exakt erwartete Mavi-Root-CA ist controllerseitig nicht als DER verfügbar; Mavi löscht keine Zertifikate per Inventory-Thumbprint, Namen oder Subject.'
}
$winRmScopeVerified = $false
if ($null -ne $expectedRootCertificate) {
    $expectedRootThumbprint = ([string]$expectedRootCertificate.Thumbprint).ToUpperInvariant()
    if ($expectedRootThumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'Mavi WinRM Reset: Die erwartete Mavi-Root-CA besitzt keinen gültigen Fingerabdruck.'
    }
    if (
        -not [string]::IsNullOrWhiteSpace($effectiveRootThumbprint) -and
        -not $expectedRootThumbprint.Equals($effectiveRootThumbprint, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw 'Mavi WinRM Reset: Die erwartete Mavi-Root-CA stimmt nicht mit ihrem Fingerabdruck überein.'
    }
    $effectiveRootThumbprint = $expectedRootThumbprint
    $winRmScopeVerified = $true
}
if ($winRmScopeVerified -and [string]::IsNullOrWhiteSpace($ExpectedFqdn)) {
    throw 'Mavi WinRM Reset: Der erwartete Ziel-FQDN fehlt; Mavi löscht keine Zertifikate über eine hostübergreifende Namenssuche.'
}

function Test-MaviLeafForRoot {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot
    )
    if (
        $null -eq $Certificate -or
        $null -eq $ExpectedRoot
    ) {
        return $false
    }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = (
            [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority -bor
            [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        )
        [void]$chain.ChainPolicy.ExtraStore.Add($ExpectedRoot)
        if (-not $chain.Build($Certificate) -or $chain.ChainElements.Count -lt 2) {
            return $false
        }
        $chainRoot = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        return (
            ([string]$chainRoot.Thumbprint).Equals(
                [string]$ExpectedRoot.Thumbprint,
                [System.StringComparison]::OrdinalIgnoreCase
            ) -and
            [Convert]::ToBase64String($chainRoot.RawData) -ceq
                [Convert]::ToBase64String($ExpectedRoot.RawData)
        )
    }
    catch {
        return $false
    }
    finally {
        $chain.Dispose()
    }
}

function Test-MaviLeafCertificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot,
        [string]$ExpectedFqdn
    )
    if (
        [string]::IsNullOrWhiteSpace($ExpectedFqdn) -or
        -not (Test-MaviLeafForRoot -Certificate $Certificate -ExpectedRoot $ExpectedRoot)
    ) {
        return $false
    }
    $expectedFriendlyName = "Mavi WinRM HTTPS $ExpectedFqdn"
    if (-not ([string]$Certificate.FriendlyName).Equals($expectedFriendlyName, [System.StringComparison]::Ordinal)) {
        return $false
    }
    $subjectName = [string]$Certificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    return $subjectName.Equals($ExpectedFqdn, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-MaviLeafCertificates {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot,
        [string]$ExpectedFqdn
    )
    if ($null -eq $ExpectedRoot -or [string]::IsNullOrWhiteSpace($ExpectedFqdn)) {
        return @()
    }
    $matchedCertificates = @()
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
        if (-not (Test-Path -LiteralPath $storePath)) { continue }
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            if (Test-MaviLeafCertificate -Certificate $certificate -ExpectedRoot $ExpectedRoot -ExpectedFqdn $ExpectedFqdn) {
                $matchedCertificates += $certificate
            }
        }
    }
    return @($matchedCertificates)
}

function Get-MaviLeavesForRoot {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot)
    if ($null -eq $ExpectedRoot) {
        return @()
    }
    $matchedLeaves = @()
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
        if (-not (Test-Path -LiteralPath $storePath)) { continue }
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            if (Test-MaviLeafForRoot -Certificate $certificate -ExpectedRoot $ExpectedRoot) {
                $matchedLeaves += $certificate
            }
        }
    }
    return @($matchedLeaves)
}

function Get-MaviWinRmListeners {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot,
        [string]$ExpectedFqdn,
        [bool]$AnyMaviLeafForRoot = $false
    )
    # Nicht $matches verwenden: PowerShell reserviert $Matches (ohne
    # Beachtung der Gross-/Kleinschreibung) fuer das Ergebnis von -match.
    $matchedListeners = @()
    if (
        $null -eq $ExpectedRoot -or
        (-not $AnyMaviLeafForRoot -and [string]::IsNullOrWhiteSpace($ExpectedFqdn))
    ) {
        return @()
    }
    foreach ($listener in @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop)) {
        if ($listener.Keys -notcontains 'Transport=HTTPS') {
            continue
        }
        $listenerValues = @{}
        foreach ($listenerValue in @(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop)) {
            $listenerValueName = [string]$listenerValue.Name
            if (-not [string]::IsNullOrWhiteSpace($listenerValueName)) {
                $listenerValues[$listenerValueName] = [string]$listenerValue.Value
            }
        }
        $listenerThumbprint = (([string]$listenerValues['CertificateThumbprint']).Trim() -replace '\s', '').ToUpperInvariant()
        if ($listenerThumbprint -notmatch '^[A-F0-9]{40}$') {
            continue
        }
        $listenerCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\My\$listenerThumbprint") -ErrorAction SilentlyContinue
        $matchesExpectedScope = if ($AnyMaviLeafForRoot) {
            Test-MaviLeafForRoot -Certificate $listenerCertificate -ExpectedRoot $ExpectedRoot
        }
        else {
            Test-MaviLeafCertificate -Certificate $listenerCertificate -ExpectedRoot $ExpectedRoot -ExpectedFqdn $ExpectedFqdn
        }
        if ($matchesExpectedScope) {
            $matchedListeners += $listener
        }
    }
    return @($matchedListeners)
}

try {
if ($disableOpenSsh) {
    # Vollstaendig falliblen OpenSSH-Preflight und die Task-Registrierung vor
    # der ersten destruktiven WinRM-Aenderung abschliessen. Der Task wird erst
    # nach erfolgreichem WinRM-Cleanup gestartet; bis dahin ist er inert und
    # wird vom aeusseren Rollback wieder entfernt.
    $sshdServicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $sshdService) {
        throw 'Mavi Remote-Aus: Der OpenSSH-Serverdienst sshd wurde nicht gefunden.'
    }
    $originalSshdStatus = [string]$sshdService.Status
    if ($originalSshdStatus -notin @('Running', 'Stopped')) {
        throw "Mavi Remote-Aus: Der urspruengliche sshd-Zustand ist nicht stabil: $originalSshdStatus"
    }
    $originalSshdStartValue = [int](Get-ItemPropertyValue `
        -LiteralPath $sshdServicePath `
        -Name Start `
        -ErrorAction Stop
    )
    if ($originalSshdStartValue -notin @(2, 3, 4)) {
        throw "Mavi Remote-Aus: Der urspruengliche sshd-Startwert ist unbekannt: $originalSshdStartValue"
    }
    $originalSshdDelayedAutoStart = 0
    $originalSshdDelayedAutoStartExists = $false
    try {
        $originalSshdDelayedAutoStart = [int](Get-ItemPropertyValue `
            -LiteralPath $sshdServicePath `
            -Name DelayedAutoStart `
            -ErrorAction Stop
        )
        $originalSshdDelayedAutoStartExists = $true
    }
    catch {
        $originalSshdDelayedAutoStart = 0
        $originalSshdDelayedAutoStartExists = $false
    }

    function Restore-MaviSshdServiceState {
        param(
            [string]$OriginalStatus,
            [int]$OriginalStartValue,
            [int]$OriginalDelayedAutoStart,
            [bool]$OriginalDelayedAutoStartExists,
            [string]$ServicePath
        )

        $startupType = switch ($OriginalStartValue) {
            2 { 'Automatic' }
            3 { 'Manual' }
            4 { 'Disabled' }
            default { throw "Mavi Remote-Aus: Unbekannter urspruenglicher sshd-Startwert: $OriginalStartValue" }
        }
        Set-Service -Name sshd -StartupType Manual -ErrorAction Stop
        if ($OriginalStatus -eq 'Running') {
            Start-Service -Name sshd -ErrorAction Stop
            (Get-Service -Name sshd -ErrorAction Stop).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(20)
            )
        }
        else {
            Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
            (Get-Service -Name sshd -ErrorAction Stop).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(20)
            )
        }
        Set-Service -Name sshd -StartupType $startupType -ErrorAction Stop
        if ($OriginalDelayedAutoStartExists) {
            Set-ItemProperty `
                -LiteralPath $ServicePath `
                -Name DelayedAutoStart `
                -Value $OriginalDelayedAutoStart `
                -ErrorAction Stop
        }
        else {
            Remove-ItemProperty `
                -LiteralPath $ServicePath `
                -Name DelayedAutoStart `
                -ErrorAction SilentlyContinue
        }

        $restoredService = Get-Service -Name sshd -ErrorAction Stop
        $restoredStartValue = [int](Get-ItemPropertyValue `
            -LiteralPath $ServicePath `
            -Name Start `
            -ErrorAction Stop
        )
        if (
            [string]$restoredService.Status -ne $OriginalStatus -or
            $restoredStartValue -ne $OriginalStartValue
        ) {
            throw 'Mavi Remote-Aus: Der urspruengliche sshd-Dienstzustand wurde nicht vollstaendig wiederhergestellt.'
        }
    }

    $keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $originalKeyFileExists = Test-Path -LiteralPath $keyFile -PathType Leaf
    [byte[]]$originalKeyFileBytes = @()
    if ($originalKeyFileExists) {
        $originalKeyFileBytes = [System.IO.File]::ReadAllBytes($keyFile)
    }

    $openSshConfigBackup = Join-Path $env:ProgramData $OpenSshConfigBackupPath
    $originalOpenSshConfigBackupExists = Test-Path -LiteralPath $openSshConfigBackup -PathType Leaf
    [byte[]]$originalOpenSshConfigBackupBytes = @()
    if ($originalOpenSshConfigBackupExists) {
        $originalOpenSshConfigBackupBytes = [System.IO.File]::ReadAllBytes($openSshConfigBackup)
    }

    $openSshRules = @(Get-NetFirewallRule -Name $OpenSshFirewallRuleName -ErrorAction SilentlyContinue)
    if ($openSshRules.Count -gt 1) {
        throw 'Mavi Remote-Aus: Die Mavi-OpenSSH-Firewallregel ist nicht eindeutig.'
    }
    $originalOpenSshFirewallRuleExists = ($openSshRules.Count -eq 1)
    $originalOpenSshFirewallRuleEnabledValue = 'False'
    $originalOpenSshFirewallDisplayName = ''
    $originalOpenSshFirewallRemoteAddresses = @()
    if ($originalOpenSshFirewallRuleExists) {
        $originalOpenSshFirewallDisplayName = [string]$openSshRules[0].DisplayName
        $originalOpenSshFirewallRuleEnabledValue = if ([string]$openSshRules[0].Enabled -eq 'True') {
            'True'
        }
        else {
            'False'
        }
        $addressFilters = @($openSshRules[0] | Get-NetFirewallAddressFilter -ErrorAction Stop)
        if ($addressFilters.Count -ne 1) {
            throw 'Mavi Remote-Aus: Die Mavi-OpenSSH-Firewallregel besitzt keinen eindeutigen Adressfilter.'
        }
        $originalOpenSshFirewallRemoteAddresses = @(
            $addressFilters[0].RemoteAddress |
            ForEach-Object { [string]$_ }
        )
        if ($originalOpenSshFirewallRemoteAddresses.Count -eq 0) {
            throw 'Mavi Remote-Aus: Die Mavi-OpenSSH-Firewallregel besitzt keinen wiederherstellbaren Remote-Scope.'
        }
    }

    $taskName = 'Mavi-Disable-RemoteAccess-' + [Guid]::NewGuid().ToString('N')
    $childScript = @'
$ErrorActionPreference = 'Stop'
Start-Sleep -Seconds 2
Set-Service -Name sshd -StartupType Disabled -ErrorAction Stop
Stop-Service -Name sshd -Force -ErrorAction Stop
(Get-Service -Name sshd -ErrorAction Stop).WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(20)
)
$finalStartValue = [int](Get-ItemPropertyValue `
    -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd' `
    -Name Start `
    -ErrorAction Stop
)
if ([string](Get-Service -Name sshd -ErrorAction Stop).Status -ne 'Stopped' -or $finalStartValue -ne 4) {
    throw 'Mavi Remote-Aus: Der SYSTEM-Task konnte sshd nicht gestoppt und deaktiviert bestaetigen.'
}
'@
    $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $taskAction = New-ScheduledTaskAction `
        -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedScript"
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $taskAction `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Force `
        -ErrorAction Stop | Out-Null
    $taskRegistered = $true
    $beforeTaskRun = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop).LastRunTime
}

try {
    # Der gehärtete Endzustand AllowNegotiate=0 sperrt auch den lokalen
    # WSMan:-Provider aus. Der Wartungsmodus öffnet ihn erst, nachdem beide
    # WinRM-Netzwerkports durch höher priorisierte Block-Regeln isoliert sind.
    $winRmMaintenanceAttempted = $true
    Enable-MaviWinRmProviderMaintenance

    if ($disableOpenSsh) {
        # Den vollständigen Rückbau vor der ersten Löschung freigeben. Wenn
        # fremde Listener vorhanden sind, bleibt auch der Mavi-Listener stehen.
        $preflightWinRmListeners = @(
            Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop
        )
        $preflightMaviWinRmListeners = @()
        if ($winRmScopeVerified) {
            $preflightMaviWinRmListeners = @(
                Get-MaviWinRmListeners `
                    -ExpectedRoot $expectedRootCertificate `
                    -ExpectedFqdn $ExpectedFqdn `
                    -AnyMaviLeafForRoot $disableOpenSsh
            )
        }
        if (-not $winRmScopeVerified) {
            throw 'Mavi Remote-Aus: Der WinRM-Zertifikats-Scope konnte ohne exakte Root-Identität nicht verifiziert werden; ein leerer Listener-Bestand reicht nicht aus.'
        }
        if ($preflightWinRmListeners.Count -ne $preflightMaviWinRmListeners.Count) {
            throw 'Mavi Remote-Aus: Fremde WinRM-Listener verhindern den vollständigen Rückbau; es wurde noch kein Listener entfernt.'
        }
    }

    # Alle Zielobjekte und ihre rollback-relevanten Eigenschaften werden vor
    # der ersten Loeschung vollstaendig gelesen. Damit kann weder ein spaeter
    # fehlschlagender Firewall-/Store-Zugriff noch die OpenSSH-Finalisierung
    # einen bereits funktionierenden HTTPS-Endpunkt dauerhaft halb entfernen.
    $listenersToRemove = @()
    if ($winRmScopeVerified) {
        $listenersToRemove = @(
            Get-MaviWinRmListeners `
                -ExpectedRoot $expectedRootCertificate `
                -ExpectedFqdn $ExpectedFqdn `
                -AnyMaviLeafForRoot $disableOpenSsh
        )
    }
    foreach ($listener in $listenersToRemove) {
        $listenerValues = @{}
        foreach ($listenerValue in @(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop)) {
            $listenerValues[[string]$listenerValue.Name] = [string]$listenerValue.Value
        }
        $addressKeys = @($listener.Keys | Where-Object { $_ -like 'Address=*' })
        if ($addressKeys.Count -ne 1) {
            throw 'Mavi WinRM Reset: Die Listener-Adresse kann nicht eindeutig gesichert werden.'
        }
        $listenerThumbprint = (([string]$listenerValues['CertificateThumbprint']) -replace '\s', '').ToUpperInvariant()
        if ($listenerThumbprint -notmatch '^[A-F0-9]{40}$') {
            throw 'Mavi WinRM Reset: Der Listener-Fingerabdruck kann nicht rollback-sicher gesichert werden.'
        }
        $winRmListenerSnapshots += [PSCustomObject]@{
            ProviderPath = [string]$listener.PSPath
            Transport = 'HTTPS'
            Address = ([string]$addressKeys[0]).Substring('Address='.Length)
            Hostname = [string]$listenerValues['Hostname']
            CertificateThumbprint = $listenerThumbprint
            MutationAttempted = $false
        }
    }

    $firewallRulesToRemove = @()
    foreach ($name in $firewallNames) {
        $firewallRulesToRemove += @(
            Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.Group -eq 'Mavi Provisioner' }
        )
    }
    foreach ($rule in $firewallRulesToRemove) {
        $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
        $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
        if ($portFilters.Count -ne 1 -or $addressFilters.Count -ne 1) {
            throw "Mavi WinRM Reset: Firewallregel $($rule.DisplayName) besitzt keinen eindeutigen rollback-faehigen Filter."
        }
        $winRmFirewallSnapshots += [PSCustomObject]@{
            Name = [string]$rule.Name
            DisplayName = [string]$rule.DisplayName
            Group = [string]$rule.Group
            Enabled = [string]$rule.Enabled
            Direction = [string]$rule.Direction
            Action = [string]$rule.Action
            Profile = [string]$rule.Profile
            EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
            Protocol = [string]$portFilters[0].Protocol
            LocalPort = @($portFilters[0].LocalPort | ForEach-Object { [string]$_ })
            RemotePort = @($portFilters[0].RemotePort | ForEach-Object { [string]$_ })
            LocalAddress = @($addressFilters[0].LocalAddress | ForEach-Object { [string]$_ })
            RemoteAddress = @($addressFilters[0].RemoteAddress | ForEach-Object { [string]$_ })
            MutationAttempted = $false
        }
    }

    $certificatesToRemove = @()
    if ($winRmScopeVerified) {
        $certificatesToRemove = if ($disableOpenSsh) {
            @(Get-MaviLeavesForRoot -ExpectedRoot $expectedRootCertificate)
        }
        else {
            @(
                Get-MaviLeafCertificates `
                    -ExpectedRoot $expectedRootCertificate `
                    -ExpectedFqdn $ExpectedFqdn
            )
        }
        foreach ($certificate in $certificatesToRemove) {
            $winRmCertificateSnapshots += New-MaviCertificateRollbackSnapshot `
                -Certificate $certificate
        }
    }

    $installedRootCertificate = $null
    $rootPath = ''
    if ($winRmScopeVerified -and $effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $rootPath = "Cert:\LocalMachine\Root\$effectiveRootThumbprint"
        $installedRootCertificate = Get-Item -LiteralPath $rootPath -ErrorAction SilentlyContinue
        if ($null -ne $installedRootCertificate) {
            $installedRootThumbprint = (
                ([string]$installedRootCertificate.Thumbprint) -replace '\s', ''
            ).ToUpperInvariant()
            $installedRootDerBase64 = [Convert]::ToBase64String(
                $installedRootCertificate.RawData
            )
            if (
                -not $installedRootThumbprint.Equals(
                    $effectiveRootThumbprint,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                $installedRootDerBase64 -cne $controllerRootDerBase64
            ) {
                throw 'Mavi WinRM Reset: Die WinRM-Root im Root Store stimmt nicht bytegenau mit dem Controller-DER überein.'
            }
            $winRmCertificateSnapshots += New-MaviCertificateRollbackSnapshot `
                -Certificate $installedRootCertificate
        }
    }

    $bootstrapCertificatesToRemove = @()
    if ($disableOpenSsh) {
        foreach ($bootstrapRootThumbprint in $BootstrapRootThumbprints) {
            $bootstrapRootPath = "Cert:\LocalMachine\Root\$bootstrapRootThumbprint"
            $bootstrapRootCertificate = Get-Item -LiteralPath $bootstrapRootPath -ErrorAction SilentlyContinue
            if ($null -eq $bootstrapRootCertificate) {
                continue
            }
            $actualBootstrapThumbprint = (
                ([string]$bootstrapRootCertificate.Thumbprint) -replace '\s', ''
            ).ToUpperInvariant()
            $actualBootstrapDerBase64 = [Convert]::ToBase64String(
                $bootstrapRootCertificate.RawData
            )
            if (
                -not $actualBootstrapThumbprint.Equals(
                    $bootstrapRootThumbprint,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -or
                $actualBootstrapDerBase64 -cne [string]$expectedBootstrapRoots[$bootstrapRootThumbprint]
            ) {
                throw 'Mavi Remote-Aus: Die Bootstrap-CA im Root Store stimmt nicht bytegenau mit dem Controller-Archiv überein.'
            }
            $bootstrapCertificatesToRemove += [PSCustomObject]@{
                Path = $bootstrapRootPath
                Thumbprint = $bootstrapRootThumbprint
                Certificate = $bootstrapRootCertificate
            }
            $winRmCertificateSnapshots += New-MaviCertificateRollbackSnapshot `
                -Certificate $bootstrapRootCertificate
        }
    }

    if (Test-Path -LiteralPath $workDirectory) {
        $workDirectoryItem = Get-Item -LiteralPath $workDirectory -Force -ErrorAction Stop
        if (-not $workDirectoryItem.PSIsContainer) {
            throw 'Mavi WinRM Reset: Der erwartete Arbeitsordner ist kein Verzeichnis.'
        }
        if (($workDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Mavi WinRM Reset: Der Arbeitsordner selbst ist ein nicht rollback-fähiger Reparse Point.'
        }
        $resolvedWorkDirectory = [System.IO.Path]::GetFullPath($workDirectory).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar
        )
        $resolvedWorkDirectoryPrefix = $resolvedWorkDirectory + [System.IO.Path]::DirectorySeparatorChar
        foreach ($workItem in @(Get-ChildItem -LiteralPath $workDirectory -Recurse -Force -ErrorAction Stop)) {
            if (($workItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Mavi WinRM Reset: Der Arbeitsordner enthaelt einen nicht rollback-faehigen Reparse Point.'
            }
            $resolvedWorkItem = [System.IO.Path]::GetFullPath($workItem.FullName)
            if (-not $resolvedWorkItem.StartsWith($resolvedWorkDirectoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'Mavi WinRM Reset: Ein Arbeitsordner-Artefakt liegt ausserhalb des erwarteten Pfads.'
            }
            $relativeWorkItem = $resolvedWorkItem.Substring($resolvedWorkDirectory.Length + 1)
            if ($workItem.PSIsContainer) {
                $workDirectoryDirectories += $relativeWorkItem
            }
            else {
                $workDirectoryFileSnapshots += [PSCustomObject]@{
                    RelativePath = $relativeWorkItem
                    Bytes = [System.IO.File]::ReadAllBytes($resolvedWorkItem)
                }
            }
        }
        $workDirectorySnapshotCreated = $true
    }

    $winRmMutationStarted = $true

    # Beim Teilrückbau muss das HTTPS-Leaf zusätzlich den erwarteten Mavi-Namen
    # tragen. Beim Vollrückbau reicht die bytegenaue Kette zur dedizierten
    # Controller-Root, damit auch historische Mavi-FQDNs vollständig erfasst
    # werden. HTTP- sowie fremde HTTPS-Listener bleiben unangetastet.
    if ($winRmScopeVerified) {
        foreach ($listener in $listenersToRemove) {
            $listenerSnapshots = @(
                $winRmListenerSnapshots |
                Where-Object { $_.ProviderPath -ceq [string]$listener.PSPath }
            )
            if ($listenerSnapshots.Count -ne 1) {
                throw 'Mavi WinRM Reset: Der Listener-Snapshot ist vor der Löschung nicht eindeutig.'
            }
            $listenerSnapshots[0].MutationAttempted = $true
            Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
            $removedListeners++
        }
        # Den WSMan-Provider nur abfragen, solange WinRM noch laeuft. Ein Zugriff
        # nach Stop/Disable kann lokal bis zum Ansible-Timeout blockieren.
        $remainingMaviListeners = @(
            Get-MaviWinRmListeners `
                -ExpectedRoot $expectedRootCertificate `
                -ExpectedFqdn $ExpectedFqdn `
                -AnyMaviLeafForRoot $disableOpenSsh
        ).Count
        if ($remainingMaviListeners -ne 0) {
            throw 'Mavi WinRM Reset: Ein eindeutig Mavi-verwalteter WinRM-Listener konnte nicht entfernt werden.'
        }
    }
    $preservedWinRmListeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop).Count
    $winRmListenersCleared = ($preservedWinRmListeners -eq 0)
    if ($disableOpenSsh -and (-not $winRmScopeVerified -or -not $winRmListenersCleared)) {
        throw 'Mavi Remote-Aus: Ohne exakt verifizierten WinRM-Scope und vollständig leeren Listener-Bestand wird OpenSSH nicht deaktiviert.'
    }

    foreach ($rule in $firewallRulesToRemove) {
        $firewallSnapshots = @(
            $winRmFirewallSnapshots |
            Where-Object { $_.Name -ceq [string]$rule.Name }
        )
        if ($firewallSnapshots.Count -ne 1) {
            throw "Mavi WinRM Reset: Der Firewall-Snapshot für $($rule.Name) ist nicht eindeutig."
        }
        $firewallSnapshots[0].MutationAttempted = $true
        Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
        $removedFirewallRules++
    }

    if ($winRmScopeVerified) {
        foreach ($certificate in @($certificatesToRemove)) {
            # Beim Teilrückbau müssen FriendlyName und Subject den Ziel-FQDN
            # bezeichnen. Beim Vollrückbau umfasst der Scope alle vom dedizierten
            # Mavi-WinRM-Root signierten Leaves, damit alte FQDNs oder beschädigte
            # FriendlyNames nicht als verwaiste Zertifikate zurückbleiben.
            # Der nicht exportierbare private Schluessel bleibt bis zum
            # erfolgreichen Commit bestehen, damit der Catch das Leaf samt
            # funktionierender Listener-Bindung restaurieren kann.
            $certificateSnapshots = @(
                $winRmCertificateSnapshots |
                Where-Object { $_.ProviderPath -ceq [string]$certificate.PSPath }
            )
            if ($certificateSnapshots.Count -ne 1) {
                throw 'Mavi WinRM Reset: Der Leaf-Zertifikatssnapshot ist vor der Löschung nicht eindeutig.'
            }
            $certificateSnapshots[0].MutationAttempted = $true
            Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
            $removedCertificates++
        }
        $remainingMaviCertificates = if ($disableOpenSsh) {
            @(Get-MaviLeavesForRoot -ExpectedRoot $expectedRootCertificate).Count
        }
        else {
            @(
                Get-MaviLeafCertificates `
                    -ExpectedRoot $expectedRootCertificate `
                    -ExpectedFqdn $ExpectedFqdn
            ).Count
        }
        if ($remainingMaviCertificates -ne 0) {
            throw 'Mavi WinRM Reset: Ein eindeutig Mavi-verwaltetes Serverzertifikat konnte nicht entfernt werden.'
        }
    }

    if ($winRmScopeVerified -and $effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $otherMaviLeafCount = @(Get-MaviLeavesForRoot -ExpectedRoot $expectedRootCertificate).Count
        if ($otherMaviLeafCount -eq 0 -and $null -ne $installedRootCertificate) {
            $rootSnapshots = @(
                $winRmCertificateSnapshots |
                Where-Object { $_.ProviderPath -ceq [string]$installedRootCertificate.PSPath }
            )
            if ($rootSnapshots.Count -ne 1) {
                throw 'Mavi WinRM Reset: Der Root-Zertifikatssnapshot ist vor der Löschung nicht eindeutig.'
            }
            $rootSnapshots[0].MutationAttempted = $true
            Remove-Item -LiteralPath $rootPath -Force -ErrorAction Stop
            $removedCertificates++
        }
    }

    if (Test-Path -LiteralPath $workDirectory) {
        $workDirectoryRemovalAttempted = $true
        Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction Stop
    }

    if ($disableOpenSsh) {
        # Die Bootstrap-CA wird nie über Subject/Issuer oder einen Inventory-
        # Thumbprint autorisiert. Der Remote-Store muss bytegenau dem DER aus
        # dem root-kontrollierten Controller-Archiv entsprechen.
        foreach ($bootstrapCertificate in $bootstrapCertificatesToRemove) {
            $bootstrapSnapshots = @(
                $winRmCertificateSnapshots |
                Where-Object { $_.ProviderPath -ceq [string]$bootstrapCertificate.Certificate.PSPath }
            )
            if ($bootstrapSnapshots.Count -ne 1) {
                throw 'Mavi Remote-Aus: Der Bootstrap-CA-Snapshot ist vor der Löschung nicht eindeutig.'
            }
            $bootstrapSnapshots[0].MutationAttempted = $true
            Remove-Item -LiteralPath $bootstrapCertificate.Path -Force -ErrorAction Stop
            $removedBootstrapCertificates++
        }
        foreach ($bootstrapRootThumbprint in $BootstrapRootThumbprints) {
            $bootstrapRootPath = "Cert:\LocalMachine\Root\$bootstrapRootThumbprint"
            if (Test-Path -LiteralPath $bootstrapRootPath) {
                throw 'Mavi Remote-Aus: Eine exakt erwartete Bootstrap-CA ist weiterhin im Windows Root Store vorhanden.'
            }
        }
        $bootstrapScopeVerified = $true
    }
}
catch {
    $cleanupError = $_.Exception.Message
}

if (-not [string]::IsNullOrWhiteSpace($cleanupError)) {
    throw "Mavi WinRM Reset wurde nicht vollständig ausgeführt: $cleanupError"
}

# Die destruktive Finalisierung beginnt erst nach vollständig erfolgreichem
# Cleanup. Scheitert sie selbst, wird der vorherige Dienstzustand ebenfalls
# wiederhergestellt, statt einen halb abgeschalteten Zugang zu hinterlassen.
try {
    # Die ursprüngliche Richtlinie wird noch unter vollständiger
    # Netzwerkisolation zurückgeschrieben. Danach wird WinRM gestoppt und
    # deaktiviert; erst dann dürfen die temporären Block-Regeln verschwinden.
    Restore-MaviAllowNegotiatePolicy
    Stop-Service -Name WinRM -Force -ErrorAction Stop
    Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
    $service = Get-Service -Name WinRM -ErrorAction Stop
    $serviceStartValue = [int](Get-ItemPropertyValue `
        -LiteralPath $winRmServicePath `
        -Name Start `
        -ErrorAction Stop
    )
    if (
        ($winRmScopeVerified -and ($remainingMaviListeners -ne 0 -or $remainingMaviCertificates -ne 0)) -or
        [string]$service.Status -ne 'Stopped' -or
        $serviceStartValue -ne 4
    ) {
        throw 'Mavi WinRM Reset: Der abschließende Stand-0-Nachweis ist fehlgeschlagen.'
    }
    Remove-MaviResetIsolationRules
}
catch {
    $finalizationError = $_.Exception.Message
    throw "Mavi WinRM Reset konnte WinRM nicht sicher deaktivieren: $finalizationError"
}

if ($disableOpenSsh) {
    try {
        # Der Task wurde bereits im falliblen Preflight vor jeder destruktiven
        # WinRM-Aenderung registriert und eindeutig ausgelesen.
        $openSshMutationStarted = $true
        Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $taskStartDeadline = (Get-Date).AddSeconds(6)
        do {
            Start-Sleep -Milliseconds 250
            $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $scheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if ($scheduledTask.State -eq 'Running' -or $scheduledTaskInfo.LastRunTime -gt $beforeTaskRun) {
                $openSshDisableScheduled = $true
                break
            }
        } while ((Get-Date) -lt $taskStartDeadline)
        if (-not $openSshDisableScheduled) {
            throw 'Mavi Remote-Aus: Der kontrollierte sshd-Stopp konnte nicht gestartet werden.'
        }

        $sshdStopDeadline = (Get-Date).AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 250
            $sshdService = Get-Service -Name sshd -ErrorAction Stop
            $sshdStartValue = [int](Get-ItemPropertyValue `
                -LiteralPath $sshdServicePath `
                -Name Start `
                -ErrorAction Stop
            )
            $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $scheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if (
                [string]$sshdService.Status -eq 'Stopped' -and
                $sshdStartValue -eq 4 -and
                [string]$scheduledTask.State -ne 'Running'
            ) {
                if ([int]$scheduledTaskInfo.LastTaskResult -ne 0) {
                    throw "Mavi Remote-Aus: Der SYSTEM-Task endete mit Code $($scheduledTaskInfo.LastTaskResult)."
                }
                $openSshStoppedVerified = $true
                $openSshStartupDisabled = $true
                $openSshState = [string]$sshdService.Status
                $openSshStartMode = 'Disabled'
                break
            }
        } while ((Get-Date) -lt $sshdStopDeadline)
        if (-not $openSshStoppedVerified) {
            throw 'Mavi Remote-Aus: Der gestartete SYSTEM-Task hat sshd nicht nachweisbar gestoppt und deaktiviert.'
        }

        # Der einmalige Task wird noch vor dem Entfernen der Zugangsdaten
        # vollständig abgeräumt. Ein Fehler ist dadurch weiterhin rollbackbar.
        Unregister-ScheduledTask `
            -TaskName $taskName `
            -Confirm:$false `
            -ErrorAction Stop
        $taskRegistered = $false

        if ($originalKeyFileExists) {
            $keyLines = @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)
            $keptKeyLines = New-Object 'System.Collections.Generic.List[string]'
            foreach ($keyLineObject in $keyLines) {
                $keyLine = [string]$keyLineObject
                $trimmedKeyLine = $keyLine.Trim()
                $isMaviKey = $false
                if (-not [string]::IsNullOrWhiteSpace($CurrentKeyMarker)) {
                    $markerPattern = '(^|\s)' + [regex]::Escape($CurrentKeyMarker) + '(\s|$)'
                    $isMaviKey = $trimmedKeyLine -match $markerPattern
                }
                if (
                    -not $isMaviKey -and
                    -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
                    ($trimmedKeyLine -eq $CurrentKeyPrefix -or $trimmedKeyLine.StartsWith($CurrentKeyPrefix + ' '))
                ) {
                    $isMaviKey = $true
                }
                if ($isMaviKey) {
                    $removedOpenSshKeys++
                    continue
                }
                $keptKeyLines.Add($keyLine)
            }
            if ($removedOpenSshKeys -gt 0) {
                $keyRewriteAttempted = $true
                [System.IO.File]::WriteAllLines(
                    $keyFile,
                    [string[]]$keptKeyLines,
                    [System.Text.Encoding]::ASCII
                )
            }
        }

        if (Test-Path -LiteralPath $keyFile -PathType Leaf) {
            foreach ($remainingKeyLineObject in @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)) {
                $remainingKeyLine = ([string]$remainingKeyLineObject).Trim()
                $remainingIsMaviKey = $false
                if (-not [string]::IsNullOrWhiteSpace($CurrentKeyMarker)) {
                    $markerPattern = '(^|\s)' + [regex]::Escape($CurrentKeyMarker) + '(\s|$)'
                    $remainingIsMaviKey = $remainingKeyLine -match $markerPattern
                }
                if (
                    -not $remainingIsMaviKey -and
                    -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
                    ($remainingKeyLine -eq $CurrentKeyPrefix -or $remainingKeyLine.StartsWith($CurrentKeyPrefix + ' '))
                ) {
                    $remainingIsMaviKey = $true
                }
                if ($remainingIsMaviKey) {
                    throw 'Mavi Remote-Aus: Ein Mavi-OpenSSH-Schlüssel ist weiterhin vorhanden.'
                }
            }
        }

        # Die aktive sshd_config wird bewusst nicht zurückgeschrieben. Nur die
        # eindeutig vom Mavi-Starter erzeugte Sicherung wird entfernt.
        if ($originalOpenSshConfigBackupExists) {
            $configBackupRemovalAttempted = $true
            Remove-Item -LiteralPath $openSshConfigBackup -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $openSshConfigBackup) {
                throw 'Mavi Remote-Aus: Die Mavi-sshd-Konfigurationssicherung ist weiterhin vorhanden.'
            }
            $removedOpenSshConfigBackups++
        }

        $rulesToRemove = @(Get-NetFirewallRule -Name $OpenSshFirewallRuleName -ErrorAction SilentlyContinue)
        foreach ($rule in $rulesToRemove) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removedOpenSshFirewallRules++
        }
        if (@(Get-NetFirewallRule -Name $OpenSshFirewallRuleName -ErrorAction SilentlyContinue).Count -ne 0) {
            throw 'Mavi Remote-Aus: Die Mavi-OpenSSH-Firewallregel ist weiterhin vorhanden.'
        }
    }
    catch {
        $openSshFinalizationError = $_.Exception.Message
        $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'

        if ($taskRegistered) {
            try {
                $taskRollbackDeadline = (Get-Date).AddSeconds(30)
                do {
                    $taskForRollback = Get-ScheduledTask `
                        -TaskName $taskName `
                        -ErrorAction SilentlyContinue
                    if ($null -eq $taskForRollback) {
                        break
                    }
                    $taskStateForRollback = [string]$taskForRollback.State
                    if ($taskStateForRollback -notin @('Running', 'Queued')) {
                        break
                    }
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    Start-Sleep -Milliseconds 250
                } while ((Get-Date) -lt $taskRollbackDeadline)

                $taskForRollback = Get-ScheduledTask `
                    -TaskName $taskName `
                    -ErrorAction SilentlyContinue
                if (
                    $null -ne $taskForRollback -and
                    [string]$taskForRollback.State -in @('Running', 'Queued')
                ) {
                    throw 'Der OpenSSH-Finalizer-Task konnte vor dem Rollback nicht sicher beendet werden.'
                }
                Unregister-ScheduledTask `
                    -TaskName $taskName `
                    -Confirm:$false `
                    -ErrorAction Stop
                if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
                    throw 'Der OpenSSH-Finalizer-Task ist nach dem Rollback weiterhin registriert.'
                }
                $taskRegistered = $false
            }
            catch {
                [void]$rollbackErrors.Add("Scheduled Task: $($_.Exception.Message)")
            }
        }

        if ($openSshMutationStarted) {
            if ($keyRewriteAttempted) {
                try {
                    if ($originalKeyFileExists) {
                        [System.IO.File]::WriteAllBytes($keyFile, $originalKeyFileBytes)
                    }
                    else {
                        Remove-Item -LiteralPath $keyFile -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    [void]$rollbackErrors.Add("OpenSSH-Key: $($_.Exception.Message)")
                }
            }

            if ($configBackupRemovalAttempted) {
                try {
                    if ($originalOpenSshConfigBackupExists) {
                        [System.IO.File]::WriteAllBytes(
                            $openSshConfigBackup,
                            $originalOpenSshConfigBackupBytes
                        )
                    }
                }
                catch {
                    [void]$rollbackErrors.Add("sshd-Konfigurationssicherung: $($_.Exception.Message)")
                }
            }

            if ($originalOpenSshFirewallRuleExists) {
                try {
                    $currentOpenSshRules = @(
                        Get-NetFirewallRule `
                            -Name $OpenSshFirewallRuleName `
                            -ErrorAction SilentlyContinue
                    )
                    if ($currentOpenSshRules.Count -eq 0) {
                        New-NetFirewallRule `
                            -Name $OpenSshFirewallRuleName `
                            -DisplayName $originalOpenSshFirewallDisplayName `
                            -Enabled $originalOpenSshFirewallRuleEnabledValue `
                            -Direction Inbound `
                            -Protocol TCP `
                            -Action Allow `
                            -LocalPort 22 `
                            -RemoteAddress $originalOpenSshFirewallRemoteAddresses `
                            -Profile Any `
                            -EdgeTraversalPolicy Block `
                            -ErrorAction Stop | Out-Null
                    }
                    elseif ($currentOpenSshRules.Count -eq 1) {
                        if ($originalOpenSshFirewallRuleEnabledValue -eq 'True') {
                            Enable-NetFirewallRule -InputObject $currentOpenSshRules[0] -ErrorAction Stop
                        }
                        else {
                            Disable-NetFirewallRule -InputObject $currentOpenSshRules[0] -ErrorAction Stop
                        }
                    }
                    else {
                        throw 'Die Mavi-OpenSSH-Firewallregel ist beim Rollback nicht eindeutig.'
                    }
                }
                catch {
                    [void]$rollbackErrors.Add("OpenSSH-Firewall: $($_.Exception.Message)")
                }
            }

            try {
                Restore-MaviSshdServiceState `
                    -OriginalStatus $originalSshdStatus `
                    -OriginalStartValue $originalSshdStartValue `
                    -OriginalDelayedAutoStart $originalSshdDelayedAutoStart `
                    -OriginalDelayedAutoStartExists $originalSshdDelayedAutoStartExists `
                    -ServicePath $sshdServicePath
            }
            catch {
                [void]$rollbackErrors.Add("sshd-Dienst: $($_.Exception.Message)")
            }
        }

        if ($rollbackErrors.Count -gt 0) {
            throw "Mavi Remote-Aus: OpenSSH-Finalisierung fehlgeschlagen: $openSshFinalizationError; Rollback unvollständig: $($rollbackErrors -join '; ')"
        }
        if ($openSshMutationStarted) {
            throw "Mavi Remote-Aus: OpenSSH-Finalisierung fehlgeschlagen, der ursprüngliche SSH-Zugang wurde wiederhergestellt: $openSshFinalizationError"
        }
        throw "Mavi Remote-Aus: OpenSSH-Finalizer konnte ohne Zugangsänderung nicht vorbereitet werden: $openSshFinalizationError"
    }
}
}
catch {
    $resetError = $_.Exception.Message
    $rollbackErrors = New-Object 'System.Collections.Generic.List[string]'

    # Ein im Preflight registrierter, aber noch nicht gestarteter Task darf bei
    # einem WinRM-Fehler nicht spaeter unvermittelt den SSH-Zugang abschalten.
    if ($taskRegistered) {
        try {
            $taskForRollback = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -ne $taskForRollback -and [string]$taskForRollback.State -in @('Running', 'Queued')) {
                Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
            }
            Unregister-ScheduledTask `
                -TaskName $taskName `
                -Confirm:$false `
                -ErrorAction Stop
            $taskRegistered = $false
        }
        catch {
            [void]$rollbackErrors.Add("Scheduled Task: $($_.Exception.Message)")
        }
    }

    $providerReadyForRollback = $false
    if ($winRmMutationStarted) {
        try {
            Enable-MaviWinRmProviderMaintenance
            $providerReadyForRollback = $true
        }
        catch {
            [void]$rollbackErrors.Add("WSMan-Wartungsmodus: $($_.Exception.Message)")
        }
    }

    if ($winRmMutationStarted -and $providerReadyForRollback) {
        try {
            Restore-MaviWinRmArtifacts
        }
        catch {
            [void]$rollbackErrors.Add("WinRM-Artefakte: $($_.Exception.Message)")
        }
    }

    $policyRestored = $false
    if ($winRmMaintenanceAttempted) {
        try {
            Restore-MaviAllowNegotiatePolicy
            $policyRestored = $true
        }
        catch {
            [void]$rollbackErrors.Add("WinRM-AllowNegotiate-Richtlinie: $($_.Exception.Message)")
        }
    }

    $serviceRestored = $false
    if ($winRmMaintenanceAttempted) {
        try {
            if ($policyRestored -and $originalWinRmStatus -eq 'Running') {
                # Den ursprünglichen Richtlinienwert sicher in den laufenden
                # Dienst übernehmen, solange beide Netzwerkports blockiert sind.
                Restart-Service -Name WinRM -Force -ErrorAction Stop
            }
            Restore-MaviWinRmServiceState `
                -OriginalStatus $originalWinRmStatus `
                -OriginalStartValue $originalWinRmStartValue `
                -OriginalDelayedAutoStart $originalWinRmDelayedAutoStart `
                -OriginalDelayedAutoStartExists $originalWinRmDelayedAutoStartExists
            $serviceRestored = $true
        }
        catch {
            [void]$rollbackErrors.Add("WinRM-Dienst: $($_.Exception.Message)")
        }
    }

    if ($winRmMaintenanceAttempted -and $policyRestored -and $serviceRestored) {
        try {
            Remove-MaviResetIsolationRules
        }
        catch {
            [void]$rollbackErrors.Add("WinRM-Wartungsfirewall: $($_.Exception.Message)")
        }
    }

    if ($rollbackErrors.Count -gt 0) {
        throw "Mavi Remote-Aus fehlgeschlagen: $resetError; Rollback unvollstaendig: $($rollbackErrors -join '; ')"
    }
    if ($winRmMutationStarted) {
        throw "Mavi Remote-Aus fehlgeschlagen; WinRM-Artefakte und Dienstzustand wurden wiederhergestellt: $resetError"
    }
    throw "Mavi Remote-Aus wurde vor der ersten destruktiven WinRM-Aenderung abgebrochen: $resetError"
}

$result = [ordered]@{
    RemovedListeners = $removedListeners
    RemovedCertificates = $removedCertificates
    RemovedFirewallRules = $removedFirewallRules
    RemovedOpenSshFirewallRules = $removedOpenSshFirewallRules
    RemovedOpenSshKeys = $removedOpenSshKeys
    RemovedOpenSshConfigBackups = $removedOpenSshConfigBackups
    RemovedBootstrapCertificates = $removedBootstrapCertificates
    BootstrapScopeVerified = $bootstrapScopeVerified
    OpenSshDisableScheduled = $openSshDisableScheduled
    OpenSshStartupDisabled = $openSshStartupDisabled
    OpenSshStoppedVerified = $openSshStoppedVerified
    OpenSshState = $openSshState
    OpenSshStartMode = $openSshStartMode
    WinRMState = [string]$service.Status
    WinRMStartMode = 'Disabled'
    WinRmScopeVerified = $winRmScopeVerified
    WinRmListenersCleared = $winRmListenersCleared
    PreservedForeignWinRmListeners = $preservedWinRmListeners
    WinRmRootThumbprint = $effectiveRootThumbprint
    BootstrapRootThumbprint = @($BootstrapRootThumbprints | Select-Object -First 1)[0]
    BootstrapRootThumbprints = @($BootstrapRootThumbprints)
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM und Kerberos-Transport auf Stand 0 zurücksetzen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Eindeutig Mavi-verwaltete WinRM-Artefakte entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "RootThumbprint": root_thumbprint,
                        "RootCertificateDerBase64": root_certificate_der_base64,
                        "ExpectedFqdn": expected_fqdn,
                        "BootstrapRootCertificatesDerBase64": normalized_bootstrap_certificates,
                        "DisableOpenSshValue": 1 if disable_openssh else 0,
                        "CurrentKeyPrefix": public_key_prefix,
                        "CurrentKeyMarker": key_marker,
                        "OpenSshFirewallRuleName": openssh_firewall_rule,
                        "OpenSshConfigBackupPath": openssh_config_backup,
                    },
                },
                "register": "mavi_remote_management_reset",
            },
            {
                "name": "Mavi Rückbau-Ergebnis auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_REMOTE_RESET_B64={{ mavi_remote_management_reset.result.Marker }}",
                },
            },
        ],
    }]

def _winrm_kerberos_https_ping_play() -> list[dict[str, Any]]:
    """Minimaler echter PSRP-Test; die Aufrufer legen die TLS/Kerberos-Variablen als Overlay fest."""
    return [{
        "name": "Mavi Kerberos-HTTPS-Nachweis",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "PSRP über strikt validiertes HTTPS und Kerberos prüfen",
                "ansible.windows.win_ping": {},
            },
        ],
    }]
