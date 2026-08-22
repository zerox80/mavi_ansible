# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""WinRM-HTTPS-Einrichtungsplaybooks.

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



def _winrm_install_https_play(
    *,
    certificate_path: str,
    certificate_sha256: str,
    ca_certificate_path: str,
    ca_certificate_sha256: str,
    identity: dict[str, Any],
    settings: dict[str, Any],
    ansible_server_ip: str,
) -> list[dict[str, Any]]:
    """Play für Zertifikatsannahme, HTTPS-Listener und enges Firewall-Scoping."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$CertificatePath,
    [string]$ExpectedSha256,
    [string]$RootCertificatePath,
    [string]$ExpectedRootSha256,
    [string]$Fqdn,
    [string]$AnsibleServerIp,
    [int]$Port,
    [string]$RuleName
)

$ErrorActionPreference = 'Stop'
if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Zertifikats-SHA-256 ist ungültig.'
}
if ($ExpectedRootSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Root-CA-SHA-256 ist ungültig.'
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw 'Mavi WinRM TLS: Port ist ungültig.'
}
$parsedAnsibleIp = $null
if (-not [System.Net.IPAddress]::TryParse($AnsibleServerIp, [ref]$parsedAnsibleIp)) {
    throw "Mavi WinRM TLS: ansible_server_ip ist ungültig: $AnsibleServerIp"
}
if ($parsedAnsibleIp.Equals([System.Net.IPAddress]::Any) -or $parsedAnsibleIp.Equals([System.Net.IPAddress]::IPv6Any)) {
    throw 'Mavi WinRM TLS: ansible_server_ip darf kein Wildcard-Wert sein.'
}
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: signiertes Zertifikat fehlt: $CertificatePath"
}
if (-not (Test-Path -LiteralPath $RootCertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: öffentliche Mavi-Root-CA fehlt: $RootCertificatePath"
}
$actualSha256 = [string](Get-FileHash -LiteralPath $CertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualSha256.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: WinRM-Zertifikat wurde vor der Annahme verändert. Erwartet=$ExpectedSha256 Ist=$actualSha256"
}
$actualRootSha256 = [string](Get-FileHash -LiteralPath $RootCertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualRootSha256.Equals($ExpectedRootSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: Mavi-WinRM-Root-CA wurde vor der Annahme verändert. Erwartet=$ExpectedRootSha256 Ist=$actualRootSha256"
}

$rootCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCertificatePath)
$basicConstraints = @($rootCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
if ($basicConstraints.Count -ne 1) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA hat keine eindeutige Basic-Constraints-Erweiterung.'
}
$decodedConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
$decodedConstraints.CopyFrom($basicConstraints[0])
if (-not $decodedConstraints.CertificateAuthority) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA ist kein CA-Zertifikat.'
}
Import-Certificate -FilePath $RootCertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
& $certreq -accept $CertificatePath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "certreq -accept konnte das Mavi-WinRM-Zertifikat nicht annehmen (Exit-Code $LASTEXITCODE)."
}

$selected = $null
foreach ($candidate in @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop)) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $candidateHash = ([System.BitConverter]::ToString($sha.ComputeHash($candidate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
    if ($candidateHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        $selected = $candidate
        break
    }
}
if ($null -eq $selected) {
    throw 'Mavi WinRM TLS: das exakt signierte Zertifikat wurde nicht im LocalMachine\\My Store gefunden.'
}
if (-not $selected.HasPrivateKey) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat hat keinen lokalen privaten Schlüssel.'
}
if (-not $selected.Issuer.Equals($rootCertificate.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Mavi WinRM TLS: das Serverzertifikat wurde nicht von der erwarteten Mavi-Root-CA ausgestellt.'
}
if ($selected.NotAfter -le (Get-Date).AddDays(1)) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat läuft zu früh ab.'
}
$hasServerAuth = $false
foreach ($extension in @($selected.Extensions)) {
    if ([string]$extension.Oid.Value -ne '2.5.29.37') { continue }
    $ekuExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension
    foreach ($usage in @($ekuExtension.EnhancedKeyUsages)) {
        if ([string]$usage.Value -eq '1.3.6.1.5.5.7.3.1') {
            $hasServerAuth = $true
            break
        }
    }
    if ($hasServerAuth) { break }
}
if (-not $hasServerAuth) {
    throw 'Mavi WinRM TLS: dem Zertifikat fehlt Server Authentication EKU.'
}
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
if (-not $chain.Build($selected)) {
    $chainStatus = (@($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')
    throw "Mavi WinRM TLS: die lokale Windows-Zertifikatskette ist nicht gültig: $chainStatus"
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SICHERHEITSABBRUCH: Die OpenSSH-Sitzung von $($currentIdentity.Name) besitzt keinen erhöhten lokalen Administrator-Token."
}

$httpBlockRuleName = 'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP'
$setupIsolationRuleName = 'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

# Ein früherer, abgebrochener Lauf kann Negotiate bereits deaktiviert haben.
# Der lokale WSMan:-Provider verwaltet selbst localhost:47001 und würde sich
# dann selbst aussperren. Vor der ausschließlich lokalen Reparatur werden
# deshalb beide Netzwerkports vollständig abgeschottet. Block-Regeln haben
# unter Windows Vorrang vor eventuell vorhandenen Allow-Regeln.
Get-NetFirewallRule -DisplayName $httpBlockRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $httpBlockRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort 5985 -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $setupIsolationRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null

New-Item -Path $policyPath -Force | Out-Null
# Nur während vollständig blockierter 5985/5986-Ports darf der lokale
# WSMan-Provider wieder administrieren. Von außen ist Negotiate dabei niemals
# erreichbar. Der finally-Block erzwingt anschließend wieder Kerberos-only.
Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 1 -Force
Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
Restart-Service -Name WinRM -Force -ErrorAction Stop

try {
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false -Force -ErrorAction Stop

    $httpsListeners = @(
        Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
        Where-Object { $_.Keys -contains 'Transport=HTTPS' }
    )
    if ($httpsListeners.Count -gt 0) {
        $managedExistingListeners = @()
        foreach ($listener in $httpsListeners) {
            # WSMan-Listener stellen Hostname, Port und Fingerabdruck als
            # Kindelemente bereit, nicht verlässlich als direkte Eigenschaften
            # des Listener-Containers. Direkter Property-Zugriff lieferte bei
            # einem vorhandenen Listener einen leeren Fingerabdruck; der daraus
            # gebildete Cert:-Pfad zeigte dann auf den gesamten X509Store.
            $listenerValues = @{}
            foreach ($listenerValue in @(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop)) {
                $listenerValueName = [string]$listenerValue.Name
                if (-not [string]::IsNullOrWhiteSpace($listenerValueName)) {
                    $listenerValues[$listenerValueName] = [string]$listenerValue.Value
                }
            }
            $listenerThumbprint = ([string]$listenerValues['CertificateThumbprint']).Trim() -replace '\s', ''
            $listenerHostname = ([string]$listenerValues['Hostname']).Trim()
            $listenerPort = 0
            $listenerPortIsValid = [int]::TryParse(
                ([string]$listenerValues['Port']).Trim(),
                [ref]$listenerPort
            )
            if ($listenerThumbprint -notmatch '^[a-fA-F0-9]{40}$') {
                throw 'SICHERHEITSABBRUCH: Ein vorhandener WinRM-HTTPS-Listener enthält keinen gültigen Zertifikatfingerabdruck. Mavi verändert diesen TLS-Endpunkt nicht.'
            }
            $listenerCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\My\$listenerThumbprint") -ErrorAction SilentlyContinue
            $listenerChainIsMavi = $false
            if ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $listenerChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $listenerChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                try {
                    if ($listenerChain.Build($listenerCertificate) -and $listenerChain.ChainElements.Count -gt 0) {
                        $listenerRoot = $listenerChain.ChainElements[$listenerChain.ChainElements.Count - 1].Certificate
                        $listenerChainIsMavi = $listenerRoot.Thumbprint.Equals(
                            $rootCertificate.Thumbprint,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
                }
                finally {
                    $listenerChain.Dispose()
                }
            }
            $expectedFriendlyName = "Mavi WinRM HTTPS $Fqdn"
            $listenerIsMaviManaged = (
                $listenerPortIsValid -and
                ($listenerPort -eq $Port) -and
                $listenerHostname.Equals($Fqdn, [System.StringComparison]::OrdinalIgnoreCase) -and
                ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) -and
                ([string]$listenerCertificate.FriendlyName).Equals($expectedFriendlyName, [System.StringComparison]::Ordinal) -and
                $listenerChainIsMavi
            )
            if (-not $listenerIsMaviManaged) {
                throw 'SICHERHEITSABBRUCH: Es existiert bereits ein fremder WinRM-HTTPS-Listener. Mavi ersetzt fremde TLS-Endpunkte nie still.'
            }
            $managedExistingListeners += [PSCustomObject]@{
                Listener = $listener
                CertificateThumbprint = $listenerThumbprint
            }
        }

        $alreadyCurrent = @(
            $managedExistingListeners | Where-Object {
                ([string]$_.CertificateThumbprint).Equals($selected.Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($managedExistingListeners.Count -ne 1 -or $alreadyCurrent.Count -ne 1) {
            foreach ($listener in $managedExistingListeners) {
                Remove-Item -LiteralPath $listener.Listener.PSPath -Recurse -Force -ErrorAction Stop
            }
            New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
        }
    }
    else {
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
    }

$existingAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    $portFilter = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
    foreach ($filter in $portFilter) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains [string]$Port) {
            if ([string]$rule.DisplayName -ne $RuleName) { $existingAllowRules += $rule }
        }
    }
}
if ($existingAllowRules.Count -gt 0) {
    $names = ($existingAllowRules | Select-Object -ExpandProperty DisplayName -Unique) -join ', '
    throw "SICHERHEITSABBRUCH: Bereits aktive Firewall-Freigabe(n) für TCP/$Port gefunden: $names. Mavi lässt keinen breiteren parallelen HTTPS-Zugang stehen."
}
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $RuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress $AnsibleServerIp -EdgeTraversalPolicy Block | Out-Null
$managedRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
$managedPort = @($managedRule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object -First 1)
$managedAddress = @($managedRule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object -First 1)
if ($managedPort.Count -ne 1 -or [string]$managedPort[0].Protocol -ne 'TCP' -or -not (@($managedPort[0].LocalPort) -contains [string]$Port)) {
    throw 'Mavi WinRM TLS: die eigene TCP-Port-Firewallregel konnte nicht exakt geprüft werden.'
}
$managedRemoteAddresses = @($managedAddress[0].RemoteAddress)
if ($managedAddress.Count -ne 1 -or $managedRemoteAddresses.Count -ne 1 -or [string]$managedRemoteAddresses[0] -ne $AnsibleServerIp) {
    throw 'Mavi WinRM TLS: die eigene Firewallregel ist nicht exakt auf die Ansible-IP beschränkt.'
}

# HTTP vollständig entfernen, solange der lokale Provider in der isolierten
# Phase noch erreichbar ist. Die dauerhafte Block-Regel für 5985 bleibt auch
# danach bestehen.
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remainingHttpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remainingHttpListeners.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallAllowRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallAllowRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}

# Den exakten Listener noch prüfen, solange der lokale WSMan-Provider über
# das vollständig netzwerkisolierte Negotiate-Fenster erreichbar ist. Nach dem
# anschließenden Kerberos-only-Neustart darf dieser Prozess den Provider nicht
# erneut öffnen; genau das scheitert auf korrekt gehärteten Hosts erwartbar.
$finalHttpsListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTPS' }
)
if ($finalHttpsListeners.Count -ne 1) {
    throw 'Mavi WinRM TLS: Der finale HTTPS-Listener ist nicht eindeutig.'
}
$finalListenerValues = @{}
foreach ($listenerValue in @(Get-ChildItem -LiteralPath $finalHttpsListeners[0].PSPath -ErrorAction Stop)) {
    $listenerValueName = [string]$listenerValue.Name
    if (-not [string]::IsNullOrWhiteSpace($listenerValueName)) {
        $finalListenerValues[$listenerValueName] = [string]$listenerValue.Value
    }
}
$finalListenerThumbprint = ([string]$finalListenerValues['CertificateThumbprint']).Trim() -replace '\s', ''
if (
    $finalListenerThumbprint -notmatch '^[a-fA-F0-9]{40}$' -or
    -not $finalListenerThumbprint.Equals($selected.Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)
) {
    throw 'Mavi WinRM TLS: Der finale HTTPS-Listener verwendet nicht das gerade bestätigte Mavi-Serverzertifikat.'
}
}
finally {
    # Diese ADMX-gestützten Dienstwerte sind die fail-closed Endstellung.
    # Der Block für 5986 bleibt bei jedem Fehler erhalten. Damit ist während
    # und nach einem fehlgeschlagenen Lauf weder HTTP noch Negotiate von außen
    # erreichbar; OpenSSH bleibt als Reparaturkanal bestehen.
    New-Item -Path $policyPath -Force | Out-Null
    Set-ItemProperty -Path $policyPath -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowKerberos -Type DWord -Value 1 -Force
    Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowBasic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowCredSSP -Type DWord -Value 0 -Force
    Restart-Service -Name WinRM -Force -ErrorAction Stop
}

$finalPolicy = Get-ItemProperty -Path $policyPath -ErrorAction Stop
if ([int]$finalPolicy.AllowUnencryptedTraffic -ne 0 -or
    [int]$finalPolicy.AllowKerberos -ne 1 -or
    [int]$finalPolicy.AllowNegotiate -ne 0 -or
    [int]$finalPolicy.AllowBasic -ne 0 -or
    [int]$finalPolicy.AllowCredSSP -ne 0) {
    throw 'SICHERHEITSABBRUCH: Die WinRM-Dienstrichtlinie ist nicht Kerberos-only.'
}
$remainingHttpAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $remainingHttpAllowRules += $rule
            break
        }
    }
}
if ($remainingHttpAllowRules.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}

# Nach dem Kerberos-only-Neustart ausschließlich providerunabhängig prüfen.
# Der exakte Listener wurde unmittelbar davor geprüft; ein laufender Dienst,
# korrekter Starttyp und lokaler Listen-Socket belegen, dass WinRM die
# persistierte Konfiguration wieder erfolgreich geladen hat. Die zwei echten
# PSRP/Kerberos-Nachweise des Controllers bleiben der abschließende End-to-End-
# Beweis, bevor das Inventory auf PSRP umgestellt wird.
$finalWinRmService = Get-Service -Name WinRM -ErrorAction Stop
$finalWinRmStartValue = [int](Get-ItemPropertyValue `
    -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM' `
    -Name Start `
    -ErrorAction Stop
)
if (
    [string]$finalWinRmService.Status -ne 'Running' -or
    $finalWinRmStartValue -ne 2
) {
    throw 'Mavi WinRM TLS: WinRM läuft nach dem Kerberos-only-Neustart nicht im erwarteten automatischen Zustand.'
}
$finalSocketDeadline = (Get-Date).AddSeconds(15)
$finalWinRmTcpListeners = @()
do {
    $finalWinRmTcpListeners = @(
        Get-NetTCPConnection `
            -State Listen `
            -LocalPort $Port `
            -ErrorAction SilentlyContinue
    )
    if ($finalWinRmTcpListeners.Count -gt 0) { break }
    Start-Sleep -Milliseconds 250
} while ((Get-Date) -lt $finalSocketDeadline)
if ($finalWinRmTcpListeners.Count -eq 0) {
    throw "Mavi WinRM TLS: Nach dem Kerberos-only-Neustart lauscht kein lokaler Endpunkt auf TCP/$Port."
}

# Erst nach dem nachgewiesenen Listenerwechsel werden ausschließlich ältere,
# eindeutig Mavi-eigene Serverzertifikate desselben Mavi-Root-Zertifikats und
# desselben Ziel-FQDN entfernt. Das neue Leaf bleibt immer erhalten; fremde
# CAs sowie Mavi-Leaves anderer Endpunkte bleiben unangetastet.
function Test-MaviManagedLeafForRoot {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot,
        [string]$ExpectedFqdn
    )
    $expectedFriendlyName = "Mavi WinRM HTTPS $ExpectedFqdn"
    if (
        $null -eq $Certificate -or
        $null -eq $ExpectedRoot -or
        [string]::IsNullOrWhiteSpace($ExpectedFqdn) -or
        -not ([string]$Certificate.FriendlyName).Equals(
            $expectedFriendlyName,
            [System.StringComparison]::Ordinal
        )
    ) {
        return $false
    }
    $subjectName = [string]$Certificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if (-not $subjectName.Equals($ExpectedFqdn, [System.StringComparison]::OrdinalIgnoreCase)) {
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

$prunedServerCertificates = 0
$selectedThumbprint = ([string]$selected.Thumbprint).ToUpperInvariant()
foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
    if (-not (Test-Path -LiteralPath $storePath)) { continue }
    foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
        $certificateThumbprint = ([string]$certificate.Thumbprint).ToUpperInvariant()
        if ($certificateThumbprint.Equals($selectedThumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        if (Test-MaviManagedLeafForRoot -Certificate $certificate -ExpectedRoot $rootCertificate -ExpectedFqdn $Fqdn) {
            if ($certificate.HasPrivateKey) {
                Remove-Item -LiteralPath $certificate.PSPath -DeleteKey -Force -ErrorAction Stop
            }
            else {
                Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
            }
            $prunedServerCertificates++
        }
    }
}

# Erst nachdem alle falliblen lokalen Nachweise und Bereinigungen erfolgreich
# sind, fällt die Setup-Isolation für 5986. Die enge Allow-Regel ausschließlich
# von der Ansible-IP bleibt bestehen.
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction Stop |
    Remove-NetFirewallRule -ErrorAction Stop

$result = [ordered]@{
    Thumbprint = $selected.Thumbprint
    CertificateSha256 = $actualSha256.ToLowerInvariant()
    RootThumbprint = $rootCertificate.Thumbprint
    NotAfterUtc = $selected.NotAfter.ToUniversalTime().ToString('o')
    RootNotAfterUtc = $rootCertificate.NotAfter.ToUniversalTime().ToString('o')
    PrunedServerCertificates = $prunedServerCertificates
    Fqdn = $Fqdn
    Port = $Port
    FirewallRule = $RuleName
    Http5985Blocked = $true
    KerberosOnly = $true
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $true
'''
    remote_dir = r"C:\ProgramData\Mavi\WinRM-TLS"
    remote_path = remote_dir + r"\mavi-winrm-server.cer"
    remote_ca_path = remote_dir + r"\mavi-winrm-root-ca.cer"
    return [{
        "name": "Mavi WinRM HTTPS sicher einrichten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi WinRM TLS-Arbeitsordner sicherstellen",
                "ansible.windows.win_file": {"path": remote_dir, "state": "directory"},
            },
            {
                "name": "Öffentliche Mavi-WinRM-Root-CA nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": ca_certificate_path,
                    "dest": remote_ca_path,
                    "force": True,
                },
            },
            {
                "name": "Signiertes Mavi-WinRM-Zertifikat nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": certificate_path,
                    "dest": remote_path,
                    "force": True,
                },
            },
            {
                "name": "WinRM HTTPS-Listener und enge Firewallregel konfigurieren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CertificatePath": remote_path,
                        "ExpectedSha256": certificate_sha256,
                        "RootCertificatePath": remote_ca_path,
                        "ExpectedRootSha256": ca_certificate_sha256,
                        "Fqdn": identity["fqdn"],
                        "AnsibleServerIp": ansible_server_ip,
                        "Port": int(settings["port"]),
                        "RuleName": "Mavi-WinRM-HTTPS-Ansible-In-TCP",
                    },
                },
                "register": "mavi_winrm_https_install",
            },
            {
                "name": "Mavi WinRM HTTPS-Ergebnis auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_HTTPS_B64={{ mavi_winrm_https_install.result.Marker }}",
                },
            },
        ],
    }]

def _winrm_remove_http_play() -> list[dict[str, Any]]:
    """HTTP-Listener ausschließlich über die bereits geprüfte TLS-Verbindung entfernen."""
    powershell = r'''[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remaining = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remaining.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}
$stillEnabled = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $stillEnabled += $rule
            break
        }
    }
}
if ($stillEnabled.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}
$Ansible.Result = @{ RemovedHttpListeners = $httpListeners.Count }
$Ansible.Changed = ($httpListeners.Count -gt 0)
'''
    return [{
        "name": "Mavi WinRM HTTP nach HTTPS-Nachweis abschalten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Alte WinRM-HTTP-Listener entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                },
            },
        ],
    }]
