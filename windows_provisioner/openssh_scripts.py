# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Windows-OpenSSH-Bootstrapskripte.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    ThreadPoolExecutor,
    argparse,
    as_completed,
    base64,
    datetime,
    getpass,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    socket,
    ssl,
    subprocess,
    sys,
    tempfile,
    time,
    timezone,
    urllib,
    yaml,
)



def _powershell_single_quote(value: str) -> str:
    return value.replace("'", "''")


def _windows_msi_path_for_ssh_guide(project: Path, raw: str, *, announce: bool = True) -> str:
    """
    Einen vom Admin eingegebenen OpenSSH-MSI-Pfad für den Windows-Bootstrap
    aufbereiten. Windows-Laufwerks- und Linux-Pfade aus der Mavi-Softwareablage werden, wenn
    möglich, in den UNC-Pfad der Softwareablage übersetzt. Das ist für eine
    erhöhte PowerShell robuster, weil gemappte Laufwerke dort fehlen können.
    """
    from .environment import get_config

    value = str(raw or "").strip().strip('"').strip("'")
    if not value:
        return ""

    config = get_config(project)
    source = config.get("software_source", {}) or {}
    drive = str(source.get("drive", "") or "").strip()
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    local_root = str(source.get("local_root", "") or "").strip().rstrip("/")

    # S:\foo\bar.msi -> \\server\share\foo\bar.msi
    if drive and unc_root:
        drive_norm = drive.replace("/", "\\")
        value_norm = value.replace("/", "\\")
        if value_norm.lower().startswith(drive_norm.lower()):
            rel = value_norm[len(drive_norm):].lstrip("\\/")
            converted = unc_root + ("\\" + rel if rel else "")
            if announce:
                print("\n✓ MSI-Pfad für Admin-PowerShell als UNC verwendet:")
                print(f"  {value}")
                print("  →")
                print(f"  {converted}")
            return converted

    # /mnt/.../Install/foo.msi -> \\server\share\foo.msi
    if local_root and unc_root:
        try:
            local_candidate = Path(value).expanduser()
            root_candidate = Path(local_root).expanduser()
            rel = local_candidate.relative_to(root_candidate)
        except (ValueError, OSError):
            rel = None
        if rel is not None:
            converted = unc_root + "\\" + str(rel).replace("/", "\\")
            if announce:
                print("\n✓ Serverpfad für Windows als UNC verwendet:")
                print(f"  {value}")
                print("  →")
                print(f"  {converted}")
            return converted

    return value


def _ssh_bootstrap_ps1(
    public_key: str,
    *,
    bundled_msi: bool,
    msi_path: str = "",
    msi_download_url: str = "",
    msi_sha256: str = "",
    expected_signer: str = "",
    ansible_server_ip: str = "",
    bootstrap_instance_id: str = "",
    bootstrap_ca_thumbprint: str = "",
) -> str:
    """Gehärteten PowerShell-Bootstrap für OpenSSH auf Windows erzeugen."""

    from .openssh import (
        _powershell_single_quote,
    )

    from .settings import VERSION

    public_key = str(public_key or "").strip()
    if (
        len(public_key) > 16384
        or "\r" in public_key
        or "\n" in public_key
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9@._+-]*[ \t]+[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\x00-\x1f\x7f]+)?",
            public_key,
        )
    ):
        raise ValueError("Der Mavi-Public-Key ist nicht genau eine gültige OpenSSH-Public-Key-Zeile.")
    for label, value in (
        ("MSI-Pfad", msi_path),
        ("MSI-URL", msi_download_url),
        ("erwarteter MSI-Signer", expected_signer),
    ):
        if "\r" in str(value or "") or "\n" in str(value or ""):
            raise ValueError(f"{label} darf keine Zeilenumbrüche enthalten.")
    if msi_download_url and urllib.parse.urlsplit(msi_download_url).scheme.lower() != "https":
        raise ValueError("Die OpenSSH-MSI darf nur über HTTPS geladen werden.")
    if msi_sha256 and not re.fullmatch(r"[0-9A-Fa-f]{64}", str(msi_sha256)):
        raise ValueError("Der OpenSSH-MSI-Hash muss aus exakt 64 Hex-Zeichen bestehen.")
    if not re.fullmatch(r"[a-z0-9-]{1,64}", str(bootstrap_instance_id or "")):
        raise ValueError("Die Bootstrap-Instanzkennung ist ungültig.")
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", str(bootstrap_ca_thumbprint or "")):
        raise ValueError("Der Bootstrap-CA-Thumbprint ist ungültig.")
    ps_key = _powershell_single_quote(public_key)
    ps_msi = _powershell_single_quote(msi_path)
    ps_msi_url = _powershell_single_quote(msi_download_url)
    ps_msi_sha256 = _powershell_single_quote(msi_sha256.lower())
    ps_expected_signer = _powershell_single_quote(expected_signer)
    ps_ansible_ip = _powershell_single_quote(ansible_server_ip)
    ps_instance_id = _powershell_single_quote(bootstrap_instance_id)
    ps_ca_thumbprint = _powershell_single_quote(bootstrap_ca_thumbprint.upper())
    # Wird eine MSI bewusst angegeben, darf der Bootstrap nicht still auf die
    # Windows-Capability ausweichen. Sonst sieht der Admin zwar "OpenSSH
    # installiert", bekommt aber nicht die explizit ausgewählte MSI.
    msi_requested = bool(msi_download_url or bundled_msi or msi_path)
    ps_msi_requested = "$true" if msi_requested else "$false"

    if msi_download_url:
        msi_assignment_lines = [
            f"$maviMsiUrl = '{ps_msi_url}'",
            "$maviMsiDir = Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap'",
            "New-Item -ItemType Directory -Path $maviMsiDir -Force | Out-Null",
            "$msiPath = Join-Path $maviMsiDir 'OpenSSH-Win64.msi'",
            "Write-Host '[1/9] OpenSSH-MSI über HTTPS herunterladen...' -ForegroundColor Cyan",
            "try {",
            "    # Invoke-WebRequest validiert Zertifikatskette und Zielnamen normal.",
            "    # Mavi setzt absichtlich keinen CertificateValidationCallback und kein Skip-Flag.",
            "    Invoke-WebRequest -UseBasicParsing -Uri $maviMsiUrl -OutFile $msiPath -TimeoutSec 120 -MaximumRedirection 0",
            "    if (-not (Test-Path -LiteralPath $msiPath)) { throw 'Downloaddatei wurde nicht angelegt.' }",
            "}",
            "catch {",
            "    throw \"OpenSSH-MSI-Download fehlgeschlagen: $($_.Exception.Message). " +
            "Eine OpenSSH-MSI wurde explizit angefordert; Windows-Capability/FoD wird nicht verwendet.\"",
            "}",
        ]
    elif bundled_msi:
        msi_assignment_lines = ["$msiPath = Join-Path $PSScriptRoot 'OpenSSH-Win64.msi'"]
    else:
        msi_assignment_lines = [f"$msiPath = '{ps_msi}'"]

    lines = [
        f"# Mavi OpenSSH Bootstrap v{VERSION} - automatisch erzeugt",
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        f"$expectedMsiSha256 = '{ps_msi_sha256}'",
        f"$expectedMsiSigner = '{ps_expected_signer}'",
        f"$ansibleServerIp = '{ps_ansible_ip}'",
        f"$maviInstanceId = '{ps_instance_id}'",
        f"$maviCaThumbprint = '{ps_ca_thumbprint}'",
        "if ([string]::IsNullOrWhiteSpace($ansibleServerIp)) {",
        "    throw 'SICHERHEITSABBRUCH: ansible_server_ip fehlt. Port 22 wird nicht breit geöffnet.'",
        "}",
        "$parsedAnsibleIp = $null",
        "if (-not [System.Net.IPAddress]::TryParse($ansibleServerIp, [ref]$parsedAnsibleIp)) {",
        "    throw \"SICHERHEITSABBRUCH: Ungültige ansible_server_ip: $ansibleServerIp\"",
        "}",
        "if ($parsedAnsibleIp.Equals([System.Net.IPAddress]::Any) -or $parsedAnsibleIp.Equals([System.Net.IPAddress]::IPv6Any)) {",
        "    throw 'SICHERHEITSABBRUCH: Wildcard-IP ist für ansible_server_ip unzulässig.'",
        "}",
        "",
        "function Assert-MaviMsiTrust {",
        "    param(",
        "        [Parameter(Mandatory=$true)][string]$Path,",
        "        [string]$ExpectedSha256 = '',",
        "        [string]$ExpectedSigner = ''",
        "    )",
        "    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {",
        "        throw \"SICHERHEITSABBRUCH: OpenSSH-MSI fehlt: $Path\"",
        "    }",
        "    if (-not [string]::IsNullOrWhiteSpace($ExpectedSha256)) {",
        "        $actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()",
        "        if ($actualSha256 -cne $ExpectedSha256.ToLowerInvariant()) {",
        "            throw \"SICHERHEITSABBRUCH: OpenSSH-MSI SHA-256 stimmt nicht. Erwartet=$ExpectedSha256 Ist=$actualSha256\"",
        "        }",
        "        Write-Host \"    SHA-256: $actualSha256 (gültig)\" -ForegroundColor Green",
        "    }",
        "    $signature = Get-AuthenticodeSignature -LiteralPath $Path",
        "    if ([string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate) {",
        "        throw \"SICHERHEITSABBRUCH: Authenticode-Status der OpenSSH-MSI ist '$($signature.Status)', erwartet wird 'Valid'.\"",
        "    }",
        "    $subject = [string]$signature.SignerCertificate.Subject",
        "    $simpleName = [string]$signature.SignerCertificate.GetNameInfo(",
        "        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,",
        "        $false",
        "    )",
        "    if (-not [string]::IsNullOrWhiteSpace($ExpectedSigner) -and",
        "        $subject -ine $ExpectedSigner -and $simpleName -ine $ExpectedSigner) {",
        "        throw \"SICHERHEITSABBRUCH: MSI-Signer stimmt nicht. Erwartet='$ExpectedSigner' Subject='$subject' SimpleName='$simpleName'.\"",
        "    }",
        "    Write-Host \"    Authenticode: Valid | Signer: $subject\" -ForegroundColor Green",
        "}",
        "",
        *msi_assignment_lines,
        f"$maviMsiRequested = {ps_msi_requested}",
        "Write-Host '[2/9] OpenSSH Server prüfen...' -ForegroundColor Cyan",
        "$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "if (-not $sshd) {",
        "    if ($maviMsiRequested) {",
        "        if ([string]::IsNullOrWhiteSpace($msiPath) -or -not (Test-Path -LiteralPath $msiPath)) {",
        "            throw \"OpenSSH-MSI ist nicht erreichbar: $msiPath. Eine MSI wurde explizit angefordert; Windows-Capability/FoD wird nicht verwendet.\"",
        "        }",
        "        Write-Host '[3/9] OpenSSH-MSI prüfen und installieren...' -ForegroundColor Cyan",
        "        Assert-MaviMsiTrust -Path $msiPath -ExpectedSha256 $expectedMsiSha256 -ExpectedSigner $expectedMsiSigner",
        "        $quotedMsi = '\"' + $msiPath + '\"'",
        "        $msi = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\\msiexec.exe') -ArgumentList \"/i $quotedMsi /qn /norestart\" -Wait -PassThru",
        "        $msiExitCode = $msi.ExitCode",
        "        if ($msi.ExitCode -notin @(0, 1641, 3010)) {",
        "            throw \"OpenSSH-MSI meldete Exit-Code $($msi.ExitCode). Windows-Capability/FoD wird nicht verwendet.\"",
        "        }",
        "        else { Write-Host \"    MSI erfolgreich, Exit-Code $($msi.ExitCode).\" -ForegroundColor Green }",
        "        $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "        if (-not $sshd -and $msiExitCode -in @(1641, 3010)) {",
        "            throw \"OpenSSH-MSI meldete Exit-Code $msiExitCode und benötigt einen Neustart, bevor sshd verfügbar ist. Nach dem Neustart den Starter erneut ausführen.\"",
        "        }",
        "        if (-not $sshd) {",
        "            Write-Host '    MSI meldet Erfolg, aber sshd fehlt. MSI-Reparatur wird ausgeführt...' -ForegroundColor Yellow",
        "            $repair = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\\msiexec.exe') -ArgumentList \"/fa $quotedMsi /qn /norestart\" -Wait -PassThru",
        "            if ($repair.ExitCode -notin @(0, 1641, 3010)) {",
        "                throw \"OpenSSH-MSI-Reparatur meldete Exit-Code $($repair.ExitCode). Windows-Capability/FoD wird nicht verwendet.\"",
        "            }",
        "            if ($repair.ExitCode -in @(1641, 3010)) {",
        "                throw \"OpenSSH-MSI-Reparatur meldete Exit-Code $($repair.ExitCode) und benötigt einen Neustart, bevor sshd verfügbar ist. Nach dem Neustart den Starter erneut ausführen.\"",
        "            }",
        "            $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "        }",
        "    }",
        "    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "    if (-not $sshd) {",
        "        if ($maviMsiRequested) {",
        "            throw 'Die OpenSSH-MSI wurde ausgeführt, aber der Dienst sshd ist danach nicht vorhanden. Windows-Capability/FoD wird nicht verwendet.'",
        "        }",
        "        Write-Host '[3/9] OpenSSH als Windows Capability installieren (Fallback)...' -ForegroundColor Yellow",
        "        Write-Host '    Dieser Schritt kann über Windows Update/WSUS mehrere Minuten dauern.' -ForegroundColor Yellow",
        "        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1",
        "        if (-not $cap) { throw 'OpenSSH.Server Windows-Capability wurde nicht gefunden.' }",
        "        if ($cap.State -ne 'Installed') { $cap | Add-WindowsCapability -Online | Out-Host }",
        "    }",
        "}",
        "$sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue",
        "if (-not $sshd) { throw 'sshd wurde nach der OpenSSH-Installation nicht gefunden.' }",
        "",
        "Write-Host '[4/9] Fremde TCP/22-Freigaben fail-closed prüfen...' -ForegroundColor Cyan",
        "$maviFirewallName = 'Mavi-OpenSSH-' + $maviInstanceId + '-Ansible-In-TCP'",
        "function Test-MaviPort22Coverage {",
        "    param([object]$LocalPort)",
        "    foreach ($token in @(([string]$LocalPort) -split ',')) {",
        "        $value = $token.Trim()",
        "        if ($value -in @('Any', '*', '22')) { return $true }",
        "        if ($value -match '^(\\d+)\\s*-\\s*(\\d+)$') {",
        "            if ([int]$Matches[1] -le 22 -and [int]$Matches[2] -ge 22) { return $true }",
        "        }",
        "    }",
        "    return $false",
        "}",
        "$unsafeRules = New-Object 'System.Collections.Generic.List[string]'",
        "$allowRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue)",
        "foreach ($rule in $allowRules) {",
        "    if ([string]$rule.Name -ceq $maviFirewallName) { continue }",
        "    $isPort22 = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object {",
        "        $protocol = [string]$_.Protocol",
        "        $tcpOrAny = $protocol -in @('6', '256') -or $protocol -ieq 'TCP' -or $protocol -ieq 'Any'",
        "        $tcpOrAny -and (Test-MaviPort22Coverage $_.LocalPort)",
        "    }).Count -gt 0",
        "    if (-not $isPort22) { continue }",
        "",
        "    # Eine breite Port-/Adressregel ist nur dann ein SSH-Bypass, wenn sie",
        "    # auch auf sshd anwendbar ist. Programmspezifische Regeln fremder",
        "    # Anwendungen (z. B. FortiClient.exe) dürfen nicht als sshd-Freigabe",
        "    # fehlklassifiziert oder verändert werden.",
        "    $appFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)",
        "    $programs = @($appFilters | ForEach-Object { [string]$_.Program } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $packages = @($appFilters | ForEach-Object { [string]$_.Package } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $packageBound = @($packages | Where-Object { $_ -notin @('Any', '*') }).Count -gt 0",
        "    $programCanApplyToSshd = $programs.Count -eq 0 -or @($programs | Where-Object {",
        "        $_ -in @('Any', '*') -or [IO.Path]::GetFileName($_) -ieq 'sshd.exe'",
        "    }).Count -gt 0",
        "    if ($packageBound -or -not $programCanApplyToSshd) { continue }",
        "",
        "    $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue)",
        "    $services = @($serviceFilters | ForEach-Object { [string]$_.Service } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })",
        "    $serviceCanApplyToSshd = $services.Count -eq 0 -or @($services | Where-Object {",
        "        $_ -in @('Any', '*') -or $_ -ieq 'sshd'",
        "    }).Count -gt 0",
        "    if (-not $serviceCanApplyToSshd) { continue }",
        "",
        "    $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)",
        "    $onlyController = $addresses.Count -eq 1 -and @($addresses[0].RemoteAddress).Count -eq 1 -and [string]$addresses[0].RemoteAddress -ceq $ansibleServerIp",
        "    if (-not $onlyController) {",
        "        $programSummary = if ($programs.Count -gt 0) { $programs -join '|' } else { 'Any' }",
        "        $serviceSummary = if ($services.Count -gt 0) { $services -join '|' } else { 'Any' }",
        "        $unsafeRules.Add(([string]$rule.DisplayName + ' [' + [string]$rule.Name + '] Program=' + $programSummary + ' Service=' + $serviceSummary))",
        "    }",
        "}",
        "if ($unsafeRules.Count -gt 0) {",
        "    throw ('SICHERHEITSABBRUCH: Bereits aktive fremde TCP/22-Freigaben würden die Controller-Beschränkung umgehen. Mavi verändert sie niemals automatisch. Administrativ prüfen/deaktivieren und erneut starten: ' + ($unsafeRules -join ', '))",
        "}",
        "$existingOwnedRule = Get-NetFirewallRule -Name $maviFirewallName -ErrorAction SilentlyContinue",
        "if ($existingOwnedRule -and [string]$existingOwnedRule.Group -cne 'Mavi Provisioner') {",
        "    throw ('SICHERHEITSABBRUCH: Firewall-Regelname wird von einer fremden Regel belegt: ' + $maviFirewallName)",
        "}",
        "",
        "Write-Host '[5/9] sshd_config über entfernbaren Instanz-Include härten...' -ForegroundColor Cyan",
        "New-Item -ItemType Directory -Path $env:ProgramData\\ssh -Force | Out-Null",
        "$sshdConfig = Join-Path $env:ProgramData 'ssh\\sshd_config'",
        "$sshdConfigPreexisted = Test-Path -LiteralPath $sshdConfig -PathType Leaf",
        "if (-not $sshdConfigPreexisted) { New-Item -ItemType File -Path $sshdConfig -Force | Out-Null }",
        "$maviStateRoot = Join-Path $env:ProgramData ('MaviProvisioner\\bootstrap\\' + $maviInstanceId)",
        "New-Item -ItemType Directory -Path $maviStateRoot -Force | Out-Null",
        "$maviStatePath = Join-Path $maviStateRoot 'state.json'",
        "$maviPreviousState = $null",
        "if (Test-Path -LiteralPath $maviStatePath) { try { $maviPreviousState = Get-Content -LiteralPath $maviStatePath -Raw | ConvertFrom-Json -ErrorAction Stop } catch { throw 'SICHERHEITSABBRUCH: Vorhandener Mavi-Bootstrap-Status ist beschädigt.' } }",
        "$configBackup = Join-Path $maviStateRoot 'sshd_config.pre-mavi.bak'",
        "if (-not (Test-Path -LiteralPath $configBackup)) { Copy-Item -LiteralPath $sshdConfig -Destination $configBackup -Force }",
        "$runConfigBackup = Join-Path $maviStateRoot 'sshd_config.rollback.tmp'",
        "Copy-Item -LiteralPath $sshdConfig -Destination $runConfigBackup -Force",
        "$managedConfigDir = Join-Path $env:ProgramData 'ssh\\sshd_config.d'",
        "New-Item -ItemType Directory -Path $managedConfigDir -Force | Out-Null",
        "$managedConfig = Join-Path $managedConfigDir ('mavi-' + $maviInstanceId + '.conf')",
        "$managedConfigBackup = Join-Path $maviStateRoot 'managed_config.rollback.tmp'",
        "$managedConfigPreexisted = Test-Path -LiteralPath $managedConfig -PathType Leaf",
        "if ($managedConfigPreexisted) { Copy-Item -LiteralPath $managedConfig -Destination $managedConfigBackup -Force }",
        "$beginMarker = '# BEGIN MAVI PROVISIONER ' + $maviInstanceId",
        "$endMarker = '# END MAVI PROVISIONER ' + $maviInstanceId",
        "$configLines = @(Get-Content -LiteralPath $sshdConfig -ErrorAction SilentlyContinue)",
        "$keptConfigLines = New-Object 'System.Collections.Generic.List[string]'",
        "$insideManagedBlock = $false",
        "foreach ($lineObj in $configLines) {",
        "    $line = [string]$lineObj",
        "    if ($line -ceq $beginMarker) { if ($insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Verschachtelter Mavi-sshd-Marker.' }; $insideManagedBlock = $true; continue }",
        "    if ($line -ceq $endMarker) { if (-not $insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Verwaister Mavi-sshd-Endmarker.' }; $insideManagedBlock = $false; continue }",
        "    if (-not $insideManagedBlock) { $keptConfigLines.Add($line) }",
        "}",
        "if ($insideManagedBlock) { throw 'SICHERHEITSABBRUCH: Unvollständiger Mavi-sshd-Marker.' }",
        "$managedDirectives = @('# Mavi Provisioner instance ' + $maviInstanceId, 'PubkeyAuthentication yes', 'PasswordAuthentication no', 'KbdInteractiveAuthentication no')",
        "$configStage = $sshdConfig + '.mavi-stage'",
        "$managedStage = $managedConfig + '.mavi-stage'",
        "$includeLine = 'Include __PROGRAMDATA__/ssh/sshd_config.d/mavi-' + $maviInstanceId + '.conf'",
        "try {",
        "    Set-Content -LiteralPath $managedStage -Value $managedDirectives -Encoding ascii",
        "    Move-Item -LiteralPath $managedStage -Destination $managedConfig -Force",
        "    Set-Content -LiteralPath $configStage -Value (@($beginMarker, $includeLine, $endMarker) + @($keptConfigLines)) -Encoding ascii",
        "    Move-Item -LiteralPath $configStage -Destination $sshdConfig -Force",
        "$sshdExeCandidates = @(",
        "    (Join-Path $env:WINDIR 'System32\\OpenSSH\\sshd.exe'),",
        "    (Join-Path $env:ProgramFiles 'OpenSSH\\sshd.exe'),",
        "    (Join-Path $env:ProgramFiles 'OpenSSH-Win64\\sshd.exe')",
        ")",
        "$sshdExe = $sshdExeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1",
        "    if (-not $sshdExe) { throw 'SICHERHEITSABBRUCH: sshd.exe zur Konfigurationsprüfung nicht gefunden.' }",
        "    & $sshdExe -t -f $sshdConfig",
        "    if ($LASTEXITCODE -ne 0) { throw 'SICHERHEITSABBRUCH: sshd_config oder Include ist ungültig.' }",
        "}",
        "catch {",
        "    Copy-Item -LiteralPath $runConfigBackup -Destination $sshdConfig -Force",
        "    if ($managedConfigPreexisted) { Copy-Item -LiteralPath $managedConfigBackup -Destination $managedConfig -Force } else { Remove-Item -LiteralPath $managedConfig -Force -ErrorAction SilentlyContinue }",
        "    throw",
        "}",
        "finally { Remove-Item -LiteralPath $runConfigBackup,$managedConfigBackup,$configStage,$managedStage -Force -ErrorAction SilentlyContinue }",
        "",
        "Write-Host '[6/9] Mavi Public Key einrichten...' -ForegroundColor Cyan",
        "$keyFile = Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys'",
        f"$maviKey = '{ps_key}'",
        "$existing = @()",
        "if (Test-Path -LiteralPath $keyFile) { $existing = @(Get-Content -LiteralPath $keyFile -ErrorAction SilentlyContinue) }",
        "$keyPreexisted = @($existing | Where-Object { $_.Trim() -eq $maviKey }).Count -gt 0",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.KeyPreexisted) { $keyPreexisted = [bool]$maviPreviousState.KeyPreexisted }",
        "if (-not $keyPreexisted) { Add-Content -LiteralPath $keyFile -Value $maviKey -Encoding ascii }",
        "icacls.exe $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null",
        "",
        "Write-Host '[7/9] PowerShell als SSH-Shell setzen...' -ForegroundColor Cyan",
        "$originalDefaultShellExists = $false",
        "$originalDefaultShell = ''",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.OriginalDefaultShellExists) {",
        "    $originalDefaultShellExists = [bool]$maviPreviousState.OriginalDefaultShellExists",
        "    $originalDefaultShell = [string]$maviPreviousState.OriginalDefaultShell",
        "} else {",
        "    $existingShellProperty = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -ErrorAction SilentlyContinue",
        "    if ($null -ne $existingShellProperty) { $originalDefaultShellExists = $true; $originalDefaultShell = [string]$existingShellProperty.DefaultShell }",
        "}",
        "New-Item -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Force | Out-Null",
        "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\OpenSSH' -Name DefaultShell -Value 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -PropertyType String -Force | Out-Null",
        "",
        "Write-Host '[8/9] Instanzeigene Windows-Firewallregel setzen...' -ForegroundColor Cyan",
        "Get-NetFirewallRule -Name $maviFirewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop",
        "New-NetFirewallRule -Name $maviFirewallName -DisplayName ('Mavi OpenSSH nur Ansible-Server (' + $maviInstanceId + ')') -Group 'Mavi Provisioner' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -RemoteAddress $ansibleServerIp -Profile Any | Out-Null",
        "$maviRule = Get-NetFirewallRule -Name $maviFirewallName -ErrorAction Stop",
        "$maviAddress = @($maviRule | Get-NetFirewallAddressFilter -ErrorAction Stop)",
        "if ($maviAddress.Count -ne 1 -or [string]$maviAddress[0].RemoteAddress -cne $ansibleServerIp) {",
        "    throw 'SICHERHEITSABBRUCH: Die Firewall-RemoteAddress konnte nicht exakt verifiziert werden.'",
        "}",
        "Write-Host \"    TCP/22 erlaubt ausschließlich von $ansibleServerIp.\" -ForegroundColor Green",
        "",
        "Write-Host '[9/9] sshd aktivieren beziehungsweise neu starten...' -ForegroundColor Cyan",
        "Set-Service -Name sshd -StartupType Automatic",
        "$sshd = Get-Service -Name sshd",
        "if ($sshd.Status -eq 'Running') { Restart-Service -Name sshd -Force } else { Start-Service -Name sshd }",
        "",
        "$trackedThumbprints = New-Object 'System.Collections.Generic.List[string]'",
        "if ($maviPreviousState -and $maviPreviousState.CaThumbprintsAdded) { foreach ($thumb in @($maviPreviousState.CaThumbprintsAdded)) { if ($thumb -match '^[0-9A-Fa-f]{40}$' -and -not $trackedThumbprints.Contains(([string]$thumb).ToUpperInvariant())) { $trackedThumbprints.Add(([string]$thumb).ToUpperInvariant()) } } }",
        "if ($env:MAVI_CA_ADDED_THIS_RUN -ceq '1' -and $maviCaThumbprint -match '^[0-9A-Fa-f]{40}$') { $addedThumbprint = $maviCaThumbprint.ToUpperInvariant(); if (-not $trackedThumbprints.Contains($addedThumbprint)) { $trackedThumbprints.Add($addedThumbprint) } }",
        "if ($maviPreviousState -and $null -ne $maviPreviousState.SshdConfigPreexisted) { $sshdConfigPreexisted = [bool]$maviPreviousState.SshdConfigPreexisted }",
        "$bootstrapState = [ordered]@{ InstanceId=$maviInstanceId; CaThumbprintsAdded=@($trackedThumbprints); FirewallRule=$maviFirewallName; ManagedConfig=$managedConfig; BeginMarker=$beginMarker; EndMarker=$endMarker; KeyFile=$keyFile; MaviKey=$maviKey; KeyPreexisted=$keyPreexisted; SshdConfig=$sshdConfig; SshdConfigPreexisted=$sshdConfigPreexisted; OriginalDefaultShellExists=$originalDefaultShellExists; OriginalDefaultShell=$originalDefaultShell; UpdatedUtc=[DateTime]::UtcNow.ToString('o') }",
        "$bootstrapState | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $maviStatePath -Encoding utf8",
        "& icacls.exe $maviStateRoot /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' /grant '*S-1-5-18:(OI)(CI)F' | Out-Null",
        "if ($LASTEXITCODE -ne 0) { throw 'Mavi-Bootstrap-Status konnte nicht sicher per ACL geschützt werden.' }",
        "",
        "Write-Host 'SSH Host-Key Fingerprint...' -ForegroundColor Cyan",
        "Get-Service sshd | Format-Table Name,Status,StartType",
        "$hostKey = Join-Path $env:ProgramData 'ssh\\ssh_host_ed25519_key.pub'",
        "if (Test-Path -LiteralPath $hostKey) {",
        "    $sshKeygenCandidates = @(",
        "        (Join-Path $env:WINDIR 'System32\\OpenSSH\\ssh-keygen.exe'),",
        "        (Join-Path $env:ProgramFiles 'OpenSSH\\ssh-keygen.exe'),",
        "        (Join-Path $env:ProgramFiles 'OpenSSH-Win64\\ssh-keygen.exe')",
        "    )",
        "    $sshKeygen = $sshKeygenCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1",
        "    if (-not $sshKeygen) {",
        "        $cmd = Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue",
        "        if ($cmd) { $sshKeygen = $cmd.Source }",
        "    }",
        "    if ($sshKeygen) { & $sshKeygen -lf $hostKey }",
        "    else { Write-Warning 'ssh-keygen.exe nicht gefunden; Host-Key wurde trotzdem erzeugt.' }",
        "}",
        "Write-Host ''",
        "Write-Host 'Mavi OpenSSH fertig: Public-Key aktiv, Passwortlogin aus, Firewall auf Ansible-IP begrenzt.' -ForegroundColor Green",
        "Write-Host 'sshd bleibt wie angefordert installiert und aktiv.' -ForegroundColor Green",
        "Write-Host 'Du kannst dieses Fenster jetzt schließen und in Mavi den PC auf OpenSSH umstellen.' -ForegroundColor Green",
        "Write-Host ''",
        "Read-Host 'ENTER zum Schließen' | Out-Null",
    ]
    return "\r\n".join(lines) + "\r\n"


def _software_local_and_windows_path(project: Path, raw: str) -> tuple[Path | None, str, str]:
    """Mavi-Softwarepfad in Planner-, Laufwerks- und UNC-Pfad übersetzen."""
    from .environment import get_config

    value = str(raw or "").strip().strip('"').strip("'")
    config = get_config(project)
    source = config.get("software_source", {}) or {}
    drive = str(source.get("drive", "") or "").strip().replace("/", "\\")
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    local_root_raw = str(source.get("local_root", "") or "").strip()
    local_root = Path(local_root_raw).expanduser() if local_root_raw else None
    rel_text = ""
    local: Path | None = None

    value_win = value.replace("/", "\\")
    if value and drive and value_win.lower().startswith(drive.lower()):
        rel_text = value_win[len(drive):].lstrip("\\/")
        if local_root is not None:
            local = local_root.joinpath(*[x for x in re.split(r"[\\/]+", rel_text) if x])
    elif value and unc_root and value_win.lower().startswith(unc_root.replace("/", "\\").lower()):
        rel_text = value_win[len(unc_root):].lstrip("\\/")
        if local_root is not None:
            local = local_root.joinpath(*[x for x in re.split(r"[\\/]+", rel_text) if x])
    elif value and value.startswith("/"):
        candidate = Path(value).expanduser()
        local = candidate
        if local_root is not None:
            try:
                rel_text = str(candidate.relative_to(local_root)).replace("/", "\\")
            except ValueError:
                rel_text = ""

    if rel_text:
        drive_path = (drive.rstrip("\\") + "\\" + rel_text) if drive else ""
        unc_path = (unc_root + "\\" + rel_text) if unc_root else ""
    else:
        drive_path = value if re.match(r"^[A-Za-z]:[\\/]", value) else ""
        unc_path = value if value.startswith("\\\\") else ""
    return local, drive_path, unc_path
