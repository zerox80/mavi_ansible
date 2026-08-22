# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""OpenSSH-Bootstrap und Remotezugriffs-Workflows."""

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

def _public_key_summary(pub_path: Path) -> tuple[str, str]:
    if not pub_path.exists():
        return "", ""
    public_key = pub_path.read_text(encoding="utf-8", errors="replace").strip()
    fingerprint = ""
    if public_key and shutil.which("ssh-keygen"):
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", str(pub_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                fingerprint = result.stdout.strip()
        except OSError:
            pass
    return public_key, fingerprint


def _known_hosts_lookup_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _known_host_present(known_hosts: Path, host: str, port: int) -> bool:
    if not known_hosts.exists() or not shutil.which("ssh-keygen"):
        return False
    lookup = _known_hosts_lookup_name(host, port)
    try:
        result = subprocess.run(
            ["ssh-keygen", "-F", lookup, "-f", str(known_hosts)],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return result.returncode == 0 and bool((result.stdout or "").strip())


def _ssh_host_key_port(
    windows: dict[str, Any],
    host_data: dict[str, Any],
    configured_port: Any,
) -> int:
    """SSH-Port unabhängig vom derzeit aktiven Ansible-Transport bestimmen."""
    from .remote import _connection_label, _effective_host_var

    raw_port = host_data.get("mavi_ssh_port")
    if raw_port is None and _connection_label(windows, host_data) == "SSH":
        raw_port = _effective_host_var(windows, host_data, "ansible_port", None)
    if raw_port is None:
        raw_port = configured_port
    try:
        port = int(raw_port or 22)
    except (TypeError, ValueError):
        port = 22
    return port if 1 <= port <= 65535 else 22


def _fingerprint_known_host_line(line: str) -> str:
    if not shutil.which("ssh-keygen"):
        return ""
    fd, tmp_name = tempfile.mkstemp(prefix="mavi-hostkey-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(line.rstrip() + "\n")
        result = subprocess.run(
            ["ssh-keygen", "-lf", tmp_name],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return (result.stdout or "").strip()
        return ""
    finally:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def ensure_ssh_host_key(
    project: Path,
    host: str,
    *,
    port: int = 22,
    yes: bool = False,
) -> Path:
    """SSH-Host-Key einmalig scannen, anzeigen und in Mavi-known_hosts speichern."""
    from .environment import die
    from .remote import get_ssh_settings

    settings = get_ssh_settings(project)
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(known_hosts.parent, 0o700)
    except OSError:
        pass

    if _known_host_present(known_hosts, host, port):
        return known_hosts

    if not shutil.which("ssh-keyscan"):
        die(
            "ssh-keyscan fehlt auf dem Ansible-Server. "
            "Auf Debian/Ubuntu: sudo apt install -y openssh-client"
        )
    if not shutil.which("ssh-keygen"):
        die(
            "ssh-keygen fehlt auf dem Ansible-Server. "
            "Auf Debian/Ubuntu: sudo apt install -y openssh-client"
        )

    cmd = ["ssh-keyscan", "-T", "7", "-p", str(port), "-t", "ed25519,rsa", host]
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=12,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"SSH-Host-Key von {host}:{port} konnte nicht gelesen werden: {exc}")

    lines = [
        x.strip() for x in (result.stdout or "").splitlines()
        if x.strip() and not x.lstrip().startswith("#")
    ]
    if not lines:
        detail = (result.stderr or "").strip()
        die(
            f"Kein SSH-Host-Key von {host}:{port} erhalten. "
            "Läuft sshd und lässt ESET TCP/22 vom Ansible-Server durch?"
            + (f"\nssh-keyscan: {detail}" if detail else "")
        )

    # Ed25519 bevorzugen, RSA als Fallback. Einen Key bestätigen reicht für den
    # strikt konfigurierten Erstkontakt; weitere Keytypen müssen nicht blind
    # übernommen werden.
    chosen = next((x for x in lines if " ssh-ed25519 " in x), lines[0])
    fingerprint = _fingerprint_known_host_line(chosen)

    print("\nMavi SSH HOST-KEY")
    print("================")
    print(f"Ziel:        {host}:{port}")
    if fingerprint:
        print(f"Fingerprint: {fingerprint}")
    print(f"Datei:       {known_hosts}")
    print(
        "\nVergleiche den SHA256-Fingerprint idealerweise mit dem Fingerprint, "
        "den die Mavi-Windows-Einrichtungsanleitung direkt auf dem Laptop ausgibt."
    )

    if not yes:
        answer = input("Diesen SSH-Host-Key vertrauen und speichern? [j/N] ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            die("SSH-Host-Key wurde nicht übernommen. Host bleibt unverändert.")

    with known_hosts.open("a", encoding="utf-8") as f:
        f.write(chosen.rstrip() + "\n")
    try:
        os.chmod(known_hosts, 0o600)
    except OSError:
        pass
    print("✓ SSH-Host-Key gespeichert.")
    return known_hosts


def cmd_ssh_keygen(args: argparse.Namespace) -> None:
    from .environment import (
        die,
        ensure_initialized,
    )
    from .remote import (
        _ssh_environment_marker,
        get_ssh_settings,
    )

    ensure_initialized(args.project, quiet=True)
    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")

    if key_path.exists() or pub_path.exists():
        print(f"SSH-Key existiert bereits: {key_path}")
        public_key, fingerprint = _public_key_summary(pub_path)
        if fingerprint:
            print(f"Fingerprint: {fingerprint}")
        if public_key:
            print(f"Public Key:  {public_key}")
        print("\nBestehende Keys werden von Mavi absichtlich NICHT überschrieben.")
        return

    if not shutil.which("ssh-keygen"):
        die("ssh-keygen ist auf dem Ansible-Server nicht installiert. Auf Debian/Ubuntu: sudo apt install -y openssh-client")

    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(key_path.parent, 0o700)
    except OSError:
        pass

    print("\nMavi SSH-KEY")
    print("===========")
    print(f"Ziel: {key_path}")
    print(
        "Es wird ein eigener Ed25519-Automationsschlüssel ohne Passphrase erzeugt.\n"
        "Der private Key bleibt ausschließlich auf dem Ansible-Server und erhält Modus 600."
    )

    if not getattr(args, "yes", False):
        answer = input("Key erzeugen? [j/N] ").strip().lower()
        if answer not in {"j", "ja", "y", "yes"}:
            print("Abgebrochen.")
            return

    cmd = [
        "ssh-keygen",
        "-t", "ed25519",
        "-f", str(key_path),
        "-N", "",
        "-C", _ssh_environment_marker(args.project),
    ]
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        die(f"ssh-keygen wurde mit Code {result.returncode} beendet.")

    try:
        os.chmod(key_path, 0o600)
        os.chmod(pub_path, 0o644)
    except OSError:
        pass

    public_key, fingerprint = _public_key_summary(pub_path)
    print(f"\n✓ SSH-Key angelegt: {key_path}")
    if fingerprint:
        print(f"  Fingerprint: {fingerprint}")
    if public_key:
        print(f"  Public Key:  {public_key}")
    print("\nNächster Schritt: mavi-provisioner ssh auto <HOST>")


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


def _bootstrap_instance_id(project: Path, config: dict[str, Any] | None = None) -> str:
    """Deterministische, controllerlokal eindeutige Kennung für Bootstrap-Ressourcen."""
    from .environment import get_config

    resolved_project = project.expanduser().resolve(strict=False)
    current_config = config if isinstance(config, dict) else get_config(project)
    profile = current_config.get("profile", {}) if isinstance(current_config, dict) else {}
    profile_name = str(profile.get("name", "") or "environment") if isinstance(profile, dict) else "environment"
    readable = re.sub(r"[^a-z0-9]+", "-", profile_name.casefold()).strip("-")[:32] or "environment"
    path_digest = hashlib.sha256(str(resolved_project).encode("utf-8")).hexdigest()[:12]
    return f"{readable}-{path_digest}"


def _openssh_artifact_instance_id(
    project: Path,
    host_data: dict[str, Any] | None = None,
) -> str:
    """Die exakte Bootstrap-Instanz für hostseitige OpenSSH-Artefakte bestimmen."""
    state = host_data.get("mavi_bootstrap") if isinstance(host_data, dict) else None
    if isinstance(state, dict):
        instance_id = str(state.get("instance_id", "") or "").strip()
        try:
            version = int(state.get("version", 1))
        except (TypeError, ValueError):
            version = 1
        if instance_id:
            if (
                version < 2
                or state.get("remote_verified") is not True
                or re.fullmatch(r"[a-z0-9-]{1,64}", instance_id) is None
            ):
                raise ValueError(
                    "Die gespeicherte Bootstrap-Instanz ist nicht als gültiger "
                    "hostgebundener v2-Nachweis verifiziert."
                )
            return instance_id
        if version >= 2 or state.get("remote_verified") is True:
            raise ValueError(
                "Der gespeicherte Bootstrap-v2-Nachweis enthält keine "
                "hostgebundene Instanzkennung."
            )
    return _bootstrap_instance_id(project)


def _openssh_firewall_rule_name(
    project: Path,
    *,
    instance_id: str = "",
) -> str:
    resolved_instance_id = str(instance_id or _bootstrap_instance_id(project)).strip()
    if re.fullmatch(r"[a-z0-9-]{1,64}", resolved_instance_id) is None:
        raise ValueError("Die Bootstrap-Instanzkennung für die OpenSSH-Firewallregel ist ungültig.")
    return f"Mavi-OpenSSH-{resolved_instance_id}-Ansible-In-TCP"


def _openssh_config_backup_relative_path(
    project: Path,
    *,
    instance_id: str = "",
) -> str:
    resolved_instance_id = str(instance_id or _bootstrap_instance_id(project)).strip()
    if re.fullmatch(r"[a-z0-9-]{1,64}", resolved_instance_id) is None:
        raise ValueError(
            "Die Bootstrap-Instanzkennung für die OpenSSH-Konfigurationssicherung ist ungültig."
        )
    return (
        "MaviProvisioner\\bootstrap\\"
        f"{resolved_instance_id}\\sshd_config.pre-mavi.bak"
    )


def _bootstrap_settings(project: Path) -> dict[str, Any]:
    """Zentrale HTTPS-Bootstrap-Konfiguration validieren und normalisieren."""
    from .environment import get_config

    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "").strip()
    local_dir_raw = str(config.get("bootstrap_local_dir", "") or "").strip()
    ansible_server_ip = str(config.get("ansible_server_ip", "") or "").strip()
    expected_signer = str(config.get("openssh_msi_expected_signer", "") or "").strip()
    allowed_cidrs_raw = config.get("bootstrap_allowed_cidrs", [])
    ca_validity_raw = config.get("bootstrap_ca_validity_days", 825)
    server_validity_raw = config.get("bootstrap_server_cert_validity_days", 90)
    instance_id = _bootstrap_instance_id(project, config)

    if not base_url:
        raise ValueError("bootstrap_base_url fehlt.")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("bootstrap_base_url muss mit https:// beginnen; HTTP ist unzulässig.")
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.") from exc
    if url_port is not None and not 1 <= url_port <= 65535:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.")
    effective_port = url_port if url_port is not None else 443
    if not parsed.hostname:
        raise ValueError("bootstrap_base_url enthält keinen gültigen Hostnamen bzw. keine IP.")
    url_host = str(parsed.hostname)
    try:
        parsed_url_ip = ipaddress.ip_address(url_host)
    except ValueError:
        try:
            url_host_ascii = url_host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.") from exc
        if (
            len(url_host_ascii) > 253
            or not re.fullmatch(
                r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?",
                url_host_ascii,
            )
        ):
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.")
        url_host = url_host_ascii.rstrip(".").lower()
        netloc_host = url_host
    else:
        url_host = str(parsed_url_ip)
        netloc_host = f"[{url_host}]" if parsed_url_ip.version == 6 else url_host
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("bootstrap_base_url darf keine Zugangsdaten enthalten.")
    if parsed.query or parsed.fragment:
        raise ValueError("bootstrap_base_url darf weder Query noch Fragment enthalten.")
    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        raise ValueError("bootstrap_base_url darf keine Steuerzeichen enthalten.")
    normalized_path = parsed.path or "/"
    if not normalized_path.endswith("/"):
        normalized_path += "/"
    if (
        normalized_path == "/"
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]*/", normalized_path)
        or "//" in normalized_path
        or "\\" in normalized_path
        or any(part in {".", ".."} for part in normalized_path.split("/"))
    ):
        raise ValueError(
            "bootstrap_base_url benötigt einen eigenen einfachen URL-Pfad, z. B. /mavi-bootstrap/."
        )
    normalized_netloc = netloc_host + (f":{url_port}" if url_port is not None else "")
    base_url = urllib.parse.urlunsplit((
        "https",
        normalized_netloc,
        normalized_path,
        "",
        "",
    ))

    if not local_dir_raw:
        raise ValueError("bootstrap_local_dir fehlt.")
    local_dir_candidate = Path(local_dir_raw).expanduser()
    if not local_dir_candidate.is_absolute():
        raise ValueError("bootstrap_local_dir muss ein absoluter lokaler Pfad sein.")
    local_dir = local_dir_candidate.resolve(strict=False)
    safe_webroot_parents = (Path("/var/www"), Path("/srv"), Path("/opt"), Path("/mnt"))
    in_safe_parent = False
    for parent in safe_webroot_parents:
        try:
            local_dir.relative_to(parent)
        except ValueError:
            continue
        if local_dir != parent:
            in_safe_parent = True
            break
    if not in_safe_parent:
        raise ValueError(
            "bootstrap_local_dir muss ein eigener Unterordner unter /var/www, /srv, /opt oder /mnt sein. "
            "Empfohlen: /var/www/mavi-bootstrap"
        )
    try:
        parsed_ip = ipaddress.ip_address(ansible_server_ip)
    except ValueError as exc:
        raise ValueError("ansible_server_ip fehlt oder ist keine einzelne gültige IP-Adresse.") from exc
    if parsed_ip.is_unspecified or parsed_ip.is_multicast or parsed_ip.is_loopback or parsed_ip.is_link_local:
        raise ValueError(
            "ansible_server_ip darf weder Wildcard-, Multicast-, Loopback- noch Link-Local-Adresse sein."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in expected_signer):
        raise ValueError("openssh_msi_expected_signer darf keine Steuerzeichen enthalten.")

    try:
        ca_validity_days = int(ca_validity_raw)
        server_cert_validity_days = int(server_validity_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "bootstrap_ca_validity_days und bootstrap_server_cert_validity_days müssen Ganzzahlen sein."
        ) from exc
    if not 90 <= ca_validity_days <= 1825:
        raise ValueError("bootstrap_ca_validity_days muss zwischen 90 und 1825 liegen.")
    if not 1 <= server_cert_validity_days <= 397:
        raise ValueError("bootstrap_server_cert_validity_days muss zwischen 1 und 397 liegen.")
    if server_cert_validity_days >= ca_validity_days:
        raise ValueError(
            "bootstrap_server_cert_validity_days muss kürzer als bootstrap_ca_validity_days sein."
        )
    if allowed_cidrs_raw in (None, "", []):
        allowed_values: list[str] = []
    elif isinstance(allowed_cidrs_raw, str):
        allowed_values = [x.strip() for x in allowed_cidrs_raw.split(",") if x.strip()]
    elif isinstance(allowed_cidrs_raw, list):
        allowed_values = [str(x or "").strip() for x in allowed_cidrs_raw if str(x or "").strip()]
    else:
        raise ValueError("bootstrap_allowed_cidrs muss eine YAML-Liste oder kommaseparierte Zeichenfolge sein.")

    if not allowed_values:
        private_candidates = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        matching_private = [network for network in private_candidates if parsed_ip in network]
        if matching_private:
            allowed_networks = matching_private
        elif parsed_ip.version == 4:
            allowed_networks = [ipaddress.ip_network("0.0.0.0/0")]
        else:
            allowed_networks = [ipaddress.ip_network("::/0")]
    else:
        try:
            allowed_networks = [ipaddress.ip_network(value, strict=False) for value in allowed_values]
        except ValueError as exc:
            raise ValueError(f"Ungültiges Netz in bootstrap_allowed_cidrs: {exc}") from exc

    # Normalisieren und doppelte Netze entfernen, damit Statusvergleiche stabil bleiben.
    allowed_networks = list(dict.fromkeys(allowed_networks))

    return {
        "base_url": base_url,
        "local_dir": local_dir,
        "ansible_server_ip": str(parsed_ip),
        "expected_signer": expected_signer,
        "url_host": url_host,
        "url_path": normalized_path,
        "port": int(effective_port),
        "allowed_cidrs": [str(network) for network in allowed_networks],
        "instance_id": instance_id,
        "ca_validity_days": ca_validity_days,
        "server_cert_validity_days": server_cert_validity_days,
    }


def _bootstrap_setup_instruction(project: Path, *, reason: str = "") -> str:
    """Einmalige Fehlerhilfe für die Vollautomatik, ohne unsicheren Fallback."""
    from .environment import (
        get_config,
        project_paths,
    )
    from .reports import redact_sensitive_text

    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "<HTTPS-BASIS-URL>").strip()
    local_dir = str(config.get("bootstrap_local_dir", "") or "/var/www/mavi-bootstrap").strip()
    safe_base_url = redact_sensitive_text(base_url)
    safe_local_dir = redact_sensitive_text(local_dir)
    safe_config_path = redact_sensitive_text(project_paths(project)["config"])
    lines = []
    if reason:
        lines.extend([f"Grund: {redact_sensitive_text(reason)}", ""])
    lines.extend([
        "Die Mavi-Vollautomatik konnte das Server-Setup nicht abschließen.",
        f"  Konfiguration: {safe_config_path}",
        f"  HTTPS-Ziel:    {safe_base_url}",
        f"  Webroot:       {safe_local_dir}",
        "Nach Korrektur des gemeldeten Grundes einfach erneut starten:",
        "  mavi-provisioner ssh server-setup",
        "Mavi installiert und konfiguriert nginx, CA, SAN-Zertifikat, Webroot und Firewall selbst.",
        "Es gibt ausdrücklich keinen HTTP-Fallback und keine deaktivierte Zertifikatsprüfung.",
    ])
    return "\n".join(lines)


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        shutil.copy2(source, tmp_path)
        if os.name != "nt":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bootstrap_pki_paths(project: Path) -> dict[str, Path]:
    """Alle privilegierten Bootstrap-Artefakte strikt pro Laufzeitprojekt isolieren."""
    instance_id = _bootstrap_instance_id(project)
    root = Path("/etc/mavi-bootstrap/instances") / instance_id
    pki = root / "pki"
    return {
        "root": root,
        "pki": pki,
        "ca_archive": root / "trusted-roots",
        "ca_key": pki / "mavi-bootstrap-root-ca.key.pem",
        "ca_cert": pki / "mavi-bootstrap-root-ca.cert.pem",
        "server_key": pki / "mavi-bootstrap-server.key.pem",
        "server_cert": pki / "mavi-bootstrap-server.cert.pem",
        "server_csr": pki / "mavi-bootstrap-server.csr.pem",
        "openssl_config": pki / "mavi-bootstrap-server.cnf",
        "state": root / "server-state.json",
        "nginx_config": Path(f"/etc/nginx/conf.d/mavi-bootstrap-{instance_id}.conf"),
        "system_ca": Path(
            f"/usr/local/share/ca-certificates/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
        "system_ca_anchor": Path(
            f"/etc/pki/ca-trust/source/anchors/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
    }


def _bootstrap_launcher_roots(project: Path) -> tuple[Path | None, str]:
    """Lokalen Ablagepfad und den dazugehörigen Windows-Pfad ableiten."""
    from .environment import get_config

    config = get_config(project)
    source = config.get("software_source", {}) or {}
    local_override = str(config.get("bootstrap_launcher_local_dir", "") or "").strip()
    windows_override = str(config.get("bootstrap_launcher_windows_dir", "") or "").strip()

    if local_override:
        local_root = Path(local_override).expanduser()
        if not local_root.is_absolute():
            raise ValueError("bootstrap_launcher_local_dir muss absolut sein.")
    else:
        software_local = str(source.get("local_root", "") or "").strip()
        local_root = Path(software_local).expanduser() / "Mavi-Bootstrap" if software_local else None
    if local_root is not None:
        if not local_root.is_absolute():
            raise ValueError("Die lokale Mavi-Starterablage muss ein absoluter Pfad sein.")
        local_root = local_root.resolve(strict=False)
        if local_root == Path("/") or len(local_root.parts) < 3:
            raise ValueError("Die lokale Mavi-Starterablage darf kein System- oder Mount-Wurzelpfad sein.")

    if windows_override:
        windows_root = windows_override.rstrip("\\/")
    else:
        drive = str(source.get("drive", "") or "").strip().replace("/", "\\").rstrip("\\")
        unc_root = str(source.get("unc_root", "") or "").strip().replace("/", "\\").rstrip("\\")
        windows_base = drive or unc_root
        windows_root = windows_base + "\\Mavi-Bootstrap" if windows_base else ""
    if windows_root:
        if any(ord(char) < 32 or ord(char) == 127 for char in windows_root):
            raise ValueError("Die Windows-Starterablage enthält unzulässige Steuerzeichen.")
        if not (re.match(r"^[A-Za-z]:\\", windows_root) or windows_root.startswith("\\\\")):
            raise ValueError("Die Windows-Starterablage muss ein absoluter Laufwerks- oder UNC-Pfad sein.")

    return local_root, windows_root


def _root_command(command: list[str], *, description: str, quiet: bool = False) -> None:
    from .environment import die
    from .reports import redact_sensitive_text

    print(f"  → {description}")
    try:
        if quiet:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            result = subprocess.run(command, check=False)
    except OSError as exc:
        die(f"{description} konnte nicht gestartet werden: {exc}")
    if result.returncode != 0:
        detail = ""
        if quiet and result.stderr:
            detail = "\n\n" + redact_sensitive_text(result.stderr.strip())
        die(f"{description} ist mit Exit-Code {result.returncode} fehlgeschlagen.{detail}")


def _install_bootstrap_server_packages() -> None:
    from .environment import die

    required = ("nginx", "openssl", "ssh-keygen")
    ca_updater_available = bool(
        shutil.which("update-ca-certificates") or shutil.which("update-ca-trust")
    )
    if all(shutil.which(binary) for binary in required) and ca_updater_available:
        return

    if shutil.which("apt-get"):
        _root_command(["apt-get", "update"], description="Paketlisten aktualisieren")
        _root_command(
            [
                "apt-get", "install", "-y", "--no-install-recommends",
                "nginx", "openssl", "ca-certificates", "openssh-client",
            ],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    package_manager = shutil.which("dnf") or shutil.which("yum")
    if package_manager:
        _root_command(
            [package_manager, "install", "-y", "nginx", "openssl", "ca-certificates", "openssh-clients"],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    die("Kein unterstützter Paketmanager gefunden. Unterstützt werden apt, dnf und yum.")


def _bootstrap_operator_ids(project: Path) -> tuple[int, int]:
    """Bei sudo den ursprünglichen Mavi-Benutzer statt root als Webroot-Eigentümer verwenden."""
    try:
        uid = int(os.environ.get("SUDO_UID", ""))
        gid = int(os.environ.get("SUDO_GID", ""))
        if uid >= 0 and gid >= 0:
            return uid, gid
    except (TypeError, ValueError):
        pass
    try:
        project_stat = project.stat()
        if project_stat.st_uid != 0:
            return int(project_stat.st_uid), int(project_stat.st_gid)
    except OSError:
        pass
    return int(os.getuid()), int(os.getgid())


def _nginx_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _openssl_server_config(host: str) -> str:
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError:
        san_line = f"DNS.1 = {host}"
    else:
        san_line = f"IP.1 = {parsed_host}"
    return (
        "[req]\n"
        "prompt = no\n"
        "distinguished_name = dn\n"
        "req_extensions = req_ext\n"
        "\n"
        "[dn]\n"
        f"CN = {host}\n"
        "O = Mavi\n"
        "OU = Automated Bootstrap\n"
        "\n"
        "[req_ext]\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[server_ext]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[alt_names]\n"
        f"{san_line}\n"
    )


def _certificate_valid_for(path: Path, seconds: int) -> bool:
    """Zertifikatslaufzeit konservativ mit OpenSSL prüfen, ohne Zertifikate zu verändern."""
    openssl = shutil.which("openssl")
    if not openssl or not path.is_file() or seconds < 0:
        return False
    try:
        result = subprocess.run(
            [openssl, "x509", "-checkend", str(int(seconds)), "-noout", "-in", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _certificate_sha1_thumbprint(path: Path) -> str:
    """Windows-Zertifikatthumbprint als exakten Bezeichner (nicht als Vertrauenshash) liefern."""
    pem = path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha1(der, usedforsecurity=False).hexdigest().upper()


def _archive_bootstrap_pki_for_rotation(paths: dict[str, Path]) -> Path:
    """Alte, instanzeigene PKI recoverable archivieren, statt sie zu überschreiben."""
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    ca_digest = _sha256_file(paths["ca_cert"])[:12] if paths["ca_cert"].is_file() else "no-ca"
    archive = paths["root"] / "rotations" / f"{timestamp}-{ca_digest}"
    archive.mkdir(parents=True, exist_ok=False)
    os.chmod(archive, 0o700)
    archived: list[str] = []
    for key in (
        "ca_key", "ca_cert", "server_key", "server_cert", "server_csr", "openssl_config", "state",
    ):
        source = paths[key]
        if source.exists():
            destination = archive / source.name
            shutil.move(str(source), str(destination))
            archived.append(destination.name)
    serial = paths["pki"] / "mavi-bootstrap-root-ca.cert.srl"
    if serial.exists():
        destination = archive / serial.name
        shutil.move(str(serial), str(destination))
        archived.append(destination.name)
    _atomic_write_bytes(
        archive / "rotation.json",
        (json.dumps({
            "archived_epoch": time.time(),
            "archived_files": archived,
            "old_ca_sha256": _sha256_file(archive / paths["ca_cert"].name)
            if (archive / paths["ca_cert"].name).is_file() else "",
            "old_ca_windows_thumbprint": _certificate_sha1_thumbprint(archive / paths["ca_cert"].name)
            if (archive / paths["ca_cert"].name).is_file() else "",
        }, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o600,
    )
    return archive


def _create_or_reuse_bootstrap_ca(
    settings: dict[str, Any],
    paths: dict[str, Path],
    *,
    rotate: bool = False,
) -> tuple[bool, Path | None]:
    """Instanz-CA erzeugen; Rotation nur explizit und mit recoverable Archiv."""
    from .environment import die

    ca_key = paths["ca_key"]
    ca_cert = paths["ca_cert"]
    if ca_cert.exists() and not ca_key.exists():
        die(
            "Das Mavi-CA-Zertifikat existiert, aber sein privater Schlüssel fehlt. "
            "Mavi rotiert die Vertrauenswurzel absichtlich nicht still. Backup wiederherstellen."
        )
    rotation_archive: Path | None = None
    if rotate and ca_cert.exists():
        # Die alte Root vor dem recoverable Voll-PKI-Archiv zusätzlich in den
        # dauerhaften DER-Index übernehmen. Andernfalls wäre bei der ersten
        # Rotation nach einem Upgrade nur die neue Root exakt löschbar.
        _archive_bootstrap_root_ca(paths)
    if rotate and (ca_cert.exists() or ca_key.exists()):
        rotation_archive = _archive_bootstrap_pki_for_rotation(paths)
    elif ca_cert.exists():
        required_seconds = (int(settings["server_cert_validity_days"]) + 30) * 86400
        if not _certificate_valid_for(ca_cert, required_seconds):
            die(
                "Die instanzeigene Mavi-CA läuft zu früh ab oder ist nicht gültig genug für ein neues "
                "Serverzertifikat. Bewusst rotieren mit: "
                "mavi-provisioner ssh server-setup --rotate-ca --yes. "
                "Danach muss die alte CA mit ihrer archivierten Thumbprint-Liste von Ziel-PCs entfernt werden."
            )
    created = not ca_cert.exists()
    if not ca_key.exists():
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_key),
            ],
            description="private Mavi-CA erzeugen",
            quiet=True,
        )
        os.chmod(ca_key, 0o600)
    if not ca_cert.exists():
        _root_command(
            [
                "openssl", "req", "-x509", "-new", "-sha256",
                "-key", str(ca_key), "-out", str(ca_cert),
                "-days", str(settings["ca_validity_days"]),
                "-subj",
                f"/CN=Mavi Bootstrap Root CA {settings['instance_id']}/O=Mavi/OU=Automated Bootstrap",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
            ],
            description="Mavi-CA-Zertifikat erzeugen",
            quiet=True,
        )
        os.chmod(ca_cert, 0o644)
    return created, rotation_archive


def _archive_bootstrap_root_ca(paths: dict[str, Path]) -> str:
    """Aktuelle Bootstrap-CA in einem root-kontrollierten DER-Archiv binden."""
    from .environment import die
    from .remote import (
        _certificate_der_from_file,
        _certificate_thumbprint_from_der,
    )

    try:
        certificate_der = _certificate_der_from_file(paths["ca_cert"])
        thumbprint = _certificate_thumbprint_from_der(certificate_der)
        archive = paths["ca_archive"]
        archive.mkdir(parents=True, exist_ok=True)
        if archive.is_symlink() or not archive.is_dir():
            raise ValueError("Das Bootstrap-CA-Archiv ist kein regulärer Ordner.")
        if os.name != "nt":
            os.chmod(archive, 0o755)
        destination = archive / f"{thumbprint}.cer"
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ValueError("Der archivierte Bootstrap-CA-Pfad ist keine reguläre Datei.")
            archived_der = _certificate_der_from_file(destination)
            if not secrets.compare_digest(archived_der, certificate_der):
                raise ValueError(
                    "Das Bootstrap-CA-Archiv enthält unter demselben Thumbprint andere DER-Daten."
                )
        else:
            _atomic_write_bytes(destination, certificate_der, mode=0o644)
        return thumbprint
    except (OSError, ValueError) as exc:
        die(f"Die aktuelle Mavi-Bootstrap-CA konnte nicht sicher archiviert werden: {exc}")
    raise AssertionError("unreachable")


def _controller_bound_bootstrap_root_certificates(
    paths: dict[str, Path] | None = None,
    *,
    project: Path | None = None,
) -> tuple[str, dict[str, str]]:
    """Aktuelle und archivierte Bootstrap-Roots aus Controller-DER ableiten."""
    from .remote import (
        _certificate_der_from_file,
        _certificate_thumbprint_from_der,
    )

    if paths is None:
        if project is None:
            raise ValueError(
                "Bootstrap-Root-Zertifikate müssen an ein Mavi-Projekt gebunden werden."
            )
        resolved_paths = _bootstrap_pki_paths(project)
    else:
        resolved_paths = paths
    current_der: bytes | None = None
    for candidate in (resolved_paths["system_ca"], resolved_paths["ca_cert"]):
        if not candidate.is_file():
            continue
        certificate_der = _certificate_der_from_file(candidate)
        if current_der is not None and not secrets.compare_digest(
            current_der,
            certificate_der,
        ):
            raise ValueError(
                "Die aktuellen Controller-Kopien der Mavi-Bootstrap-CA widersprechen sich."
            )
        current_der = certificate_der
    if current_der is None:
        raise ValueError(
            "Die aktuelle Mavi-Bootstrap-CA ist auf dem Controller nicht lesbar."
        )

    current_thumbprint = _certificate_thumbprint_from_der(current_der)
    certificates: dict[str, str] = {
        current_thumbprint: base64.b64encode(current_der).decode("ascii")
    }
    archive = resolved_paths["ca_archive"]
    if archive.exists():
        if archive.is_symlink() or not archive.is_dir():
            raise ValueError("Das Controller-Archiv der Bootstrap-CAs ist kein regulärer Ordner.")
        for candidate in sorted(archive.glob("*.cer"), key=lambda path: path.name):
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError(
                    f"Der archivierte Bootstrap-CA-Pfad ist keine reguläre Datei: {candidate}"
                )
            certificate_der = _certificate_der_from_file(candidate)
            thumbprint = _certificate_thumbprint_from_der(certificate_der)
            if candidate.stem.upper() != thumbprint:
                raise ValueError(
                    f"Archivname und DER-Thumbprint der Bootstrap-CA stimmen nicht überein: {candidate}"
                )
            encoded = base64.b64encode(certificate_der).decode("ascii")
            existing = certificates.get(thumbprint)
            if existing is not None and not secrets.compare_digest(existing, encoded):
                raise ValueError(
                    "Das Controller-Archiv enthält kollidierende Bootstrap-CA-Identitäten."
                )
            certificates[thumbprint] = encoded
    return current_thumbprint, certificates


def _issue_bootstrap_server_certificate(settings: dict[str, Any], paths: dict[str, Path]) -> None:
    config_text = _openssl_server_config(settings["url_host"])
    _atomic_write_bytes(paths["openssl_config"], config_text.encode("utf-8"), mode=0o600)

    temporary_key = paths["pki"] / ".mavi-server.key.new"
    temporary_csr = paths["pki"] / ".mavi-server.csr.new"
    temporary_cert = paths["pki"] / ".mavi-server.cert.new"
    for candidate in (temporary_key, temporary_csr, temporary_cert):
        candidate.unlink(missing_ok=True)
    try:
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(temporary_key),
            ],
            description="HTTPS-Serverschlüssel erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "req", "-new", "-sha256",
                "-key", str(temporary_key), "-out", str(temporary_csr),
                "-config", str(paths["openssl_config"]),
            ],
            description="HTTPS-Zertifikatsanfrage mit SAN erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "x509", "-req", "-sha256",
                "-in", str(temporary_csr),
                "-CA", str(paths["ca_cert"]),
                "-CAkey", str(paths["ca_key"]),
                "-CAcreateserial", "-out", str(temporary_cert),
                "-days", str(settings["server_cert_validity_days"]),
                # -extensions alleine reicht bei `openssl x509 -req` nicht aus.
                # Ohne -extfile ignoriert OpenSSL die SAN-Erweiterung und das
                # Zertifikat ist anschließend nicht für die Bootstrap-IP bzw.
                # den Bootstrap-DNS-Namen gültig.
                "-extfile", str(paths["openssl_config"]),
                "-extensions", "server_ext",
            ],
            description="HTTPS-Serverzertifikat mit Mavi-CA signieren",
            quiet=True,
        )
        os.chmod(temporary_key, 0o600)
        os.chmod(temporary_cert, 0o644)
        os.replace(temporary_key, paths["server_key"])
        os.replace(temporary_csr, paths["server_csr"])
        os.replace(temporary_cert, paths["server_cert"])
        os.chmod(paths["server_key"], 0o600)
        os.chmod(paths["server_csr"], 0o600)
        os.chmod(paths["server_cert"], 0o644)
    finally:
        for candidate in (temporary_key, temporary_csr, temporary_cert):
            candidate.unlink(missing_ok=True)


def _nginx_bootstrap_config(settings: dict[str, Any], paths: dict[str, Path]) -> str:
    allow_lines = ["        allow 127.0.0.1;", "        allow ::1;"]
    allow_lines.append(f"        allow {settings['ansible_server_ip']};")
    allow_lines.extend(f"        allow {cidr};" for cidr in settings["allowed_cidrs"])
    allow_lines.append("        deny all;")
    webroot = str(settings["local_dir"]).rstrip("/\\") + "/"
    listen_lines = [f"    listen {settings['port']} ssl;"]
    if ipaddress.ip_address(settings["ansible_server_ip"]).version == 6:
        listen_lines.append(f"    listen [::]:{settings['port']} ssl;")
    return "\n".join([
        f"# Automatisch verwaltet durch Mavi Provisioner; Instanz {settings['instance_id']}",
        "server {",
        *listen_lines,
        f"    server_name {_nginx_quote(settings['url_host'])};",
        f"    ssl_certificate {_nginx_quote(str(paths['server_cert']))};",
        f"    ssl_certificate_key {_nginx_quote(str(paths['server_key']))};",
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        "    ssl_session_tickets off;",
        "    server_tokens off;",
        "    client_max_body_size 1m;",
        "    add_header X-Content-Type-Options nosniff always;",
        "    add_header Cache-Control \"no-store\" always;",
        "",
        f"    location ^~ {_nginx_quote(settings['url_path'])} {{",
        f"        alias {_nginx_quote(webroot)};",
        "        autoindex off;",
        "        default_type application/octet-stream;",
        "        limit_except GET HEAD { deny all; }",
        *allow_lines,
        "    }",
        "",
        "    location / { return 404; }",
        "}",
        "",
    ])


def _ufw_delete_tagged_rules(ufw: str, tag: str) -> None:
    """Nur eindeutig mit der aktuellen Instanz markierte UFW-Regeln entfernen."""
    from .environment import die

    try:
        status = subprocess.run(
            [ufw, "status", "numbered"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"UFW-Regeln konnten für die sichere Instanzbereinigung nicht gelesen werden: {exc}")
    if status.returncode != 0:
        die("UFW-Regeln konnten für die sichere Instanzbereinigung nicht gelesen werden.")
    numbers: list[int] = []
    for line in (status.stdout or "").splitlines():
        if tag not in line:
            continue
        match = re.match(r"^\[\s*(\d+)\]", line.strip())
        if match:
            numbers.append(int(match.group(1)))
    for number in sorted(set(numbers), reverse=True):
        _root_command(
            [ufw, "--force", "delete", str(number)],
            description=f"instanzeigene UFW-Regel {number} entfernen",
        )


def _configure_bootstrap_firewall(settings: dict[str, Any]) -> dict[str, Any]:
    """Server-Firewall ausschließlich über instanzeigene, entfernbaren Ressourcen verwalten."""
    from .environment import die

    port = str(settings["port"])
    firewall_sources = list(settings["allowed_cidrs"])
    server_source = str(settings["ansible_server_ip"])
    firewall_tag = f"mavi-bootstrap-{settings['instance_id']}"
    if not any(
        ipaddress.ip_address(server_source) in ipaddress.ip_network(cidr)
        for cidr in firewall_sources
        if ipaddress.ip_network(cidr).version == ipaddress.ip_address(server_source).version
    ):
        firewall_sources.append(server_source)
    ufw = shutil.which("ufw")
    if ufw:
        status = subprocess.run([ufw, "status"], check=False, capture_output=True, text=True)
        if status.returncode == 0 and re.search(r"(?im)^Status:\s+active\s*$", status.stdout or ""):
            _ufw_delete_tagged_rules(ufw, firewall_tag)
            for cidr in firewall_sources:
                _root_command(
                    [
                        ufw, "allow", "from", cidr, "to", "any", "port", port,
                        "proto", "tcp", "comment", firewall_tag,
                    ],
                    description=f"UFW HTTPS/{port} für {cidr} freigeben",
                )
            return {"backend": "ufw", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}

    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        state = subprocess.run([firewall_cmd, "--state"], check=False, capture_output=True, text=True)
        if state.returncode == 0:
            zones = subprocess.run(
                [firewall_cmd, "--permanent", "--get-zones"],
                check=False,
                capture_output=True,
                text=True,
            )
            if zones.returncode != 0:
                die("firewalld-Zonen konnten nicht gelesen werden.")
            if firewall_tag in (zones.stdout or "").split():
                _root_command(
                    [firewall_cmd, "--permanent", f"--delete-zone={firewall_tag}"],
                    description=f"alte instanzeigene firewalld-Zone {firewall_tag} entfernen",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--new-zone={firewall_tag}"],
                description=f"instanzeigene firewalld-Zone {firewall_tag} anlegen",
            )
            for cidr in firewall_sources:
                _root_command(
                    [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-source={cidr}"],
                    description=f"firewalld HTTPS/{port} für {cidr} freigeben",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-port={port}/tcp"],
                description=f"firewalld HTTPS/{port} in Instanzzone freigeben",
            )
            _root_command([firewall_cmd, "--reload"], description="firewalld neu laden")
            return {
                "backend": "firewalld",
                "tag": firewall_tag,
                "sources": firewall_sources,
                "port": int(port),
            }
    return {"backend": "none", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}


def _remove_bootstrap_firewall(state: dict[str, Any]) -> None:
    """Nur im Serverstatus ausgewiesene Firewall-Ressourcen dieser Instanz entfernen."""
    from .environment import die

    firewall = state.get("firewall", {}) if isinstance(state, dict) else {}
    if not isinstance(firewall, dict):
        return
    backend = str(firewall.get("backend", "") or "")
    tag = str(firewall.get("tag", "") or "")
    instance_id = str(state.get("instance_id", "") or "") if isinstance(state, dict) else ""
    if not tag or tag != f"mavi-bootstrap-{instance_id}":
        if backend not in {"", "none"}:
            die("Firewall-Status besitzt keine eindeutig zur Instanz passende Eigentumsmarke.")
        return
    if backend == "ufw":
        ufw = shutil.which("ufw")
        if not ufw:
            die("UFW fehlt; instanzeigene Regeln konnten nicht entfernt werden.")
        _ufw_delete_tagged_rules(ufw, tag)
    elif backend == "firewalld":
        firewall_cmd = shutil.which("firewall-cmd")
        if not firewall_cmd:
            die("firewall-cmd fehlt; instanzeigene Zone konnte nicht entfernt werden.")
        zones = subprocess.run(
            [firewall_cmd, "--permanent", "--get-zones"],
            check=False,
            capture_output=True,
            text=True,
        )
        if zones.returncode != 0:
            die("firewalld-Zonen konnten nicht gelesen werden.")
        if tag in (zones.stdout or "").split():
            _root_command(
                [firewall_cmd, "--permanent", f"--delete-zone={tag}"],
                description=f"instanzeigene firewalld-Zone {tag} entfernen",
            )
            _root_command([firewall_cmd, "--reload"], description="firewalld neu laden")


def _trust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    from .environment import die

    paths["system_ca"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_copy_file(paths["ca_cert"], paths["system_ca"])
    os.chmod(paths["system_ca"], 0o644)
    update_ca = shutil.which("update-ca-certificates")
    if update_ca:
        _root_command([update_ca], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    update_trust = shutil.which("update-ca-trust")
    if update_trust:
        anchors = paths["system_ca_anchor"]
        anchors.parent.mkdir(parents=True, exist_ok=True)
        _atomic_copy_file(paths["ca_cert"], anchors)
        _root_command([update_trust, "extract"], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    die("Weder update-ca-certificates noch update-ca-trust ist verfügbar.")


def _untrust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    """Nur die Vertrauensanker der aktuellen Bootstrap-Instanz entfernen."""
    from .environment import die

    removed_debian_anchor = paths["system_ca"].exists()
    removed_rhel_anchor = paths["system_ca_anchor"].exists()
    paths["system_ca"].unlink(missing_ok=True)
    paths["system_ca_anchor"].unlink(missing_ok=True)
    if removed_debian_anchor:
        update_ca = shutil.which("update-ca-certificates")
        if not update_ca:
            die("update-ca-certificates fehlt; lokaler CA-Trust konnte nicht sauber aktualisiert werden.")
        _root_command([update_ca, "--fresh"], description="instanzeigene Mavi-CA aus Linux-Vertrauen entfernen")
    if removed_rhel_anchor:
        update_trust = shutil.which("update-ca-trust")
        if not update_trust:
            die("update-ca-trust fehlt; lokaler CA-Trust konnte nicht sauber aktualisiert werden.")
        _root_command([update_trust, "extract"], description="instanzeigene Mavi-CA aus Linux-Vertrauen entfernen")


def _enable_and_reload_nginx(paths: dict[str, Path]) -> None:
    from .environment import die

    nginx = shutil.which("nginx")
    if not nginx:
        die("nginx wurde trotz Paketinstallation nicht gefunden.")
    _root_command([nginx, "-t"], description="nginx-Konfiguration sicher validieren")
    if shutil.which("systemctl"):
        _root_command(["systemctl", "enable", "--now", "nginx"], description="nginx aktivieren und starten")
        _root_command(["systemctl", "reload", "nginx"], description="nginx-Konfiguration laden")
    elif shutil.which("service"):
        _root_command(["service", "nginx", "restart"], description="nginx neu starten")
    else:
        die("Weder systemctl noch service ist verfügbar, um nginx zu starten.")


def _tcp_port_is_bindable(port: int, *, include_ipv6: bool) -> bool:
    """Konservativer Vorabcheck: Kann nginx den Port auf allen benötigten Familien binden?"""
    targets: list[tuple[int, tuple[Any, ...]]] = [
        (socket.AF_INET, ("0.0.0.0", port)),
    ]
    if include_ipv6 and socket.has_ipv6:
        targets.append((socket.AF_INET6, ("::", port, 0, 0)))
    for family, address in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind(address)
        except OSError:
            return False
    return True


def _tcp_listener_process_names(port: int) -> set[str]:
    """Best effort: Namen der Prozesse ermitteln, die den TCP-Port bereits halten."""
    names: set[str] = set()
    ss = shutil.which("ss")
    if ss:
        try:
            result = subprocess.run(
                [ss, "-H", "-ltnp"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            for line in (result.stdout or "").splitlines():
                fields = line.split()
                if len(fields) < 4 or not re.search(rf":{port}$", fields[3]):
                    continue
                for process_name in re.findall(r'\(\("([^"]+)"', line):
                    names.add(process_name.casefold())
    if names:
        return names

    fuser = shutil.which("fuser")
    if not fuser:
        return names
    try:
        result = subprocess.run(
            [fuser, "-n", "tcp", str(port)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return names
    for pid_text in re.findall(r"\b\d+\b", (result.stdout or "") + " " + (result.stderr or "")):
        try:
            process_name = Path(f"/proc/{int(pid_text)}/comm").read_text(encoding="utf-8").strip()
        except (OSError, ValueError, UnicodeError):
            continue
        if process_name:
            names.add(process_name.casefold())
    return names


def _managed_nginx_is_active() -> bool:
    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            result = subprocess.run(
                [systemctl, "is-active", "--quiet", "nginx"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    service = shutil.which("service")
    if service:
        try:
            result = subprocess.run(
                [service, "nginx", "status"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    return False


def _bootstrap_url_with_port(settings: dict[str, Any], port: int) -> str:
    parsed = urllib.parse.urlsplit(settings["base_url"])
    host = str(parsed.hostname or settings["url_host"])
    try:
        host_is_ipv6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        host_is_ipv6 = False
    netloc_host = f"[{host}]" if host_is_ipv6 else host
    netloc = netloc_host if port == 443 else f"{netloc_host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parsed.path, "", ""))


def _persist_bootstrap_base_url(
    project: Path,
    base_url: str,
    *,
    fallback_uid: int,
    fallback_gid: int,
) -> None:
    """Automatisch gewählten Port zentral speichern und bestehende Dateirechte erhalten."""
    from .environment import (
        atomic_write_yaml,
        die,
        load_yaml,
        project_paths,
    )

    config_path = project_paths(project)["config"]
    existing_uid = fallback_uid
    existing_gid = fallback_gid
    existing_mode = 0o644
    try:
        current_stat = config_path.stat()
        existing_uid = int(current_stat.st_uid)
        existing_gid = int(current_stat.st_gid)
        existing_mode = int(current_stat.st_mode & 0o7777)
    except OSError:
        pass
    config = load_yaml(config_path, {}) or {}
    if not isinstance(config, dict):
        die(f"Zentrale Konfiguration ist kein YAML-Objekt: {config_path}")
    config["bootstrap_base_url"] = base_url
    try:
        atomic_write_yaml(config_path, config)
    except OSError as exc:
        die(f"Automatisch gewählter HTTPS-Port konnte nicht zentral gespeichert werden: {exc}")
    try:
        os.chown(config_path, existing_uid, existing_gid, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        pass
    except OSError as exc:
        die(f"Besitzrechte der zentralen Konfiguration konnten nicht erhalten werden: {exc}")
    os.chmod(config_path, existing_mode)


def _select_usable_bootstrap_port(
    project: Path,
    settings: dict[str, Any],
    *,
    uid: int,
    gid: int,
) -> dict[str, Any]:
    """Konfigurierten Port behalten oder einen freien, dauerhaft gespeicherten Ersatz wählen."""
    from .environment import die
    from .reports import redact_sensitive_text

    configured_port = int(settings["port"])
    include_ipv6 = ipaddress.ip_address(settings["ansible_server_ip"]).version == 6
    if _tcp_port_is_bindable(configured_port, include_ipv6=include_ipv6):
        return settings

    listeners = _tcp_listener_process_names(configured_port)
    managed_nginx_listener = (
        any(name == "nginx" or name.startswith("nginx-") for name in listeners)
        and _managed_nginx_is_active()
    )
    if managed_nginx_listener:
        health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
        endpoint_ok, endpoint_detail = _strict_https_probe(
            health_url,
            trusted_ca=_bootstrap_pki_paths(project)["system_ca"],
        )
        if endpoint_ok:
            print(
                f"  ✓ HTTPS-Port {configured_port} liefert bereits das gültige "
                "Mavi-Zertifikat und bleibt erhalten."
            )
            return settings
        print(
            f"  ! nginx nutzt HTTPS-Port {configured_port}, liefert dort aber nicht "
            "nachweislich das Mavi-Zertifikat. Mavi trennt den TLS-Endpunkt automatisch."
        )
        print(f"    Prüfung: {redact_sensitive_text(endpoint_detail)}")

    preferred_ports = [8443, 9443, 10443, 11443, 12443, 13443, 14443, 15443]
    fallback_candidates = preferred_ports + list(range(8444, 8501))
    selected_port = next(
        (
            candidate
            for candidate in fallback_candidates
            if candidate != configured_port
            and _tcp_port_is_bindable(candidate, include_ipv6=include_ipv6)
        ),
        None,
    )
    occupied_by = ", ".join(sorted(listeners)) if listeners else "einen anderen Dienst"
    if selected_port is None:
        die(
            f"HTTPS-Port {configured_port} ist durch {occupied_by} belegt, "
            "und Mavi konnte keinen freien Ersatzport finden."
        )
    fallback_url = _bootstrap_url_with_port(settings, selected_port)
    _persist_bootstrap_base_url(
        project,
        fallback_url,
        fallback_uid=uid,
        fallback_gid=gid,
    )
    print(
        f"  ! HTTPS-Port {configured_port} ist durch {occupied_by} belegt. "
        f"Mavi verwendet automatisch Port {selected_port}."
    )
    print(f"  ✓ bootstrap_base_url dauerhaft gespeichert: {fallback_url}")
    return _bootstrap_settings(project)


def _relaunch_bootstrap_server_setup_as_root(project: Path, *, rotate_ca: bool = False) -> None:
    from .environment import die

    sudo = shutil.which("sudo")
    if not sudo:
        die("Für das automatische nginx-/Zertifikats-Setup fehlt sudo.")
    executable = shutil.which(sys.argv[0]) or sys.argv[0]
    script_path = Path(executable).expanduser().resolve()
    command = [
        sudo,
        sys.executable,
        str(script_path),
        "--project",
        str(project.resolve()),
        "ssh",
        "server-setup",
        "--yes",
    ]
    if rotate_ca:
        command.append("--rotate-ca")
    print("\nMavi benötigt einmalig sudo für nginx, Zertifikat und Server-Firewall.")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        die(f"Automatisches HTTPS-Server-Setup ist mit Code {result.returncode} fehlgeschlagen.")


def cmd_ssh_server_setup(args: argparse.Namespace) -> None:
    """Kompletten HTTPS-Server inklusive privater CA automatisch einrichten."""
    from .environment import (
        die,
        ensure_initialized,
    )
    from .reports import redact_sensitive_text
    from .settings import VERSION

    project = args.project.resolve()
    if os.name == "nt" or not hasattr(os, "geteuid"):
        die("Das automatische HTTPS-Server-Setup ist für Linux-Ansible-Server vorgesehen.")
    if os.geteuid() != 0:
        ensure_initialized(project, quiet=True)
        _relaunch_bootstrap_server_setup_as_root(
            project,
            rotate_ca=bool(getattr(args, "rotate_ca", False)),
        )
        return

    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    uid, gid = _bootstrap_operator_ids(project)
    rotate_ca = bool(getattr(args, "rotate_ca", False))
    if rotate_ca and not bool(getattr(args, "yes", False)):
        die("CA-Rotation benötigt die explizite Bestätigung --yes.")

    print("\nMavi VOLLAUTOMATISCHES HTTPS-SERVER-SETUP")
    print("=========================================")
    _install_bootstrap_server_packages()
    settings = _select_usable_bootstrap_port(project, settings, uid=uid, gid=gid)
    print(f"HTTPS:      {settings['base_url']}")
    print(f"Webroot:    {settings['local_dir']}")
    print(f"Instanz:    {settings['instance_id']}")
    print(f"Client-Netze: {', '.join(settings['allowed_cidrs'])}")

    paths["pki"].mkdir(parents=True, exist_ok=True)
    os.chmod(paths["root"], 0o755)
    os.chmod(paths["pki"], 0o700)
    ca_created, rotation_archive = _create_or_reuse_bootstrap_ca(
        settings,
        paths,
        rotate=rotate_ca,
    )
    archived_ca_thumbprint = _archive_bootstrap_root_ca(paths)
    _issue_bootstrap_server_certificate(settings, paths)
    _trust_bootstrap_ca_locally(paths)

    webroot: Path = settings["local_dir"]
    webroot.mkdir(parents=True, exist_ok=True)
    os.chmod(webroot, 0o755)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    _atomic_copy_file(paths["ca_cert"], webroot / "Mavi-ROOT-CA.pem")
    _atomic_write_bytes(
        webroot / ".mavi-bootstrap-owner.json",
        (json.dumps({
            "instance_id": settings["instance_id"],
            "project": str(project),
            "webroot": str(webroot),
        }, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )

    paths["nginx_config"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(
        paths["nginx_config"],
        _nginx_bootstrap_config(settings, paths).encode("utf-8"),
        mode=0o644,
    )
    _enable_and_reload_nginx(paths)
    firewall_state = _configure_bootstrap_firewall(settings)

    launcher_root, _windows_root = _bootstrap_launcher_roots(project)
    if launcher_root is not None:
        try:
            launcher_root.mkdir(parents=True, exist_ok=True)
            os.chmod(launcher_root, 0o755)
            os.chown(launcher_root, uid, gid, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            print(f"! Softwareablage wird später mit Benutzerrechten angelegt: {redact_sensitive_text(exc)}")

    for managed_path in (
        webroot,
        webroot / "Mavi-SETUP-CHECK.txt",
        webroot / "Mavi-ROOT-CA.pem",
        webroot / ".mavi-bootstrap-owner.json",
    ):
        try:
            os.chown(managed_path, uid, gid, follow_symlinks=False)
        except NotImplementedError:
            pass
        except OSError as exc:
            die(f"Webroot-Besitzrechte konnten nicht gesetzt werden: {exc}")
    state = {
        "version": VERSION,
        "instance_id": settings["instance_id"],
        "project": str(project),
        "base_url": settings["base_url"],
        "webroot": str(webroot),
        "host": settings["url_host"],
        "ansible_server_ip": settings["ansible_server_ip"],
        "port": settings["port"],
        "allowed_cidrs": settings["allowed_cidrs"],
        "firewall": firewall_state,
        "ca_sha256": _sha256_file(paths["ca_cert"]),
        "ca_windows_thumbprint": _certificate_sha1_thumbprint(paths["ca_cert"]),
        "ca_thumbprint": archived_ca_thumbprint,
        "ca_validity_days": settings["ca_validity_days"],
        "server_cert_validity_days": settings["server_cert_validity_days"],
        "ca_created": ca_created,
        "rotation_archive": str(rotation_archive) if rotation_archive is not None else "",
        "configured_epoch": time.time(),
    }
    _atomic_write_bytes(
        paths["state"],
        (json.dumps(state, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )
    print("\n✓ nginx, Mavi-CA, SAN-Zertifikat, Webroot und Server-Firewall sind eingerichtet.")
    print("✓ Die CA bleibt stabil und wird bei späteren Läufen nicht still ersetzt.")
    if rotation_archive is not None:
        print(f"! Alte PKI recoverable archiviert: {rotation_archive}")
        print("! Die archivierte alte CA muss anschließend auf allen Ziel-PCs anhand der Thumbprint entfernt werden.")


def _ensure_automatic_https_server(project: Path) -> dict[str, Any]:
    """Server-Setup nur bei Bedarf automatisch mit sudo ausführen."""
    from .environment import die
    from .settings import VERSION

    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    files_ready = all(
        path.exists()
        for path in (
            paths["system_ca"],
            paths["ca_archive"],
            paths["nginx_config"],
            paths["state"],
        )
    )
    if files_ready and hasattr(os, "geteuid") and os.geteuid() == 0:
        files_ready = all(
            path.exists()
            for path in (
                paths["ca_key"], paths["ca_cert"], paths["server_key"], paths["server_cert"],
            )
        )
    state_ready = False
    nginx_ready = False
    if files_ready:
        try:
            state = json.loads(paths["state"].read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("Ungültiger Mavi-Serverstatus")
            current_ca_thumbprint, _controller_roots = (
                _controller_bound_bootstrap_root_certificates(paths)
            )
            state_ready = (
                state.get("instance_id") == settings["instance_id"]
                and state.get("project") == str(project.resolve())
                and state.get("base_url") == settings["base_url"]
                and state.get("webroot") == str(settings["local_dir"])
                and state.get("host") == settings["url_host"]
                and state.get("ansible_server_ip") == settings["ansible_server_ip"]
                and state.get("port") == settings["port"]
                and state.get("allowed_cidrs") == settings["allowed_cidrs"]
                and state.get("ca_validity_days") == settings["ca_validity_days"]
                and state.get("server_cert_validity_days") == settings["server_cert_validity_days"]
                and state.get("ca_thumbprint") == current_ca_thumbprint
            )
            nginx_ready = paths["nginx_config"].read_text(encoding="utf-8") == _nginx_bootstrap_config(
                settings,
                paths,
            )
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            state_ready = False
            nginx_ready = False
    https_ready = False
    certificates_ready = (
        _certificate_valid_for(paths["ca_cert"], 30 * 86400)
        and _certificate_valid_for(paths["server_cert"], 7 * 86400)
    )
    if files_ready and state_ready and nginx_ready and certificates_ready:
        https_ready, _detail = _strict_https_probe(
            health_url,
            expected_body=health_body,
            trusted_ca=paths["system_ca"],
        )
    if files_ready and state_ready and nginx_ready and certificates_ready and https_ready:
        return settings

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd_ssh_server_setup(argparse.Namespace(project=project, yes=True))
    else:
        _relaunch_bootstrap_server_setup_as_root(project)

    if not paths["system_ca"].is_file():
        die("Automatisches Setup meldete Erfolg, aber das Mavi-CA-Zertifikat fehlt.")
    # Das Root-Setup kann bei einem Portkonflikt die zentrale Basis-URL
    # automatisch angepasst haben. Daher alle abgeleiteten Werte neu laden.
    settings = _bootstrap_settings(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    https_ready, detail = _strict_https_probe(
        health_url,
        expected_body=health_body,
        trusted_ca=paths["system_ca"],
    )
    if not https_ready:
        die(f"Automatisches HTTPS-Setup wurde abgeschlossen, ist aber nicht erreichbar: {detail}")
    return settings


class _RejectBootstrapRedirects(urllib.request.HTTPRedirectHandler):
    """Feste Bootstrap-URL: auch kein HTTPS-zu-HTTP-Redirect wird verfolgt."""

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"Bootstrap-Weiterleitungen sind deaktiviert: {newurl}",
            headers,
            fp,
        )


def _strict_https_probe(
    url: str,
    *,
    expected_body: bytes | None = None,
    trusted_ca: Path | None = None,
) -> tuple[bool, str]:
    """HTTPS-Aufruf mit strikter Ketten- und Hostnamenprüfung, ohne Bypass."""
    from .settings import VERSION

    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            return False, "Sicherheitsabbruch: URL ist nicht HTTPS."
        context = ssl.create_default_context()
        if trusted_ca is not None:
            if not trusted_ca.is_file():
                return False, f"Vertrauenswürdige Mavi-CA fehlt: {trusted_ca}"
            # Ergänzt die private Mavi-CA ausdrücklich zum normalen Trust Store.
            # CERT_REQUIRED und check_hostname bleiben zwingend aktiv.
            context.load_verify_locations(cafile=str(trusted_ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        request = urllib.request.Request(url, headers={"User-Agent": f"mavi-provisioner/{VERSION}"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectBootstrapRedirects(),
            urllib.request.HTTPSHandler(context=context),
        )
        with opener.open(request, timeout=10) as response:
            status = int(getattr(response, "status", 200))
            final_url = str(response.geturl() or url)
            body = response.read(1024 * 1024)
        final = urllib.parse.urlsplit(final_url)
        if (
            final.scheme.lower() != "https"
            or final.hostname != parsed.hostname
            or final.port != parsed.port
        ):
            return False, f"Unzulässige HTTPS-Weiterleitung: {final_url}"
        if status < 200 or status >= 300:
            return False, f"HTTPS antwortete mit Status {status}."
        if expected_body is not None and body != expected_body:
            return False, "HTTPS-Inhalt stimmt nicht mit dem lokal veröffentlichten Artefakt überein."
        return True, f"HTTPS erreichbar, Zertifikat und Hostname gültig (Status {status})."
    except ssl.SSLCertVerificationError as exc:
        return False, f"Zertifikatsprüfung fehlgeschlagen: {exc}"
    except ssl.SSLError as exc:
        return False, f"TLS-/CA-Prüfung fehlgeschlagen: {exc}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTPS antwortete mit Status {exc.code}."
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return False, f"Zertifikatsprüfung fehlgeschlagen: {exc.reason}"
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"
    except (TimeoutError, OSError, ValueError) as exc:
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"


def _https_ssh_bootstrap_cmd(
    ps1_download_url: str,
    ps1_sha256: str,
    *,
    ca_der: bytes,
    launcher_id: str,
) -> str:
    """Erzeugt den doppelklickbaren CMD-Starter für den OpenSSH-Bootstrap."""
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", ps1_sha256):
        raise ValueError("Der PS1-Hash für den Windows-Starter ist ungültig.")
    if not ca_der or len(ca_der) > 65536:
        raise ValueError("Das Mavi-CA-Zertifikat ist leer oder unerwartet groß.")
    safe_url = _powershell_single_quote(ps1_download_url)
    safe_sha = _powershell_single_quote(ps1_sha256.lower())
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", launcher_id).strip("._-") or "WINDOWS"
    ca_sha256 = hashlib.sha256(ca_der).hexdigest()
    ca_base64 = base64.b64encode(ca_der).decode("ascii")
    ca_chunks = [ca_base64[index:index + 64] for index in range(0, len(ca_base64), 64)]

    ca_import_script = (
        "$ErrorActionPreference='Stop';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "$p=Join-Path $d 'Mavi-Bootstrap-Root-CA.cer';"
        f"$expected='{ca_sha256}';"
        "$bytes=[IO.File]::ReadAllBytes($p);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: CA SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes);"
        "$now=[DateTime]::UtcNow;if($now -lt $cert.NotBefore.ToUniversalTime() -or $now -gt $cert.NotAfter.ToUniversalTime()){throw 'SICHERHEITSABBRUCH: Eingebettete Mavi-CA ist noch nicht oder nicht mehr gültig.'};"
        "$rawBc=$cert.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'}|Select-Object -First 1;"
        "if($null -eq $rawBc){throw 'SICHERHEITSABBRUCH: Zertifikat besitzt keine CA-BasicConstraints.'};"
        "$bc=New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension;"
        "$bc.CopyFrom($rawBc);if(-not $bc.CertificateAuthority){throw 'SICHERHEITSABBRUCH: Eingebettetes Zertifikat ist keine CA.'};"
        "$added=$false;"
        "$store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');"
        "try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);"
        "$found=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false);"
        "if($found.Count -eq 0){$store.Add($cert);$added=$true;Write-Host ('Mavi-CA installiert: '+$cert.Thumbprint) -ForegroundColor Green}"
        "else{Write-Host ('Mavi-CA bereits vertraut: '+$cert.Thumbprint) -ForegroundColor Green}}finally{$store.Close()};"
        "if($added){exit 17}else{exit 0}"
    )
    ca_import_b64 = base64.b64encode(ca_import_script.encode("utf-16-le")).decode("ascii")

    download_script = (
        "$ErrorActionPreference='Stop';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        f"$u='{safe_url}';$expected='{safe_sha}';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "New-Item -ItemType Directory -Path $d -Force|Out-Null;"
        "$p=Join-Path $d 'Mavi-OpenSSH-Setup.ps1';"
        "try{"
        "Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $p -TimeoutSec 60 -MaximumRedirection 0;"
        "if(-not(Test-Path -LiteralPath $p)){throw 'Bootstrap-Download fehlgeschlagen.'};"
        "$actual=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: PS1 SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "& $p"
        "}catch{Write-Host '';Write-Host ('Mavi OpenSSH Bootstrap FEHLER: '+$_.Exception.Message) -ForegroundColor Red;"
        "Read-Host 'ENTER zum Schliessen'|Out-Null;exit 10}"
    )
    download_b64 = base64.b64encode(download_script.encode("utf-16-le")).decode("ascii")
    copied_launcher = f"Mavi-OpenSSH-Launcher-{safe_id}.cmd"
    lines = [
        "@echo off",
        "setlocal EnableExtensions DisableDelayedExpansion",
        f"title Mavi OpenSSH Vollautomatik - {safe_id}",
        "if /I \"%~1\"==\"--mavi-elevated\" goto mavi_elevated",
        f"set \"MaviCOPY=%TEMP%\\{copied_launcher}\"",
        "copy /Y \"%~f0\" \"%MaviCOPY%\" >nul",
        "if errorlevel 1 goto mavi_copy_failed",
        "echo.",
        "echo Mavi macht jetzt automatisch: UAC, CA-Vertrauen, HTTPS und OpenSSH.",
        "echo Bitte die Windows-UAC-Abfrage bestaetigen.",
        "echo.",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"try{$r=Start-Process -FilePath $env:MaviCOPY -Verb RunAs -ArgumentList @('--mavi-elevated') -Wait -PassThru;exit $r.ExitCode}catch{Write-Host $_.Exception.Message -ForegroundColor Red;exit 5}\"",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" (",
        "  echo.",
        "  echo Mavi Bootstrap meldete Fehlercode %MaviRC%.",
        "  pause",
        ")",
        "exit /b %MaviRC%",
        "",
        ":mavi_copy_failed",
        "echo FEHLER: Der Starter konnte nicht nach TEMP kopiert werden.",
        "pause",
        "exit /b 4",
        "",
        ":mavi_elevated",
        "powershell.exe -NoProfile -Command \"if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }\"",
        "if errorlevel 1 (",
        "  echo FEHLER: Administratorrechte wurden nicht erteilt.",
        "  pause",
        "  exit /b 5",
        ")",
        "set \"MaviDIR=%TEMP%\\Mavi-OpenSSH-Bootstrap\"",
        "if not exist \"%MaviDIR%\" mkdir \"%MaviDIR%\"",
        "set \"MaviCA64=%MaviDIR%\\Mavi-Bootstrap-Root-CA.b64\"",
        "set \"MaviCACERT=%MaviDIR%\\Mavi-Bootstrap-Root-CA.cer\"",
        f"> \"%MaviCA64%\" echo {ca_chunks[0]}",
        *[f">> \"%MaviCA64%\" echo {chunk}" for chunk in ca_chunks[1:]],
        "certutil.exe -f -decode \"%MaviCA64%\" \"%MaviCACERT%\" >nul",
        "if errorlevel 1 goto mavi_ca_failed",
        "set \"MAVI_CA_ADDED_THIS_RUN=0\"",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {ca_import_b64}",
        "set \"MaviCARC=%ERRORLEVEL%\"",
        "if \"%MaviCARC%\"==\"17\" set \"MAVI_CA_ADDED_THIS_RUN=1\"",
        "if not \"%MaviCARC%\"==\"0\" if not \"%MaviCARC%\"==\"17\" goto mavi_ca_failed",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {download_b64}",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" goto mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH wurde vollautomatisch eingerichtet.",
        "exit /b 0",
        "",
        ":mavi_ca_failed",
        "echo.",
        "echo SICHERHEITSABBRUCH: Die feste Mavi-CA konnte nicht verifiziert oder importiert werden.",
        "pause",
        "exit /b 8",
        "",
        ":mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH Bootstrap meldete Fehlercode %MaviRC%.",
        "pause",
        "exit /b %MaviRC%",
        "",
    ]
    if max((len(line) for line in lines), default=0) > 7000:
        raise RuntimeError("Interner Fehler: HTTPS-Launcher-Zeile überschreitet das sichere CMD-Limit.")
    return "\r\n".join(lines)


def _deliver_ssh_launcher_to_public_desktop(
    project: Path,
    *,
    host: str,
    launcher_path: Path,
    expected_sha256: str,
) -> str:
    """Liefert den öffentlichen, hashgebundenen Starter über das bestehende PSRP/WinRM aus.

    Das ist ausschließlich ein Ersatz für eine nicht beschreibbare zentrale
    Softwareablage. Der bisherige, bereits funktionierende Verwaltungsweg wird
    verwendet; weder HTTP noch ein freigegebener Schreibzugriff werden erzeugt.
    Die Datei landet zunächst unter einem temporären Namen auf Windows, wird
    dort gegen den lokalen SHA-256 geprüft und erst dann am endgültigen Namen veröffentlicht.
    """
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        create_temporary_vault_password_file,
        strip_ansi,
    )
    from .remote import (
        _connection_label,
        _host_inventory_entry,
    )
    from .reports import redact_sensitive_text

    if not launcher_path.is_file():
        raise FileNotFoundError(
            "Der lokale Mavi-OpenSSH-Starter fehlt vor der Direktbereitstellung: "
            f"{launcher_path}"
        )

    expected_sha256 = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Der lokale SHA-256 des Mavi-OpenSSH-Starters ist ungültig.")

    local_sha256 = _sha256_file(launcher_path).lower()
    if local_sha256 != expected_sha256:
        raise RuntimeError(
            "SICHERHEITSABBRUCH: Der Mavi-OpenSSH-Starter wurde vor der Direktbereitstellung verändert; "
            f"erwartet={expected_sha256} lokal={local_sha256}"
        )

    _inv, windows, host_data = _host_inventory_entry(project, host)
    connection = _connection_label(windows, host_data)
    if connection not in {"PSRP", "WinRM"}:
        raise PermissionError(
            "Die sichere Direktbereitstellung ist nur über die noch bestehende PSRP/WinRM-Verbindung möglich. "
            f"{host} verwendet derzeit {connection}."
        )

    launcher_name = launcher_path.name
    if re.fullmatch(r"[A-Za-z0-9._-]+", launcher_name) is None:
        raise ValueError("Der Name des Mavi-OpenSSH-Starters enthält unzulässige Zeichen.")

    remote_dir = r"C:\Users\Public\Desktop\Mavi-Bootstrap"
    remote_final_path = remote_dir + "\\" + launcher_name
    remote_stage_path = remote_dir + "\\." + launcher_name + ".new"
    acl_powershell = r'''[CmdletBinding()]
param([string]$Path)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Mavi-Bootstrap-Ordner fehlt: $Path"
}

$acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) {
    [void]$acl.RemoveAccessRuleAll($rule)
}

$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$rules = @(
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inherit,
        $propagation,
        $allow
    )
)
foreach ($rule in $rules) {
    [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
$Ansible.Changed = $true
'''
    powershell = r'''[CmdletBinding()]
param(
    [string]$StagingPath,
    [string]$FinalPath,
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
try {
    if (-not (Test-Path -LiteralPath $StagingPath -PathType Leaf)) {
        throw "Temporärer Mavi-Starter fehlt: $StagingPath"
    }

    $stagingHash = [string](Get-FileHash -LiteralPath $StagingPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $stagingHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des temporären Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$stagingHash"
    }

    if (Test-Path -LiteralPath $FinalPath -PathType Leaf) {
        Remove-Item -LiteralPath $FinalPath -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $StagingPath -Destination $FinalPath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FinalPath -PathType Leaf)) {
        throw "Mavi-Starter konnte nicht auf dem öffentlichen Desktop veröffentlicht werden: $FinalPath"
    }

    $finalHash = [string](Get-FileHash -LiteralPath $FinalPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $finalHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des veröffentlichten Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$finalHash"
    }

    $payload = [ordered]@{
        Path = $FinalPath
        Sha256 = $finalHash.ToLowerInvariant()
    }
    $json = $payload | ConvertTo-Json -Compress
    $marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $Ansible.Result = @{ Marker = $marker }
    $Ansible.Changed = $true
}
catch {
    Remove-Item -LiteralPath $StagingPath -Force -ErrorAction SilentlyContinue
    throw
}
'''
    play = [{
        "name": "Mavi OpenSSH-Starter direkt bereitstellen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Öffentlichen Mavi-Bootstrap-Desktop anlegen",
                "ansible.windows.win_file": {
                    "path": remote_dir,
                    "state": "directory",
                },
            },
            {
                "name": "Mavi-Bootstrap-Desktop gegen unbefugtes Ändern sperren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": acl_powershell,
                    "parameters": {
                        "Path": remote_dir,
                    },
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter temporär kopieren",
                "ansible.windows.win_copy": {
                    "src": str(launcher_path.resolve()),
                    "dest": remote_stage_path,
                    "force": True,
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter prüfen und veröffentlichen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "StagingPath": remote_stage_path,
                        "FinalPath": remote_final_path,
                        "ExpectedSha256": expected_sha256,
                    },
                },
                "register": "mavi_launcher_delivery_verify",
            },
            {
                "name": "Mavi-Starter-Bereitstellung auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_LAUNCHER_DELIVERY_B64={{ mavi_launcher_delivery_verify.result.Marker }}"
                },
            },
        ],
    }]

    playbook_path: Path | None = None
    vault_password_file: Path | None = None
    try:
        fd, raw_playbook = tempfile.mkstemp(prefix=".mavi-ssh-launcher-delivery-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_playbook)
        atomic_write_yaml(playbook_path, play)

        print("  → Mavi-Starter wird über die bestehende PSRP/WinRM-Verbindung auf den öffentlichen Desktop kopiert.")
        vault_password = getpass.getpass("Vault password: ")
        vault_password_file = create_temporary_vault_password_file(vault_password)
        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(playbook_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung des Mavi-Starters hat nach 120 Sekunden nicht geantwortet."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung konnte nicht gestartet werden: "
                f"{redact_sensitive_text(exc)}"
            ) from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(r"Mavi_LAUNCHER_DELIVERY_B64=([A-Za-z0-9+/=]+)", combined)
        if completed.returncode != 0 or not match:
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-10:])
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung auf den öffentlichen Desktop ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )

        try:
            payload = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Die PSRP/WinRM-Bereitstellung lieferte keinen lesbaren SHA-256-Nachweis zurück."
            ) from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Die PSRP/WinRM-Bereitstellung lieferte ein unerwartetes Ergebnis.")

        remote_sha256 = str(payload.get("Sha256", "") or "").strip().lower()
        remote_path = str(payload.get("Path", "") or "").strip()
        if remote_sha256 != expected_sha256:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: SHA-256 des direkt bereitgestellten Mavi-Starters stimmt nicht überein; "
                f"erwartet={expected_sha256} Windows={remote_sha256 or '(leer)'}"
            )
        if remote_path.casefold() != remote_final_path.casefold():
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Mavi-Starter wurde nicht am erwarteten öffentlichen Desktop-Pfad veröffentlicht."
            )
        return remote_path
    finally:
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)


def _publish_https_ssh_bootstrap(
    project: Path,
    *,
    host: str,
    public_key: str,
    msi_raw: str = "",
) -> dict[str, str]:
    from .remote import _certificate_thumbprint_from_der, _safe_host_token
    from .settings import VERSION

    settings = _bootstrap_settings(project)
    webroot: Path = settings["local_dir"]
    safe_host = _safe_host_token(host)
    host_dir = webroot / safe_host
    local_msi: Path | None = None
    if msi_raw:
        local_msi, _, _ = _software_local_and_windows_path(project, msi_raw)
        if local_msi is None or not local_msi.is_file():
            raise FileNotFoundError(
                "Die angegebene OpenSSH-MSI ist auf dem Ansible-Server nicht als Datei erreichbar: "
                f"{msi_raw}"
            )

    try:
        webroot.mkdir(parents=True, exist_ok=True)
        resolved_webroot = webroot.resolve(strict=True)
        host_dir.mkdir(parents=True, exist_ok=True)
        resolved_host_dir = host_dir.resolve(strict=True)
        resolved_host_dir.relative_to(resolved_webroot)
        if resolved_host_dir.parent != resolved_webroot:
            raise PermissionError("Host-Webroot muss ein direkter Unterordner des Bootstrap-Webroots sein.")
        probe_path = host_dir / ".mavi-write-probe"
        _atomic_write_bytes(probe_path, b"write-ok\n", mode=0o600)
        probe_path.unlink()
    except (OSError, ValueError) as exc:
        raise PermissionError(_bootstrap_setup_instruction(project, reason=str(exc))) from exc

    quoted_host = urllib.parse.quote(safe_host, safe="") + "/"
    host_base_url = urllib.parse.urljoin(settings["base_url"], quoted_host)
    ps1_name = f"Mavi-OpenSSH-Setup-{safe_host}.ps1"
    launcher_name = f"START-Mavi-OPENSSH-{safe_host}.cmd"
    msi_name = "OpenSSH-Win64.msi"
    msi_sha256 = ""
    msi_url = ""
    if local_msi is not None:
        msi_destination = host_dir / msi_name
        source_msi_sha256 = _sha256_file(local_msi)
        _atomic_copy_file(local_msi, msi_destination)
        copied_msi_sha256 = _sha256_file(msi_destination)
        if copied_msi_sha256 != source_msi_sha256:
            msi_destination.unlink(missing_ok=True)
            raise RuntimeError(
                "SICHERHEITSABBRUCH: OpenSSH-MSI wurde beim Kopieren verändert; "
                f"Quelle={source_msi_sha256} Ziel={copied_msi_sha256}"
            )
        msi_sha256 = source_msi_sha256
        msi_url = urllib.parse.urljoin(host_base_url, msi_name)

    pki_paths = _bootstrap_pki_paths(project)
    if not pki_paths["system_ca"].is_file():
        raise FileNotFoundError(
            "Die automatisch verwaltete Mavi-CA fehlt. 'mavi-provisioner ssh server-setup' ausführen."
        )
    try:
        ca_pem = pki_paths["system_ca"].read_text(encoding="ascii")
        ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError(f"Das Mavi-CA-Zertifikat ist nicht lesbar: {exc}") from exc
    ca_windows_thumbprint = hashlib.sha1(ca_der, usedforsecurity=False).hexdigest().upper()
    ps1_url = urllib.parse.urljoin(host_base_url, ps1_name)
    ps1_bytes = _ssh_bootstrap_ps1(
        public_key,
        bundled_msi=False,
        msi_download_url=msi_url,
        msi_sha256=msi_sha256,
        expected_signer=settings["expected_signer"],
        ansible_server_ip=settings["ansible_server_ip"],
        bootstrap_instance_id=settings["instance_id"],
        bootstrap_ca_thumbprint=ca_windows_thumbprint,
    ).encode("utf-8-sig")
    ps1_sha256 = hashlib.sha256(ps1_bytes).hexdigest()
    ca_thumbprint = _certificate_thumbprint_from_der(ca_der)
    launcher_bytes = _https_ssh_bootstrap_cmd(
        ps1_url,
        ps1_sha256,
        ca_der=ca_der,
        launcher_id=safe_host,
    ).encode("ascii", errors="strict")

    _atomic_write_bytes(host_dir / ps1_name, ps1_bytes)
    _atomic_write_bytes(host_dir / launcher_name, launcher_bytes)

    launcher_sha256 = hashlib.sha256(launcher_bytes).hexdigest()
    # Der Starter ist absichtlich immer als echte lokale Datei vorhanden. Damit
    # kann er mit `cat <Datei>` angezeigt und manuell in den Mavi-Release-Ordner
    # kopiert werden. Ein schreibgeschützter Install-Mount blockiert die
    # OpenSSH-Vorbereitung nicht und es gibt keinen PSRP-/NTLM-Kopier-Fallback.
    offline_launcher = host_dir / launcher_name
    windows_launcher = ""
    delivery_method = "manual_release_file"
    delivery_note = "Starter lokal erzeugt; manuelle Ablage im Mavi-Release-Ordner vorgesehen."
    software_share_error = ""
    metadata = {
        "version": VERSION,
        "host": host,
        "mode": "fixed_https",
        "created_epoch": time.time(),
        "launcher_url": urllib.parse.urljoin(host_base_url, launcher_name),
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "ca_thumbprint": ca_thumbprint,
        "instance_id": settings["instance_id"],
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "software_share_error": software_share_error,
    }
    _atomic_write_bytes(
        host_dir / ".mavi-bootstrap.json",
        (json.dumps(metadata, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    return {
        "local_dir": str(host_dir),
        "launcher": launcher_name,
        "launcher_url": metadata["launcher_url"],
        "launcher_sha256": launcher_sha256,
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "ca_thumbprint": ca_thumbprint,
        "instance_id": settings["instance_id"],
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "health_url": urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt"),
        "health_body": health_body.decode("ascii"),
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
    }


# Der alte temporäre Share-/HTTP-Bootstrap bleibt vollständig entfernt. Der
# geprüfte Nutzinhalt liegt im festen HTTPS-Webroot. Der All-in-one-Erststarter
# wird immer als lokale Datei erzeugt, damit ein Administrator ihn gezielt in
# einen Mavi-Release-Ordner legen kann. Er enthält nur die öffentliche CA und
# feste Hashes, kopiert sich vor UAC nach TEMP und benötigt im Admin-Kontext
# kein SMB oder WinRM.


def _local_windows_authenticode_status(
    msi_path: Path,
    *,
    expected_signer: str = "",
) -> tuple[str, str]:
    """Best-effort-Diagnose; der Windows-Bootstrap erzwingt die definitive Prüfung."""
    from .reports import redact_sensitive_text

    if os.name != "nt":
        return (
            "DEFERRED",
            "Definitive Windows-Authenticode-Prüfung erfolgt vor msiexec auf dem Ziel-PC.",
        )
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return "UNKNOWN", "Windows PowerShell wurde für die lokale Diagnose nicht gefunden."
    ps_path = _powershell_single_quote(str(msi_path.resolve()))
    script = (
        "$ErrorActionPreference='Stop';"
        f"$s=Get-AuthenticodeSignature -LiteralPath '{ps_path}';"
        "$subject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
        "$simple=if($s.SignerCertificate){[string]$s.SignerCertificate.GetNameInfo("
        "[System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)}else{''};"
        "[pscustomobject]@{Status=[string]$s.Status;Subject=$subject;SimpleName=$simple}|ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "UNKNOWN", redact_sensitive_text(str(exc))
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"Exit-Code {result.returncode}").strip()
        return "UNKNOWN", redact_sensitive_text(detail)
    try:
        data = json.loads(result.stdout.strip())
    except (ValueError, TypeError, json.JSONDecodeError):
        return "UNKNOWN", "Authenticode-Ausgabe war nicht lesbar."
    status = str(data.get("Status", "Unknown") or "Unknown")
    subject = str(data.get("Subject", "") or "")
    simple_name = str(data.get("SimpleName", "") or "")
    if status != "Valid":
        return status, f"Windows Authenticode ist {status}, erwartet wird Valid."
    if expected_signer and expected_signer.casefold() not in {subject.casefold(), simple_name.casefold()}:
        return "SIGNER_MISMATCH", f"Signer ist '{subject or simple_name}', erwartet '{expected_signer}'."
    return "Valid", f"Signer: {subject or simple_name}"


def cmd_ssh_setup_check(args: argparse.Namespace) -> None:
    """Fehlendes Server-Setup automatisch erledigen und danach diagnostizieren."""
    from .environment import ensure_initialized
    from .reports import redact_sensitive_text
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)
    print("\nMavi HTTPS-/OPENSSH-SETUP-CHECK")
    print("================================")
    try:
        settings = _ensure_automatic_https_server(args.project)
    except ValueError as exc:
        print(f"✗ Konfiguration: {redact_sensitive_text(exc)}")
        print(_bootstrap_setup_instruction(args.project, reason=str(exc)))
        raise SystemExit(2)

    print(f"✓ HTTPS-Basis-URL: {settings['base_url']}")
    print(f"✓ Webroot:         {settings['local_dir']}")
    print(f"✓ Ansible-IP:      {settings['ansible_server_ip']}")
    print(f"  Erwarteter MSI-Signer: {settings['expected_signer'] or '(nicht zusätzlich festgelegt)'}")

    webroot: Path = settings["local_dir"]
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    try:
        webroot.mkdir(parents=True, exist_ok=True)
        probe = webroot / ".mavi-setup-write-probe"
        _atomic_write_bytes(probe, b"write-ok\n", mode=0o600)
        probe.unlink()
        _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
        print("✓ Webroot ist schreibbar; Setup-Prüfdatei wurde veröffentlicht.")
    except OSError as exc:
        print(f"✗ Webroot ist nicht schreibbar: {redact_sensitive_text(exc)}")
        print(_bootstrap_setup_instruction(args.project, reason=str(exc)))
        raise SystemExit(2)

    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    https_ok, https_detail = _strict_https_probe(
        health_url,
        expected_body=health_body,
        trusted_ca=_bootstrap_pki_paths(args.project)["system_ca"],
    )
    print(f"{'✓' if https_ok else '✗'} HTTPS/Zertifikat: {redact_sensitive_text(https_detail)}")
    print(f"  Prüf-URL: {health_url}")

    msi_raw = str(getattr(args, "msi", None) or "").strip()
    msi_ok = True
    if msi_raw:
        local_msi, _, _ = _software_local_and_windows_path(args.project, msi_raw)
        if local_msi is None or not local_msi.is_file():
            msi_ok = False
            print(f"✗ MSI: lokal nicht erreichbar: {redact_sensitive_text(msi_raw)}")
        else:
            print(f"✓ MSI-Datei: {local_msi}")
            print(f"✓ MSI SHA-256: {_sha256_file(local_msi)}")
            auth_status, auth_detail = _local_windows_authenticode_status(
                local_msi,
                expected_signer=settings["expected_signer"],
            )
            marker = "✓" if auth_status in {"Valid", "DEFERRED"} else "✗"
            msi_ok = auth_status in {"Valid", "DEFERRED"}
            print(f"{marker} MSI Authenticode: {auth_status} — {redact_sensitive_text(auth_detail)}")
    else:
        print("- MSI: keine angegeben; Bootstrap nutzt Windows Capability/FoD.")

    if not https_ok or not msi_ok:
        print("\nSICHERHEITSABBRUCH: Das Setup ist noch nicht einsatzbereit; es gibt keinen unsicheren Fallback.")
        if not https_ok:
            print(_bootstrap_setup_instruction(args.project, reason=https_detail))
        raise SystemExit(2)
    print("\n✓ HTTPS-Bootstrap-Grundsetup ist einsatzbereit.")


def cmd_ssh_guide(args: argparse.Namespace) -> None:
    from .environment import (
        die,
        ensure_initialized,
    )
    from .execution import shlex_quote
    from .remote import (
        _effective_host_var,
        _host_inventory_entry,
        get_ssh_settings,
    )
    from .reports import redact_sensitive_text

    ensure_initialized(args.project, quiet=True)
    try:
        _ensure_automatic_https_server(args.project)
    except ValueError as exc:
        print("\nSICHERHEITSABBRUCH: Die zentrale HTTPS-Konfiguration ist ungültig.")
        print(redact_sensitive_text(exc))
        raise SystemExit(2)

    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")
    public_key, fingerprint = _public_key_summary(pub_path)

    if not public_key:
        print("\nMavi erzeugt den einmaligen SSH-Automationsschlüssel jetzt selbst.")
        cmd_ssh_keygen(
            argparse.Namespace(
                project=args.project,
                key=str(key_path),
                yes=True,
            )
        )
        public_key, fingerprint = _public_key_summary(pub_path)

    host = str(getattr(args, "host", None) or "WINDOWS").strip()
    host_ip = "<IP-DES-LAPTOPS>"
    ansible_user = r"<DOMÄNE\Provisioning-Admin>"
    if getattr(args, "host", None):
        _inventory, windows, host_data = _host_inventory_entry(args.project, host)
        host_ip = str(host_data.get("ansible_host", "") or host)
        ansible_user = str(
            _effective_host_var(windows, host_data, "ansible_user", ansible_user) or ansible_user
        )

    print("\nMavi OPENSSH-EINRICHTUNG FÜR WINDOWS")
    print("==================================")
    print(f"Host:         {host}")
    print(f"Ziel/IP:      {host_ip}")
    print(f"SSH-Benutzer: {ansible_user}")
    print(f"Private Key:  {key_path}")
    if fingerprint:
        print(f"Fingerprint:  {fingerprint}")
    if not public_key:
        die("Der automatisch erzeugte Mavi-Public-Key konnte nicht gelesen werden.")

    msi_raw = str(getattr(args, "msi", None) or "").strip()
    if bool(getattr(args, "prompt_msi", False)):
        print("\nOPENSSH-INSTALLATIONSQUELLE")
        print("===========================")
        print("Optional die OpenSSH-Win64-*.msi auf der Serverablage angeben.")
        print("Mavi veröffentlicht sie im festen HTTPS-Webroot und speichert ihren SHA-256.")
        print("Die vorhandene Herstellersignatur wird NICHT verändert; Windows verlangt Status Valid.")
        print("Enter = keine MSI, dann nutzt das Setup Windows Capability/FoD.")
        msi_raw = input("Pfad zur OpenSSH-Win64-*.msi [optional]: ").strip()

    try:
        package = _publish_https_ssh_bootstrap(
            args.project,
            host=host,
            public_key=public_key,
            msi_raw=msi_raw,
        )
    except (ValueError, FileNotFoundError, PermissionError, OSError, RuntimeError) as exc:
        print("\nSICHERHEITSABBRUCH: Die Vollautomatik konnte den Bootstrap nicht sicher veröffentlichen.")
        detail = redact_sensitive_text(exc)
        print(detail)
        raise SystemExit(2)

    trusted_ca = _bootstrap_pki_paths(args.project)["system_ca"]
    health_ok, health_detail = _strict_https_probe(
        package["health_url"],
        expected_body=package["health_body"].encode("ascii"),
        trusted_ca=trusted_ca,
    )
    launcher_path = Path(package["local_dir"]) / package["launcher"]
    launcher_ok, launcher_detail = _strict_https_probe(
        package["launcher_url"],
        expected_body=launcher_path.read_bytes(),
        trusted_ca=trusted_ca,
    )
    if not health_ok or not launcher_ok:
        failed_detail = health_detail if not health_ok else launcher_detail
        print("\nSICHERHEITSABBRUCH: HTTPS/Zertifikat oder veröffentlichter Inhalt ist nicht gültig.")
        print(_bootstrap_setup_instruction(args.project, reason=failed_detail))
        raise SystemExit(2)

    print("\n✓ Mavi OPENSSH-VOLLAUTOMATIK BEREIT")
    print("==================================")
    print("Starter-Datei:  " + package["offline_launcher"])
    print("Anzeigen:       cat " + shlex_quote(package["offline_launcher"]))
    print("Ablage:         Diese Datei einmal manuell in den Mavi-Release-Ordner kopieren.")
    print(f"HTTPS intern:   {package['launcher_url']}")
    print(f"Webroot:        {package['local_dir']}")
    print(f"Launcher SHA:   {package['launcher_sha256']}")
    print(f"Mavi-CA SHA:     {package['ca_der_sha256']} (im Starter fest eingebettet)")
    print(f"PS1 SHA-256:    {package['ps1_sha256']} (wird vor Ausführung geprüft)")
    print(f"Ansible-IP:     {package['ansible_server_ip']} (einzige erlaubte Quelle für TCP/22)")
    if package["msi_url"]:
        print(f"MSI über HTTPS: {package['msi_url']}")
        print(f"MSI SHA-256:    {package['msi_sha256']} (wird vor msiexec geprüft)")
        print(f"MSI Signatur:   Windows Authenticode muss Valid sein; Signer: {package['expected_signer'] or 'beliebiger gültiger Signer'}")
    else:
        print("MSI:             keine; Windows Capability/FoD wird verwendet.")

    print("\nAuf dem Laptop sind nur zwei Klicks nötig, nachdem die Datei im Release-Ordner liegt:")
    print(f"  1) {package['launcher']} doppelklicken")
    print("  2) UAC mit Ja bestätigen; CA, HTTPS und OpenSSH macht Mavi selbst")
    print("\nKein nginx-Setup, kein Zertifikatsimport und keine PSRP-/WinRM-Dateiverteilung.")
    print("Zertifikatsprüfung bleibt aktiv. Es gibt weder HTTP- noch Copy-Paste-Fallback.")
    print("Der private SSH-Key bleibt ausschließlich auf dem Ansible-Server.")
    print("sshd bleibt installiert und aktiv; nur die Mavi-Key-Entfernen-Funktion entfernt Keys.")
    print("\nDanach in Mavi: PC auf OpenSSH umstellen und Verbindung testen (win_ping).")

def cmd_ssh_use(args: argparse.Namespace) -> None:
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_ssh_transport,
        _effective_host_var,
        _host_inventory_entry,
        get_ssh_settings,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    settings = get_ssh_settings(args.project)
    key_path = Path(getattr(args, "key", None) or settings["private_key"]).expanduser().resolve()
    port = int(getattr(args, "port", None) or settings["port"] or 22)

    pub_path = Path(str(key_path) + ".pub")
    if not key_path.exists():
        die(
            f"SSH-Private-Key fehlt: {key_path}\n"
            "Zuerst 'mavi-provisioner ssh keygen' ausführen."
        )
    if not pub_path.exists():
        die(f"SSH-Public-Key fehlt: {pub_path}")

    target_host = str(host_data.get("ansible_host", "") or args.host)
    ensure_ssh_host_key(
        args.project,
        target_host,
        port=port,
        yes=bool(getattr(args, "yes", False)),
    )

    core_version = _parse_ansible_core_version()
    if core_version is not None and core_version < (2, 18, 0):
        print(
            f"! Hinweis: Ansible Core {'.'.join(map(str, core_version))} erkannt. "
            "Windows über SSH ist offiziell erst ab Ansible Core 2.18 unterstützt."
        )

    _apply_ssh_transport(args.project, host_data, key_path=key_path, port=port)
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    user = _effective_host_var(windows, host_data, "ansible_user", "(geerbt)")
    print(f"✓ {args.host} auf OpenSSH umgestellt.")
    print(f"  Verbindung: ssh:{port}")
    print("  Shell:      powershell")
    print(f"  Benutzer:   {user}")
    print(f"  Key:        {key_path}")
    print(f"  known_hosts:{Path(settings['known_hosts']).expanduser().resolve()}")
    print("  Auth:       SSH-Key only (geerbtes PSRP-Passwort für SSH deaktiviert)")
    print("\nJetzt testen mit:")
    print(f"  mavi-provisioner ping {args.host}")


def cmd_ssh_winrm_https(args: argparse.Namespace) -> None:
    """WinRM ausschließlich aus einer bestehenden Mavi-SSH-Key-Sitzung heraus härten."""

    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .execution import create_temporary_vault_password_file
    from .remote import (
        _apply_psrp_https_transport,
        _bootstrap_ca_probe_play,
        _certificate_thumbprint_from_file,
        _effective_host_var,
        _ensure_psrp_kerberos_controller_dependencies,
        _extract_bootstrap_ca_probe_result,
        _extract_winrm_csr,
        _extract_winrm_https_install_result,
        _host_inventory_entry,
        _is_missing_gssapi_failure,
        _issue_winrm_server_certificate,
        _kerberos_principal_for_host,
        _prepare_kerberos_runtime_config,
        _psrp_https_inventory_vars,
        _remember_winrm_https_state,
        _remove_host_winrm_certificate_artifacts,
        _run_winrm_temporary_play,
        _utc_now_iso,
        _vault_ansible_user_for_host,
        _winrm_csr_play,
        _winrm_https_settings,
        _winrm_https_target_identity,
        _winrm_install_https_play,
        _winrm_kerberos_https_ping_play,
    )
    from .reports import redact_sensitive_text
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    connection = str(_effective_host_var(windows, host_data, "ansible_connection", "") or "").lower()
    if connection != "ssh":
        die(
            f"{args.host} ist nicht per OpenSSH konfiguriert. Mavi führt die WinRM-Härtung "
            "ausschließlich über die bestehende SSH-Key-Verbindung aus; HTTP/NTLM wird nicht verwendet."
        )

    try:
        bootstrap = _bootstrap_settings(args.project)
        (
            current_bootstrap_thumbprint,
            controller_bootstrap_certificates,
        ) = _controller_bound_bootstrap_root_certificates(project=args.project)
        current_bootstrap_certificate = controller_bootstrap_certificates[
            current_bootstrap_thumbprint
        ]
        current_bootstrap_ca_sha256 = hashlib.sha256(
            base64.b64decode(current_bootstrap_certificate, validate=True)
        ).hexdigest()
        bootstrap_probe_candidates = list(
            controller_bootstrap_certificates.values()
        )
        settings = _winrm_https_settings(args.project)
        identity = _winrm_https_target_identity(args.host, host_data, settings)
        _, kdc_endpoints = _prepare_kerberos_runtime_config(args.project, settings)
    except (OSError, ValueError, RuntimeError) as exc:
        die(f"WinRM-HTTPS-Konfiguration ist nicht sicher verwendbar: {exc}")

    try:
        _ensure_psrp_kerberos_controller_dependencies()
    except (OSError, RuntimeError, ValueError) as exc:
        die(f"Kerberos-Abhängigkeiten auf dem Ansible-Server konnten nicht eingerichtet werden: {exc}")

    vault_password = getpass.getpass("Vault password: ")
    try:
        vault_file = create_temporary_vault_password_file(vault_password)
    except OSError as exc:
        die(f"Temporäre Vault-Datei konnte nicht sicher angelegt werden: {exc}")

    try:
        try:
            kerberos_principal = _kerberos_principal_for_host(windows, host_data, settings)
        except ValueError as principal_error:
            # ansible_user kann korrekt ausschließlich im verschlüsselten
            # group_vars-Vault liegen. Erst nach dessen Entschlüsselung darf
            # Mavi daraus die UPN erzeugen; ein erfundenes Konto ist verboten.
            vault_ansible_user = _vault_ansible_user_for_host(
                args.project, args.host, vault_file
            )
            try:
                kerberos_principal = _kerberos_principal_for_host(
                    windows,
                    host_data,
                    settings,
                    vault_ansible_user=vault_ansible_user,
                )
            except ValueError:
                raise principal_error

        print("\nMavi WINRM HTTPS + KERBEROS-ONLY")
        print("================================")
        print(f"Host:              {args.host}")
        print(f"SSH-Umbaukanal:    {host_data.get('ansible_host', args.host)}")
        print(f"WinRM-FQDN:        {identity['fqdn']}")
        print("PSRP-Endzustand:   HTTPS:5986 / Zertifikatsprüfung / Kerberos-only")
        print(f"Kerberos-Principal:{kerberos_principal}")
        print(f"KDC-Bindung:       {', '.join(kdc_endpoints)} (direkt aus AD-DNS)")
        print(f"TCP/5986 nur von:  {bootstrap['ansible_server_ip']}")
        print("HTTP/5985:         wird per SSH entfernt; es gibt keinen NTLM-Rückweg.")

        bootstrap_probe_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_bootstrap_ca_probe_play(
                current_root_certificate_der_base64=current_bootstrap_certificate,
                candidate_root_certificates_der_base64=bootstrap_probe_candidates,
            ),
            vault_password_file=vault_file,
            description="Hostgebundener Bootstrap-CA-Nachweis über SSH",
        )
        bootstrap_probe_result = _extract_bootstrap_ca_probe_result(
            bootstrap_probe_output
        )
        if bootstrap_probe_result["current_root_thumbprint"] != current_bootstrap_thumbprint:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Zielhost bestätigt nicht die aktuell veröffentlichte "
                "Mavi-Bootstrap-CA."
            )
        unexpected_bootstrap_roots = set(
            bootstrap_probe_result["present_root_thumbprints"]
        ) - set(controller_bootstrap_certificates)
        if unexpected_bootstrap_roots:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Zielhost meldet eine Bootstrap-CA, die nicht "
                "durch DER-Material auf dem Controller gebunden ist."
            )

        request_id = secrets.token_hex(16)
        csr_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_csr_play(identity=identity, request_id=request_id),
            vault_password_file=vault_file,
            description="WinRM-CSR-Erzeugung über SSH",
        )
        csr_pem = _extract_winrm_csr(csr_output)
        issued = _issue_winrm_server_certificate(
            args.project,
            host=args.host,
            identity=identity,
            csr_pem=csr_pem,
        )
        install_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_install_https_play(
                certificate_path=str(issued["cert_der"]),
                certificate_sha256=str(issued["cert_sha256"]),
                ca_certificate_path=str(issued["ca_der"]),
                ca_certificate_sha256=str(issued["ca_der_sha256"]),
                identity=identity,
                settings=settings,
                ansible_server_ip=bootstrap["ansible_server_ip"],
            ),
            vault_password_file=vault_file,
            description="WinRM-HTTPS-Installation über SSH",
        )
        install_result = _extract_winrm_https_install_result(install_output)
        expected_root_thumbprint = _certificate_thumbprint_from_file(Path(issued["ca_der"]))
        if not secrets.compare_digest(
            install_result["certificate_sha256"],
            str(issued["cert_sha256"]).strip().lower(),
        ):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Windows-Abschlussbeleg gehört nicht zum gerade signierten "
                "Mavi-WinRM-Serverzertifikat."
            )
        if (
            install_result["fqdn"] != str(identity["fqdn"]).lower()
            or install_result["port"] != int(settings["port"])
            or install_result["root_thumbprint"] != expected_root_thumbprint
        ):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Windows-Abschlussbeleg stimmt nicht mit dem erwarteten "
                "Mavi-WinRM-Endpunkt bzw. der Mavi-Root-CA überein."
            )

        # HTTP/5985 wird bereits innerhalb derselben abgeschotteten Windows-
        # Transaktion entfernt, bevor Negotiate endgültig deaktiviert wird.
        # Ein nachträglicher WSMan:\localhost-Aufruf wäre bei Kerberos-only
        # absichtlich nicht mehr möglich.
        secure_vars = _psrp_https_inventory_vars(
            settings,
            fqdn=identity["fqdn"],
            ca_cert=Path(issued["ca_cert"]),
        )
        secure_vars["ansible_user"] = kerberos_principal
        try:
            _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_winrm_kerberos_https_ping_play(),
                vault_password_file=vault_file,
                description="Erster Kerberos-HTTPS-Nachweis",
                extra_vars=secure_vars,
                use_vault_kerberos_ticket=True,
                kerberos_principal=kerberos_principal,
                kerberos_target_fqdn=identity["fqdn"],
            )
        except RuntimeError as first_probe_error:
            if not _is_missing_gssapi_failure(first_probe_error):
                raise
            print(
                "\n! GSSAPI fehlt im tatsächlichen Ansible-Worker; Mavi repariert "
                "die pipx-Umgebung und wiederholt den Nachweis einmalig."
            )
            _ensure_psrp_kerberos_controller_dependencies(force_pipx_inject=True)
            _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_winrm_kerberos_https_ping_play(),
                vault_password_file=vault_file,
                description="Erster Kerberos-HTTPS-Nachweis nach GSSAPI-Reparatur",
                extra_vars=secure_vars,
                use_vault_kerberos_ticket=True,
                kerberos_principal=kerberos_principal,
                kerberos_target_fqdn=identity["fqdn"],
            )
        _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_kerberos_https_ping_play(),
            vault_password_file=vault_file,
            description="Zweiter Kerberos-HTTPS-Nachweis",
            extra_vars=secure_vars,
            use_vault_kerberos_ticket=True,
            kerberos_principal=kerberos_principal,
            kerberos_target_fqdn=identity["fqdn"],
        )
        removed_controller_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts(
            args.project,
            args.host,
            keep_request_id=str(issued["request_id"]),
            known_hosts=(windows.get("hosts", {}) or {}).keys(),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nSICHERHEITSABBRUCH: WinRM wurde nicht als Mavi-Transport übernommen.")
        print(redact_sensitive_text(exc))
        print("Der Inventory-Host bleibt auf SSH. HTTP/5985 wird von Mavi nicht erneut aktiviert.")
        raise SystemExit(2)
    finally:
        vault_file.unlink(missing_ok=True)

    # Erst die direkte Windows-Abfrage über die funktionierende SSH-Sitzung
    # bindet Bootstrap-Identitäten an diesen Host. Frühere, nur aufgrund von
    # Webserver-Probes erzeugte v1-Einträge werden dabei nicht blind vertraut;
    # sie wandern nur dann in die Historie, wenn Windows sie exakt bestätigt.
    host_data["mavi_bootstrap"] = {
        "version": 2,
        "remote_verified": True,
        "instance_id": bootstrap["instance_id"],
        "root_thumbprint": bootstrap_probe_result["current_root_thumbprint"],
        "root_thumbprints": bootstrap_probe_result["present_root_thumbprints"],
        "ca_sha256": current_bootstrap_ca_sha256,
        "verified_at": _utc_now_iso(),
    }
    _remember_winrm_https_state(
        host_data,
        settings=settings,
        fqdn=identity["fqdn"],
        ca_cert=Path(issued["ca_cert"]),
        kerberos_principal=kerberos_principal,
        certificate_thumbprint=install_result["thumbprint"],
        certificate_not_after=install_result["certificate_not_after"],
        root_thumbprint=install_result["root_thumbprint"],
        root_not_after=install_result["root_not_after"],
        pruned_server_certificates=install_result["pruned_server_certificates"],
    )
    _apply_psrp_https_transport(
        host_data,
        settings=settings,
        fqdn=identity["fqdn"],
        ca_cert=Path(issued["ca_cert"]),
        kerberos_principal=kerberos_principal,
    )
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    print("\n✓ WinRM-HTTPS/Kerberos-only ist einsatzbereit.")
    print("  HTTP/5985:        entfernt und zugehörige TCP/5985-Freigaben deaktiviert")
    print("  PSRP:             HTTPS:5986, Zertifikat validiert, Kerberos-only")
    print(f"  Inventory-Host:   {args.host} wurde dauerhaft auf sicheren PSRP umgestellt")
    print(f"  SSH:              bleibt installiert und aktiv als separater Verwaltungsweg")
    print(f"  Leaf-Thumbprint:  {install_result['thumbprint']}")
    print(f"  Leaf-Ablauf:      {install_result['certificate_not_after']}")
    print(f"  Alte Leaf-Zertifikate auf Windows: {install_result['pruned_server_certificates']} entfernt")
    print(f"  Alte Host-PKI-Dateien auf Controller: {removed_controller_artifacts} entfernt")
    for warning in artifact_warnings:
        print(f"! {warning}")


def _winrm_reset_root_identity(
    winrm_state: Any,
    *,
    ca_cert: Path,
    ca_der: Path,
) -> tuple[str, str]:
    """Exakte Root-Identität für den Rückbau bestimmen, v1-Hashes inklusive."""
    from .remote import (
        _certificate_der_base64_from_file,
        _certificate_thumbprint_from_file,
        _normalized_certificate_thumbprint,
    )

    state = winrm_state if isinstance(winrm_state, dict) else None
    stored_root_thumbprint = (
        _normalized_certificate_thumbprint(state.get("root_thumbprint"))
        if state is not None
        else ""
    )
    if not ca_der.is_file():
        if stored_root_thumbprint:
            raise ValueError(
                "Für die gespeicherte Mavi-WinRM-Root fehlt das controllerseitige DER; "
                "ein Inventory-Thumbprint allein ist keine Löschberechtigung."
            )
        return "", ""

    controller_root_thumbprint = _certificate_thumbprint_from_file(ca_der)
    if stored_root_thumbprint and controller_root_thumbprint != stored_root_thumbprint:
        raise ValueError(
            "Die gespeicherte historische Mavi-WinRM-Root stimmt nicht mit dem "
            "controllerseitigen DER überein; ein Thumbprint allein darf keine Root löschen."
        )

    if state is not None and not stored_root_thumbprint:
        # v1 kannte noch keinen Root-Thumbprint. Sein Hash bezog sich auf die
        # PEM-Datei der Controller-CA. Nur ein exakter Hash-Treffer darf diese
        # alte Aufzeichnung auf die heutige Thumbprint-Identität hochstufen.
        expected_hash = str(state.get("ca_sha256", "") or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or not ca_cert.is_file():
            raise ValueError(
                "Der alte Mavi-WinRM-Status enthält keine prüfbare Root-CA-Identität; "
                "der sichere Rückbau wird verweigert."
            )
        actual_hash = _sha256_file(ca_cert).lower()
        if not secrets.compare_digest(expected_hash, actual_hash):
            raise ValueError(
                "Die lokale Mavi-WinRM-CA stimmt nicht mit dem gespeicherten v1-CA-Hash "
                "dieses Hosts überein; der sichere Rückbau wird verweigert."
            )
        if _certificate_thumbprint_from_file(ca_cert) != controller_root_thumbprint:
            raise ValueError(
                "PEM- und DER-Datei der lokalen Mavi-WinRM-CA bezeichnen nicht dieselbe Root; "
                "der sichere Rückbau wird verweigert."
            )

    return (
        controller_root_thumbprint,
        _certificate_der_base64_from_file(ca_der),
    )


def _winrm_leaf_fqdn_for_host(
    project: Path,
    host: str,
    host_data: dict[str, Any],
) -> str:
    """Den hostgebundenen FQDN für Mavi-WinRM-Leaves bestimmen.

    Ein gespeicherter, bereits geprüfter Endpunkt hat beim Rückbau Vorrang:
    Eine zwischenzeitlich geänderte globale Domänenkonfiguration darf den
    Lösch-Scope nicht auf einen anderen Hostnamen verschieben.
    """
    from .remote import (
        _normalize_winrm_dns_name,
        _winrm_https_settings,
        _winrm_https_target_identity,
    )

    state = host_data.get("mavi_winrm_https")
    if isinstance(state, dict):
        saved_fqdn = str(state.get("fqdn", "") or "").strip()
        if saved_fqdn:
            return _normalize_winrm_dns_name(
                saved_fqdn,
                label="gespeicherter WinRM-FQDN",
            )

    settings = _winrm_https_settings(project)
    identity = _winrm_https_target_identity(host, host_data, settings)
    return str(identity["fqdn"])


def _bootstrap_state_thumbprints(state: Any) -> tuple[str, ...]:
    """Exakte, deduplizierte Thumbprints aus einem Bootstrap-Status lesen."""
    from .remote import _normalized_certificate_thumbprint

    if not isinstance(state, dict):
        return ()
    raw_values = state.get("root_thumbprints")
    if not isinstance(raw_values, list):
        raw_values = []
    values = [state.get("root_thumbprint"), *raw_values]
    normalized: list[str] = []
    for value in values:
        thumbprint = _normalized_certificate_thumbprint(value)
        if thumbprint and thumbprint not in normalized:
            normalized.append(thumbprint)
    return tuple(normalized)


def _verified_bootstrap_root_thumbprints(host_data: dict[str, Any]) -> tuple[str, ...]:
    """Nur vom Zielhost selbst bestätigte Bootstrap-Identitäten akzeptieren."""
    state = host_data.get("mavi_bootstrap")
    if not isinstance(state, dict):
        return ()
    try:
        version = int(state.get("version", 1))
    except (TypeError, ValueError):
        version = 1
    if version < 2 or state.get("remote_verified") is not True:
        return ()
    return _bootstrap_state_thumbprints(state)


def cmd_ssh_winrm_reset(args: argparse.Namespace) -> None:
    """WinRM auf Stand 0 setzen und OpenSSH auf Wunsch als letzten Kanal abschalten."""

    from .catalogs import yes_no
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .execution import create_temporary_vault_password_file
    from .remote import (
        _apply_remote_management_disabled_transport,
        _apply_ssh_transport,
        _bootstrap_ca_probe_play,
        _effective_host_var,
        _extract_bootstrap_ca_probe_result,
        _extract_winrm_reset_result,
        _host_inventory_entry,
        _remove_host_bootstrap_artifacts,
        _remove_host_winrm_certificate_artifacts,
        _run_winrm_temporary_play,
        _ssh_environment_marker,
        _utc_now_iso,
        _winrm_pki_paths,
        _winrm_reset_play,
        get_ssh_settings,
    )
    from .reports import redact_sensitive_text
    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    disable_openssh = bool(getattr(args, "disable_openssh", False))
    had_winrm_https_state = isinstance(host_data.get("mavi_winrm_https"), dict)
    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "") or ""
    ).lower()

    if not bool(getattr(args, "yes", False)):
        print("\nMavi REMOTE-VERWALTUNG ZURÜCKSETZEN")
        print("====================================")
        print(f"PC:       {args.host}")
        print("WinRM:    nur eindeutig Mavi-Listener, -Regeln, -Zertifikate und Arbeitsdateien entfernen")
        print("           Dienst anschließend stoppen und deaktivieren")
        if disable_openssh:
            print("OpenSSH:  Mavi-Key entfernen, Mavi-Firewallregel entfernen, sshd stoppen/deaktivieren")
            print("CA:       Mavi Bootstrap Root CA nur bei bytegleichem Controller-DER entfernen")
            print("! Danach gibt es keinen Mavi-Fernzugang mehr. Neueinrichtung nur lokal per Starter.")
        else:
            print("OpenSSH:  bleibt als sofortiger Weg für eine neue WinRM-Einrichtung aktiv")
        if not yes_no("Diesen Stand-0-Rückbau wirklich ausführen?", default=False):
            print("Abgebrochen.")
            return

    requested_key = getattr(args, "key", None)
    requested_port = getattr(args, "port", None)
    if connection != "ssh" and not str(requested_key or "").strip():
        remembered_key = str(
            host_data.get("mavi_ssh_private_key_file", "") or ""
        ).strip()
        if remembered_key:
            requested_key = remembered_key
    if connection != "ssh" and requested_port is None:
        remembered_port = host_data.get("mavi_ssh_port")
        try:
            remembered_port = int(remembered_port)
        except (TypeError, ValueError):
            remembered_port = 0
        if not 1 <= remembered_port <= 65535:
            die(
                f"Für den bestehenden PSRP-/WinRM-Host {args.host} ist kein verlässlicher "
                "historischer SSH-Port gespeichert. Bitte den tatsächlich erreichbaren Port "
                "einmal explizit mit --port angeben; Mavi rät nicht den globalen Standard: "
                f"mavi-provisioner ssh winrm-reset {args.host} --port PORT"
            )
        requested_port = remembered_port
    if connection != "ssh" or requested_key is not None or requested_port is not None:
        resolved_port = requested_port
        if resolved_port is None:
            resolved_port = _ssh_host_key_port(
                windows,
                host_data,
                get_ssh_settings(args.project)["port"],
            )
        if connection != "ssh":
            print(f"\n{args.host} wird zuerst über den vorhandenen Mavi-Key auf OpenSSH umgestellt.")
        cmd_ssh_use(
            argparse.Namespace(
                project=args.project,
                host=args.host,
                key=requested_key,
                port=resolved_port,
                yes=bool(getattr(args, "yes", False)),
            )
        )
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)

    reset_public_key_prefix = ""
    reset_key_marker = ""
    openssh_firewall_rule = ""
    openssh_config_backup = ""
    bootstrap_root_thumbprints: tuple[str, ...] = ()
    bootstrap_root_certificates: tuple[str, ...] = ()
    bootstrap_probe_current_certificate = ""
    bootstrap_probe_candidates: tuple[str, ...] = ()
    controller_bootstrap_certificates: dict[str, str] = {}
    current_bootstrap_thumbprint = ""
    if disable_openssh:
        try:
            (
                current_bootstrap_thumbprint,
                controller_bootstrap_certificates,
            ) = _controller_bound_bootstrap_root_certificates(project=args.project)
        except (OSError, ValueError) as exc:
            die(
                "Für den vollständigen Rückbau ist kein vertrauenswürdiger controllerseitiger "
                "Bootstrap-CA-Satz verfügbar: " + redact_sensitive_text(exc)
            )
        bootstrap_probe_current_certificate = controller_bootstrap_certificates[
            current_bootstrap_thumbprint
        ]
        bootstrap_probe_candidates = tuple(
            controller_bootstrap_certificates.values()
        )
        stored_bootstrap_thumbprints = _bootstrap_state_thumbprints(
            host_data.get("mavi_bootstrap")
        )
        verified_bootstrap_thumbprints = _verified_bootstrap_root_thumbprints(
            host_data
        )
        if (
            stored_bootstrap_thumbprints
            and verified_bootstrap_thumbprints != stored_bootstrap_thumbprints
        ):
            die(
                "Der gespeicherte Bootstrap-CA-Verlauf ist nicht als v2-Remote-Nachweis "
                "verifiziert und kann keinen vollständigen Lösch-Scope belegen."
            )
        unbound_bootstrap_thumbprints = set(
            verified_bootstrap_thumbprints
        ) - set(controller_bootstrap_certificates)
        if unbound_bootstrap_thumbprints:
            die(
                "Für mindestens eine vom Host bestätigte historische Bootstrap-CA fehlt "
                "das exakte DER im root-kontrollierten Controller-Archiv; Option 11 "
                "schreibt deshalb keinen unvollständigen Rückbau-Nachweis."
            )

    if disable_openssh:
        active_key_path = _ssh_private_key_path_for_host(
            args.project,
            windows,
            host_data,
        )
        reset_public_key_prefix = _public_key_prefix_for_private_key(active_key_path)
        if not reset_public_key_prefix:
            die(
                "Der aktive SSH-Public-Key kann weder aus der Companion-.pub-Datei "
                "gelesen noch mit ssh-keygen -y aus dem privaten Key abgeleitet werden. "
                "Der vollständige Remote-Rückbau wird ohne exakte Key-Identität nicht attestiert."
            )
        reset_key_marker = _ssh_environment_marker(args.project)
        try:
            openssh_artifact_instance_id = _openssh_artifact_instance_id(
                args.project,
                host_data,
            )
            openssh_firewall_rule = _openssh_firewall_rule_name(
                args.project,
                instance_id=openssh_artifact_instance_id,
            )
            openssh_config_backup = _openssh_config_backup_relative_path(
                args.project,
                instance_id=openssh_artifact_instance_id,
            )
        except ValueError as exc:
            die(
                "Der vollständige Rückbau kann den instanzgebundenen Mavi-OpenSSH-Scope "
                "nicht sicher bestimmen: " + redact_sensitive_text(exc)
            )

    winrm_state = host_data.get("mavi_winrm_https")
    pki_paths = _winrm_pki_paths(args.project)
    try:
        root_thumbprint, root_certificate_der_base64 = _winrm_reset_root_identity(
            winrm_state,
            ca_cert=pki_paths["ca_cert"],
            ca_der=pki_paths["ca_der"],
        )
    except (OSError, ValueError) as exc:
        die(
            "Die lokale Mavi-WinRM-CA konnte nicht sicher dem gespeicherten Host-Status "
            f"zugeordnet werden: {redact_sensitive_text(exc)}"
        )
    if had_winrm_https_state and not root_thumbprint:
        die(
            "Die zu diesem PC gespeicherte Mavi-WinRM-Verwaltung kann ohne die exakte "
            "Mavi-WinRM-Root-CA nicht sicher zurückgebaut werden. "
            "Mavi rät hier weder per Subject noch löscht es pauschal Zertifikate."
        )
    if disable_openssh and not root_thumbprint:
        die(
            "Der vollständige Option-11-Rückbau benötigt die exakte Mavi-WinRM-Root-Identität. "
            "Ein leerer WinRM-Listener-Bestand beweist nicht, dass keine verwaisten Mavi-"
            "Zertifikate mehr vorhanden sind; deshalb wird kein v3-Vollnachweis erzeugt."
        )
    expected_winrm_fqdn = ""
    if root_thumbprint:
        try:
            expected_winrm_fqdn = _winrm_leaf_fqdn_for_host(
                args.project,
                args.host,
                host_data,
            )
        except (OSError, ValueError) as exc:
            die(
                "Der Mavi-WinRM-Ziel-FQDN für den Zertifikats-Rückbau ist nicht "
                f"verlässlich bestimmbar: {redact_sensitive_text(exc)}"
            )

    vault_file: Path | None = None
    vault_password = getpass.getpass("Vault password: ")
    try:
        vault_file = create_temporary_vault_password_file(vault_password)
    except OSError as exc:
        die(f"Temporäre Vault-Datei konnte nicht sicher angelegt werden: {exc}")
    finally:
        vault_password = ""

    try:
        print("\nRückbau läuft über OpenSSH; das Ergebnis erscheint nach Abschluss (maximal 180 Sekunden).")
        if disable_openssh:
            bootstrap_probe_output = _run_winrm_temporary_play(
                args.project,
                host=args.host,
                play=_bootstrap_ca_probe_play(
                    current_root_certificate_der_base64=(
                        bootstrap_probe_current_certificate
                    ),
                    candidate_root_certificates_der_base64=list(
                        bootstrap_probe_candidates
                    ),
                    require_current_root=False,
                ),
                vault_password_file=vault_file,
                description="Live-Nachweis des Bootstrap-Lösch-Scope über SSH",
            )
            bootstrap_probe_result = _extract_bootstrap_ca_probe_result(
                bootstrap_probe_output,
                require_current_root=False,
            )
            if (
                bootstrap_probe_result["current_root_thumbprint"]
                != current_bootstrap_thumbprint
            ):
                raise RuntimeError(
                    "Der Bootstrap-Nachweis gehört nicht zur aktuellen controllerseitigen CA."
                )
            bootstrap_root_thumbprints = tuple(
                bootstrap_probe_result["present_root_thumbprints"]
            )
            unexpected_bootstrap_roots = set(bootstrap_root_thumbprints) - set(
                controller_bootstrap_certificates
            )
            if unexpected_bootstrap_roots:
                raise RuntimeError(
                    "Der Bootstrap-Nachweis enthält eine nicht durch Controller-DER "
                    "gebundene Root-CA."
                )
            bootstrap_root_certificates = tuple(
                controller_bootstrap_certificates[thumbprint]
                for thumbprint in bootstrap_root_thumbprints
            )
        reset_output = _run_winrm_temporary_play(
            args.project,
            host=args.host,
            play=_winrm_reset_play(
                root_thumbprint=root_thumbprint,
                root_certificate_der_base64=root_certificate_der_base64,
                expected_fqdn=expected_winrm_fqdn,
                bootstrap_root_certificates_der_base64=list(
                    bootstrap_root_certificates
                ),
                disable_openssh=disable_openssh,
                public_key_prefix=reset_public_key_prefix,
                key_marker=reset_key_marker,
                openssh_firewall_rule=openssh_firewall_rule,
                openssh_config_backup=openssh_config_backup,
            ),
            vault_password_file=vault_file,
            description=(
                "WinRM/Kerberos- und OpenSSH-Rückbau über SSH"
                if disable_openssh
                else "WinRM/Kerberos-Stand-0-Rückbau über SSH"
            ),
            timeout=180.0,
        )
        reset_result = _extract_winrm_reset_result(reset_output)
        if root_thumbprint and reset_result["winrm_root_thumbprint"] != root_thumbprint:
            raise RuntimeError(
                "Der Mavi-Rückbau-Nachweis bestätigt nicht die erwartete Mavi-WinRM-Root-CA."
            )
        if disable_openssh:
            if (
                tuple(reset_result["bootstrap_root_thumbprints"])
                != bootstrap_root_thumbprints
                or not reset_result["bootstrap_scope_verified"]
                or not reset_result["openssh_startup_disabled"]
                or not reset_result["openssh_disable_scheduled"]
                or not reset_result["openssh_stopped_verified"]
                or reset_result["openssh_state"].casefold() != "stopped"
                or reset_result["openssh_start_mode"].casefold() != "disabled"
                or not reset_result["winrm_scope_verified"]
                or not reset_result["winrm_listeners_cleared"]
            ):
                raise RuntimeError(
                    "Der Mavi-Rückbau-Nachweis bestätigt Bootstrap-CA, leeren WinRM-Listener-"
                    "Bestand oder den gestoppten/deaktivierten sshd nicht vollständig."
                )
    except (OSError, RuntimeError, ValueError) as exc:
        print("\nFEHLER: Der Remote-Rückbau wurde nicht vollständig bestätigt.")
        print(redact_sensitive_text(exc))
        print(f"Der Inventory-Host {args.host} bleibt für die Reparatur auf OpenSSH eingestellt.")
        raise SystemExit(2)
    finally:
        if vault_file is not None:
            vault_file.unlink(missing_ok=True)

    removed_artifacts, artifact_warnings = _remove_host_winrm_certificate_artifacts(
        args.project,
        args.host,
        known_hosts=(windows.get("hosts", {}) or {}).keys(),
    )
    removed_bootstrap_artifacts = 0
    bootstrap_artifact_warnings: list[str] = []
    if disable_openssh:
        removed_bootstrap_artifacts, bootstrap_artifact_warnings = _remove_host_bootstrap_artifacts(
            args.project,
            args.host,
            known_hosts=(windows.get("hosts", {}) or {}).keys(),
        )

    # Der Inventory-Nachweis wird bewusst erst nach dem vollständigen Remote-
    # Ergebnis und den ausschließlich hostbezogenen Controller-Bereinigungen
    # geschrieben. Ein unterbrochener Rückbau erhält daher nie den Status
    # "vollständig aus".
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    current_key_raw = str(
        _effective_host_var(windows, host_data, "ansible_ssh_private_key_file", "") or ""
    ).strip()
    current_port_raw = _effective_host_var(windows, host_data, "ansible_port", None)
    try:
        current_port = int(current_port_raw) if current_port_raw is not None else None
    except (TypeError, ValueError):
        current_port = None
    host_data.pop("mavi_winrm_https", None)
    host_data.pop("mavi_winrm_fqdn", None)
    if disable_openssh:
        # Nur die historischen Werte für einen späteren, expliziten
        # `ssh use`-Schritt behalten. Sie sind keine aktiven Ansible-Variablen.
        if current_key_raw:
            host_data["mavi_ssh_private_key_file"] = str(
                Path(current_key_raw).expanduser().resolve()
            )
        if current_port is not None and 1 <= current_port <= 65535:
            host_data["mavi_ssh_port"] = current_port
        _apply_remote_management_disabled_transport(host_data)

        all_controller_warnings = [*artifact_warnings, *bootstrap_artifact_warnings]
        remote_cleanup_verified = (
            reset_result["winrm_scope_verified"]
            and reset_result["winrm_listeners_cleared"]
            and reset_result["bootstrap_scope_verified"]
            and reset_result["openssh_startup_disabled"]
            and reset_result["openssh_stopped_verified"]
            and reset_result["openssh_state"].casefold() == "stopped"
            and reset_result["openssh_start_mode"].casefold() == "disabled"
        )
        host_data["mavi_remote_management_disabled"] = {
            "version": 3,
            "recorded_at": _utc_now_iso(),
            "winrm": True,
            "openssh": True,
            "remote_cleanup_verified": remote_cleanup_verified,
            "winrm_scope_verified": reset_result["winrm_scope_verified"],
            "winrm_listeners_cleared": reset_result["winrm_listeners_cleared"],
            "bootstrap_scope_verified": reset_result["bootstrap_scope_verified"],
            "openssh_stopped_verified": reset_result["openssh_stopped_verified"],
            "controller_cleanup_complete": not all_controller_warnings,
            "bootstrap_ca_thumbprint": bootstrap_root_thumbprints[0],
            "bootstrap_ca_thumbprints": list(bootstrap_root_thumbprints),
            "winrm_root_thumbprint": reset_result["winrm_root_thumbprint"] or root_thumbprint,
            "result": {
                "removed_listeners": reset_result["removed_listeners"],
                "removed_certificates": reset_result["removed_certificates"],
                "removed_firewall_rules": reset_result["removed_firewall_rules"],
                "removed_openssh_firewall_rules": reset_result["removed_openssh_firewall_rules"],
                "removed_openssh_keys": reset_result["removed_openssh_keys"],
                "removed_openssh_config_backups": reset_result[
                    "removed_openssh_config_backups"
                ],
                "removed_bootstrap_certificates": reset_result["removed_bootstrap_certificates"],
                "openssh_state": reset_result["openssh_state"],
                "openssh_start_mode": reset_result["openssh_start_mode"],
                "preserved_foreign_winrm_listeners": reset_result[
                    "preserved_foreign_winrm_listeners"
                ],
            },
        }
        if not bootstrap_artifact_warnings:
            host_data.pop("mavi_bootstrap", None)
    else:
        _apply_ssh_transport(
            args.project,
            host_data,
            key_path=Path(current_key_raw).expanduser() if current_key_raw else None,
            port=current_port,
        )
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)

    print("\n✓ Remote-Verwaltungszustand wurde zurückgesetzt.")
    if reset_result["winrm_scope_verified"]:
        print("  WinRM:            Mavi-Listener entfernt, Dienst gestoppt und deaktiviert")
    else:
        print("  WinRM:            Dienst gestoppt und deaktiviert; Mavi-CA war nicht exakt belegbar")
        print("! Mavi hat deshalb keine Zertifikate oder Listener nur anhand ihres Namens gelöscht.")
    if reset_result["preserved_foreign_winrm_listeners"]:
        print(
            "  Fremde WinRM-Listener: "
            f"{reset_result['preserved_foreign_winrm_listeners']} erhalten (WinRM bleibt deaktiviert)"
        )
    print("  Kerberos/PSRP:    gespeicherter Hoststatus entfernt; kein persistenter Mavi-Ticketcache")
    print(f"  Host-PKI-Dateien: {removed_artifacts} Datei(en) auf dem Controller entfernt")
    print("  Gemeinsame CAs:   bleiben auf dem Controller für andere Windows-PCs erhalten")
    if disable_openssh:
        print(
            "  Bootstrap-CA:     "
            f"{reset_result['removed_bootstrap_certificates']} exakt passende CA-Kopie(n) auf Windows entfernt"
        )
        print(f"  Bootstrap-Dateien:{removed_bootstrap_artifacts} hostbezogene Datei(en) auf dem Controller entfernt")
        print(
            "  OpenSSH:          Mavi-Key/-Regel und Mavi-Konfigurationssicherung entfernt; "
            "sshd ist nachweislich gestoppt und deaktiviert"
        )
        print("  Fernzugang:       vollständig aus; OpenSSH bleibt lediglich installiert")
        print("\nFür eine spätere Neueinrichtung zuerst den Mavi-OpenSSH-Starter lokal am PC ausführen.")
        print(f"Danach: mavi-provisioner ssh use {args.host}")
    else:
        print("  OpenSSH:          bleibt installiert und aktiv")
        print(f"\nWinRM neu einrichten mit: mavi-provisioner ssh winrm-https {args.host}")
    for warning in artifact_warnings:
        print(f"! {warning}")
    for warning in bootstrap_artifact_warnings:
        print(f"! {warning}")


def cmd_ssh_use_psrp(args: argparse.Namespace) -> None:
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _effective_host_var,
        _host_inventory_entry,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    try:
        _apply_saved_winrm_https_transport(args.project, host_data)
    except ValueError as exc:
        die(str(exc))
    atomic_write_yaml(project_paths(args.project)["inventory"], inv)
    user = _effective_host_var(windows, host_data, "ansible_user", "(geerbt)")
    print(f"✓ {args.host} auf gespeichertes PSRP/WinRM HTTPS/Kerberos zurückgestellt.")
    print("  Verbindung: psrp:5986 / HTTPS / Kerberos-only")
    print(f"  Benutzer:   {user}")


def _public_key_prefix_from_path(pub_path: Path) -> str:
    """Key-Typ und Base64-Payload einer Public-Key-Datei lesen."""
    if not pub_path.exists():
        return ""
    try:
        text = pub_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return _public_key_prefix_from_text(text)


def _public_key_prefix_from_text(public_key: str) -> str:
    """Key-Typ und Base64-Payload einer OpenSSH-Public-Key-Zeile lesen."""
    parts = str(public_key or "").strip().split()
    if len(parts) < 2:
        return ""
    return f"{parts[0]} {parts[1]}"


def _public_key_prefix_for_private_key(private_key_path: Path) -> str:
    """Public-Key-Präfix aus Companion-Datei oder dem privaten Key bestimmen."""
    resolved = private_key_path.expanduser().resolve()
    companion_prefix = _public_key_prefix_from_path(Path(str(resolved) + ".pub"))
    if companion_prefix:
        return companion_prefix
    if not resolved.is_file():
        return ""
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        return ""
    try:
        result = subprocess.run(
            [ssh_keygen, "-y", "-P", "", "-f", str(resolved)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return _public_key_prefix_from_text(result.stdout)


def _ssh_private_key_path_for_host(
    project: Path,
    windows: dict[str, Any],
    host_data: dict[str, Any],
    *,
    requested_key: Path | str | None = None,
) -> Path:
    """Expliziten, aktiven oder gemerkten SSH-Key eines Hosts auflösen."""
    from .remote import _connection_label, _effective_host_var, get_ssh_settings

    raw_key = str(requested_key or "").strip()
    if not raw_key and _connection_label(windows, host_data) == "SSH":
        raw_key = str(
            _effective_host_var(
                windows,
                host_data,
                "ansible_ssh_private_key_file",
                "",
            )
            or ""
        ).strip()
    if not raw_key:
        raw_key = str(host_data.get("mavi_ssh_private_key_file", "") or "").strip()
    if not raw_key:
        raw_key = str(get_ssh_settings(project)["private_key"])
    return Path(raw_key).expanduser().resolve()


def _mavi_public_key_prefix(project: Path) -> str:
    """Nur Key-Typ + Base64-Payload, ohne Kommentar, für exakten Remote-Abgleich."""
    from .remote import get_ssh_settings

    settings = get_ssh_settings(project)
    pub_path = Path(settings["public_key"]).expanduser().resolve()
    return _public_key_prefix_from_path(pub_path)


def _remove_mavi_ssh_keys_from_host(
    project: Path,
    host: str,
) -> int:
    """Entfernt nur Mavi-autorisierte Public Keys auf genau einem Windows-Host."""
    from .environment import project_paths
    from .execution import run_subprocess
    from .remote import _ssh_environment_marker

    key_prefix = _mavi_public_key_prefix(project)
    marker = _ssh_environment_marker(project)

    powershell = r'''[CmdletBinding()]
param(
    [string]$CurrentKeyPrefix = "",
    [string]$Marker = ""
)

$keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'

$result = [ordered]@{
    KeyFile = $keyFile
    Existed = $false
    RemovedCount = 0
    Removed = @()
    RemainingCount = 0
}

if (-not (Test-Path -LiteralPath $keyFile)) {
    $Ansible.Result = $result
    $Ansible.Changed = $false
    return
}

$result.Existed = $true
$lines = @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)
$kept = New-Object 'System.Collections.Generic.List[string]'
$removed = New-Object 'System.Collections.Generic.List[string]'

foreach ($lineObj in $lines) {
    $line = [string]$lineObj
    $trim = $line.Trim()
    $remove = $false

    if (-not [string]::IsNullOrWhiteSpace($trim) -and -not $trim.StartsWith('#')) {
        if (-not [string]::IsNullOrWhiteSpace($Marker)) {
            $markerPattern = '(^|\s)' + [regex]::Escape($Marker) + '(\s|$)'
            if ($trim -match $markerPattern) {
                $remove = $true
            }
        }

        if (
            -not $remove -and
            -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
            ($trim -eq $CurrentKeyPrefix -or $trim.StartsWith($CurrentKeyPrefix + ' '))
        ) {
            $remove = $true
        }
    }

    if ($remove) {
        $removed.Add($trim)
    }
    else {
        $kept.Add($line)
    }
}

if ($removed.Count -gt 0) {
    if ($kept.Count -gt 0) {
        Set-Content -LiteralPath $keyFile -Value @($kept) -Encoding ascii
    }
    else {
        [System.IO.File]::WriteAllText($keyFile, '', [System.Text.Encoding]::ASCII)
    }

    & icacls.exe $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "ACLs für '$keyFile' konnten nach der Key-Entfernung nicht gesetzt werden. icacls Exit-Code: $LASTEXITCODE"
    }
}

$result.RemovedCount = $removed.Count
$result.Removed = @($removed)
$result.RemainingCount = $kept.Count
$Ansible.Result = $result
$Ansible.Changed = ($removed.Count -gt 0)
'''

    play = [{
        "name": "Mavi SSH-Public-Keys entfernen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi SSH-Key(s) aus administrators_authorized_keys entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CurrentKeyPrefix": key_prefix,
                        "Marker": marker,
                    },
                },
                "register": "mavi_ssh_key_remove",
            },
            {
                "name": "Mavi SSH-Key-Entfernung anzeigen",
                "ansible.builtin.debug": {
                    "msg": (
                        "Mavi_SSH_KEY_REMOVE removed={{ mavi_ssh_key_remove.result.RemovedCount | default(0) }} "
                        "remaining={{ mavi_ssh_key_remove.result.RemainingCount | default(0) }} "
                        "file={{ mavi_ssh_key_remove.result.KeyFile | default('') }}"
                    )
                },
            },
        ],
    }]

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yml",
            prefix="mavi-ssh-key-remove-",
            delete=False,
        ) as fh:
            yaml.safe_dump(
                play,
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
            tmp_path = Path(fh.name)

        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(tmp_path),
            "--limit",
            host,
            "--ask-vault-pass",
        ]
        return run_subprocess(cmd, project)
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink()
            except OSError:
                pass


def cmd_ssh_remove_keys(args: argparse.Namespace) -> None:
    """Mavi-Keys nach ausdrücklicher Bestätigung vom Windows-PC entfernen."""
    from .catalogs import yes_no
    from .environment import (
        atomic_write_yaml,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _connection_label,
        _host_inventory_entry,
        _saved_winrm_https_transport,
        _ssh_environment_marker,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    del inv
    connection_before = _connection_label(windows, host_data)
    saved_winrm_available = False
    if connection_before == "SSH":
        try:
            _saved_winrm_https_transport(args.project, host_data)
        except ValueError:
            pass
        else:
            saved_winrm_available = True

    if not bool(getattr(args, "yes", False)):
        print("\nMavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print(f"PC:          {args.host}")
        print(f"Verbindung:  {connection_before}")
        print(f"Entfernt werden NUR Mavi-Keys dieses Projekts mit Marker '{_ssh_environment_marker(args.project)}'")
        print("und der aktuell auf dem Ansible-Server konfigurierte Mavi-Public-Key.")
        print("Andere Einträge in administrators_authorized_keys bleiben erhalten.")
        if connection_before == "SSH":
            if saved_winrm_available:
                print("Danach wird dieser Host auf das gespeicherte PSRP/WinRM HTTPS + Kerberos umgestellt.")
            else:
                print("! Für diesen PC ist kein geprüfter PSRP/WinRM-Ersatzweg gespeichert.")
                print("! Der Mavi-Key wird bei Bestätigung trotzdem entfernt; das Inventory bleibt auf SSH.")
        question = (
            "Mavi SSH-Key(s) trotz fehlendem Ersatzweg wirklich entfernen?"
            if connection_before == "SSH" and not saved_winrm_available
            else "Mavi SSH-Key(s) auf diesem PC wirklich entfernen?"
        )
        if not yes_no(question, default=False):
            print("Abgebrochen.")
            return

    rc = _remove_mavi_ssh_keys_from_host(args.project, args.host)
    if rc != 0:
        print(f"\n! Key-Entfernung auf {args.host} fehlgeschlagen, Code {rc}.")
        return

    if connection_before == "SSH" and saved_winrm_available:
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)
        del windows
        _apply_saved_winrm_https_transport(args.project, host_data)
        atomic_write_yaml(project_paths(args.project)["inventory"], inv)
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt und Inventory auf PSRP HTTPS/Kerberos umgestellt.")
    else:
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt. Verbindung bleibt {connection_before}.")
        if connection_before == "SSH":
            print("  Für neue Mavi-SSH-Verbindungen muss wieder ein Key eingerichtet oder die Verbindung umgestellt werden.")

    print("  OpenSSH/sshd bleibt auf Windows installiert und aktiv.")
    print("  Fremde SSH-Keys und Mavi-known_hosts auf dem Ansible-Server bleiben unangetastet.")


def ssh_remove_keys_menu(project: Path) -> None:
    from .catalogs import (
        choose_host_interactive,
        yes_no,
    )
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _connection_label,
        _host_inventory_entry,
        _saved_winrm_https_transport,
    )

    while True:
        print()
        print("Mavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print("  1) Von EINEM Windows-PC entfernen")
        print("  2) Von ALLEN Windows-PCs entfernen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        if choice == "1":
            host = choose_host_interactive(project)
            cmd_ssh_remove_keys(
                argparse.Namespace(project=project, host=host, yes=False)
            )
            return

        if choice == "2":
            inv = load_inventory(project)
            windows = ensure_windows_tree(inv)
            hosts = list((windows.get("hosts", {}) or {}).keys())
            if not hosts:
                print("Keine Windows-PCs im Inventory vorhanden.")
                return

            print()
            print(f"! Mavi SSH-Key(s) werden auf {len(hosts)} PC(s) entfernt.")
            switch_to_winrm: set[str] = set()
            ssh_without_replacement: list[str] = []
            for host in hosts:
                _, host_windows, host_data = _host_inventory_entry(project, host)
                if _connection_label(host_windows, host_data) != "SSH":
                    continue
                try:
                    _saved_winrm_https_transport(project, host_data)
                except ValueError:
                    ssh_without_replacement.append(host)
                else:
                    switch_to_winrm.add(host)

            if ssh_without_replacement:
                print(
                    f"! Für {len(ssh_without_replacement)} SSH-PC(s) ist kein geprüfter "
                    "PSRP/WinRM-Ersatzweg gespeichert: " + ", ".join(ssh_without_replacement)
                )
                print("! Bei Bestätigung werden die Mavi-Keys dort trotzdem entfernt; das Inventory bleibt auf SSH.")
                question = "Mavi SSH-Key(s) trotzdem auf ALLEN Inventory-PCs entfernen?"
            else:
                question = "Mavi SSH-Key(s) wirklich auf ALLEN Inventory-PCs entfernen?"
            if not yes_no(question, default=False):
                print("Abgebrochen.")
                return

            succeeded: list[str] = []
            failed: list[str] = []
            for index, host in enumerate(hosts, start=1):
                print()
                print(f"[{index}/{len(hosts)}] {host}")
                before_inv, before_windows, before_data = _host_inventory_entry(project, host)
                del before_inv
                connection_before = _connection_label(before_windows, before_data)
                rc = _remove_mavi_ssh_keys_from_host(project, host)
                if rc != 0:
                    failed.append(host)
                    print(f"! {host}: fehlgeschlagen, Verbindung bleibt {connection_before}.")
                    continue

                if host in switch_to_winrm:
                    after_inv, after_windows, after_data = _host_inventory_entry(project, host)
                    del after_windows
                    _apply_saved_winrm_https_transport(project, after_data)
                    atomic_write_yaml(project_paths(project)["inventory"], after_inv)
                succeeded.append(host)
                if host in switch_to_winrm:
                    print(f"✓ {host}: Key(s) entfernt → PSRP HTTPS/Kerberos")
                else:
                    print(f"✓ {host}: Key(s) entfernt, Verbindung bleibt {connection_before}")

            print()
            print("Mavi SSH-KEY-ENTFERNUNG FERTIG")
            print("==============================")
            print(f"Erfolgreich: {len(succeeded)}/{len(hosts)}")
            if failed:
                print("Fehlgeschlagen: " + ", ".join(failed))
            return

        if choice == "0":
            return

        print("Ungültige Auswahl.")


def _parse_ansible_core_version() -> tuple[int, ...] | None:
    if not shutil.which("ansible"):
        return None
    try:
        result = subprocess.run(
            ["ansible", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    first = (result.stdout or result.stderr or "").splitlines()
    if not first:
        return None
    m = re.search(r"(?:core\s+)?(\d+)\.(\d+)(?:\.(\d+))?", first[0])
    if not m:
        return None
    return tuple(int(x or 0) for x in m.groups())


def _remote_management_disabled_state(host_data: dict[str, Any]) -> dict[str, Any] | None:
    """Versionierte Option-11-Nachweise lesen, ohne alte Einträge schönzureden."""
    from .remote import _normalized_certificate_thumbprint

    raw = host_data.get("mavi_remote_management_disabled")
    if not isinstance(raw, dict):
        return None
    if raw.get("winrm") is not True or raw.get("openssh") is not True:
        return None
    try:
        version = int(raw.get("version", 1))
    except (TypeError, ValueError):
        version = 1
    verified = (
        version >= 3
        and raw.get("remote_cleanup_verified") is True
        and raw.get("winrm_scope_verified") is True
        and raw.get("winrm_listeners_cleared") is True
        and raw.get("bootstrap_scope_verified") is True
        and raw.get("openssh_stopped_verified") is True
    )
    bootstrap_thumbprints = _bootstrap_state_thumbprints(
        {
            "root_thumbprint": raw.get("bootstrap_ca_thumbprint"),
            "root_thumbprints": raw.get("bootstrap_ca_thumbprints"),
        }
    )
    return {
        "version": version,
        "verified": verified,
        "controller_cleanup_complete": raw.get("controller_cleanup_complete") is True,
        "recorded_at": str(raw.get("recorded_at", "") or ""),
        "bootstrap_ca_thumbprint": bootstrap_thumbprints[0] if bootstrap_thumbprints else "",
        "bootstrap_ca_thumbprints": bootstrap_thumbprints,
        "winrm_root_thumbprint": _normalized_certificate_thumbprint(
            raw.get("winrm_root_thumbprint")
        ),
        "raw": raw,
    }


def _stored_bootstrap_root_thumbprints(host_data: dict[str, Any]) -> tuple[str, ...]:
    """Nur hostgebundene oder verifizierte Rückbau-Identitäten liefern."""
    thumbprints = _verified_bootstrap_root_thumbprints(host_data)
    if thumbprints:
        return thumbprints
    disabled = _remote_management_disabled_state(host_data)
    if disabled and disabled.get("verified"):
        return tuple(disabled["bootstrap_ca_thumbprints"])
    return ()


def _host_known_ca_thumbprints(
    project: Path,
    host_data: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    """Nur lokal bekannte exakte Mavi-CA-Thumbprints für einen Live-Audit liefern."""
    from .remote import (
        _certificate_thumbprint_from_file,
        _normalized_certificate_thumbprint,
        _winrm_pki_paths,
    )

    winrm_thumbprint = ""
    winrm_state = host_data.get("mavi_winrm_https")
    if isinstance(winrm_state, dict):
        winrm_thumbprint = _normalized_certificate_thumbprint(winrm_state.get("root_thumbprint"))
    disabled = _remote_management_disabled_state(host_data)
    if not winrm_thumbprint and disabled:
        winrm_thumbprint = disabled["winrm_root_thumbprint"]
    if not winrm_thumbprint:
        try:
            ca_der = _winrm_pki_paths(project)["ca_der"]
            if ca_der.is_file():
                winrm_thumbprint = _certificate_thumbprint_from_file(ca_der)
        except (OSError, ValueError):
            pass

    # Ohne pro Host gespeicherte Identität darf eine aktuell auf dem Controller
    # liegende, möglicherweise rotierte Bootstrap-CA den Audit-Scope nicht
    # erfinden. Ein leerer Wert macht die Live-Prüfung bewusst unvollständig.
    bootstrap_thumbprints = _stored_bootstrap_root_thumbprints(host_data)
    return winrm_thumbprint, bootstrap_thumbprints


def _winrm_root_certificate_der_base64_for_thumbprint(
    project: Path,
    expected_thumbprint: str,
) -> str:
    """Nur die exakt erwartete öffentliche Mavi-WinRM-CA für einen Audit liefern."""
    from .remote import (
        _certificate_der_base64_from_file,
        _certificate_thumbprint_from_file,
        _normalized_certificate_thumbprint,
        _winrm_pki_paths,
    )

    expected = _normalized_certificate_thumbprint(expected_thumbprint)
    if not expected:
        return ""
    ca_der = _winrm_pki_paths(project)["ca_der"]
    if not ca_der.is_file():
        return ""
    try:
        if _certificate_thumbprint_from_file(ca_der) != expected:
            return ""
        return _certificate_der_base64_from_file(ca_der)
    except (OSError, ValueError):
        return ""


def _certificate_expiry_text(value: Any, *, warning_days: int) -> tuple[str, bool]:
    """Ablaufdatum samt Warnzustand ohne Annahmen über lokale Zeitzonen formatieren."""
    from .remote import _normalized_certificate_timestamp

    try:
        normalized = _normalized_certificate_timestamp(value, label="Zertifikatsablaufdatum")
        expires = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except RuntimeError:
        return "unbekannt", True
    remaining_seconds = (expires - datetime.now(timezone.utc)).total_seconds()
    remaining_days = int(remaining_seconds // 86400)
    if remaining_seconds <= 0:
        return f"{normalized} (abgelaufen)", True
    warning = remaining_seconds <= warning_days * 86400
    return f"{normalized} (noch {remaining_days} Tage)", warning


def _print_certificate_metadata(host_data: dict[str, Any]) -> None:
    """Im Inventory gespeicherte Laufzeiten mit den geplanten Warnschwellen zeigen."""
    from .remote import _normalized_certificate_thumbprint

    state = host_data.get("mavi_winrm_https")
    if not isinstance(state, dict):
        return
    leaf_thumbprint = _normalized_certificate_thumbprint(state.get("certificate_thumbprint"))
    root_thumbprint = _normalized_certificate_thumbprint(state.get("root_thumbprint"))
    if leaf_thumbprint:
        leaf_text, leaf_warning = _certificate_expiry_text(
            state.get("certificate_not_after"),
            warning_days=30,
        )
        print(f"WinRM-Leaf:         {leaf_thumbprint} — {leaf_text}")
        if leaf_warning:
            print("! WinRM-Serverzertifikat läuft in weniger als 30 Tagen ab oder ist unbekannt.")
    if root_thumbprint:
        root_text, root_warning = _certificate_expiry_text(
            state.get("root_not_after"),
            warning_days=90,
        )
        print(f"WinRM-Root-CA:      {root_thumbprint} — {root_text}")
        if root_warning:
            print("! Mavi-WinRM-Root-CA läuft in weniger als 90 Tagen ab oder ist unbekannt.")



def _audit_value(audit: dict[str, Any], section: str, field: str, default: Any = None) -> Any:
    value = audit.get(section)
    return value.get(field, default) if isinstance(value, dict) else default


def _audit_nonnegative_count(audit: dict[str, Any], section: str, field: str) -> int:
    value = _audit_value(audit, section, field, -1)
    if isinstance(value, bool):
        return -1
    try:
        number = int(value)
    except (TypeError, ValueError):
        return -1
    return number if number >= 0 else -1


def _audit_service_is_disabled_or_absent(audit: dict[str, Any], section: str) -> bool:
    exists = _audit_value(audit, section, "Exists", None)
    if exists is False:
        return True
    start = _audit_value(audit, section, "Start", -1)
    status = str(_audit_value(audit, section, "Status", "") or "").casefold()
    return start == 4 and status == "stopped"


def _audit_service_state_is_unknown(audit: dict[str, Any], section: str) -> bool:
    """Nur einen tatsächlich gelesenen Dienstzustand als aktiv/inaktiv werten."""
    exists = _audit_value(audit, section, "Exists", None)
    if exists is False:
        return False
    if exists is not True:
        return True
    start = _audit_value(audit, section, "Start", -1)
    status = str(_audit_value(audit, section, "Status", "") or "").casefold()
    return not isinstance(start, int) or start < 0 or status not in {
        "stopped",
        "running",
        "startpending",
        "stoppending",
        "paused",
        "pausepending",
        "continuepending",
    }


def _classify_remote_management_audit(
    audit: dict[str, Any] | None,
    disabled_state: dict[str, Any] | None,
) -> dict[str, Any]:
    """Live-Audit in bestätigte, partielle und unbekannte Rückbauzustände einordnen."""
    proof_available = bool(disabled_state and disabled_state.get("verified"))
    legacy_record = disabled_state is not None and not proof_available
    if audit is None:
        return {
            "code": "disabled_unreachable" if proof_available else "unknown_unreachable",
            "label": (
                "AUS – laut Rückbau-Nachweis; Live-Prüfung nicht möglich"
                if proof_available
                else "UNBEKANNT – Live-Prüfung nicht möglich"
            ),
            "details": [],
        }

    query_errors = audit.get("QueryErrors")
    query_errors = query_errors if isinstance(query_errors, list) else ["Audit-Ergebnis unvollständig"]
    winrm_listener_count = _audit_nonnegative_count(audit, "WinRM", "MaviListenerCount")
    foreign_winrm_listener_count = _audit_nonnegative_count(
        audit, "WinRM", "ForeignListenerCount"
    )
    winrm_rule_count = _audit_nonnegative_count(audit, "WinRM", "FirewallRuleCount")
    winrm_policy_count = _audit_nonnegative_count(audit, "WinRM", "PolicyValueCount")
    ssh_rule_count = _audit_nonnegative_count(audit, "OpenSSH", "FirewallRuleCount")
    key_count = _audit_nonnegative_count(audit, "OpenSSH", "MaviKeyCount")
    ssh_config_backup_count = _audit_nonnegative_count(
        audit, "OpenSSH", "MaviConfigBackupCount"
    )
    leaf_count = _audit_nonnegative_count(audit, "Certificates", "ManagedLeafCount")
    roots_present = any(
        _audit_value(audit, "Certificates", key, False) is True
        for key in ("WinRmRootPresent", "BootstrapRootPresent", "CurrentLeafPresent")
    )
    cert_checks_known = (
        _audit_value(audit, "CertificateChecks", "WinRmRootThumbprintProvided", False) is True
        and _audit_value(audit, "CertificateChecks", "WinRmRootIdentityProvided", False) is True
        and _audit_value(audit, "CertificateChecks", "WinRmLeafIdentityProvided", False) is True
        and _audit_value(audit, "CertificateChecks", "BootstrapRootThumbprintProvided", False) is True
    )
    listener_check_skipped_disabled = (
        _audit_value(audit, "WinRM", "ListenerCheckSkippedDisabled", False) is True
    )
    listener_scope_known = not listener_check_skipped_disabled or proof_available

    winrm_unknown = _audit_service_state_is_unknown(audit, "WinRM")
    ssh_unknown = _audit_service_state_is_unknown(audit, "OpenSSH")
    winrm_active = not winrm_unknown and not _audit_service_is_disabled_or_absent(audit, "WinRM")
    ssh_active = not ssh_unknown and not _audit_service_is_disabled_or_absent(audit, "OpenSSH")
    mavi_residual = (
        winrm_listener_count > 0
        or winrm_rule_count > 0
        or ssh_rule_count > 0
        or key_count > 0
        or ssh_config_backup_count > 0
        or leaf_count > 0
        or roots_present
    )
    residual = mavi_residual or foreign_winrm_listener_count > 0
    unknown_counts = any(
        count < 0
        for count in (
            winrm_listener_count,
            foreign_winrm_listener_count,
            winrm_rule_count,
            ssh_rule_count,
            key_count,
            ssh_config_backup_count,
            leaf_count,
        )
    )
    clean = (
        not query_errors
        and cert_checks_known
        and listener_scope_known
        and not unknown_counts
        and not winrm_active
        and not ssh_active
        and not residual
    )
    policy_details = (
        ["generische WinRM-Richtlinienwerte beobachtet (nicht angefasst)"]
        if winrm_policy_count > 0
        else []
    )
    if clean:
        if legacy_record:
            return {
                "code": "legacy_not_confirmable",
                "label": "UNBEKANNT – alter Rückbau-Eintrag ohne Rückbau-Nachweis",
                "details": ["Alter Inventory-Eintrag wird nicht als sauber bestätigt."],
            }
        return {
            "code": "confirmed_disabled",
            "label": "AUS – live bestätigt",
            "details": policy_details,
        }

    details: list[str] = []
    if winrm_active:
        details.append("WinRM aktiv")
    if ssh_active:
        details.append("sshd aktiv")
    if mavi_residual:
        details.append("Mavi-Artefakte vorhanden")
    if ssh_config_backup_count > 0:
        details.append("Mavi-OpenSSH-Konfigurationssicherung vorhanden")
    if foreign_winrm_listener_count > 0:
        details.append("nicht zuordenbare WinRM-Listener erhalten")
    details.extend(policy_details)
    if (
        query_errors
        or unknown_counts
        or winrm_unknown
        or ssh_unknown
        or not cert_checks_known
        or not listener_scope_known
    ):
        details.append("Live-Prüfung unvollständig")

    if winrm_active or ssh_active:
        return {"code": "active", "label": "AKTIV", "details": details}
    if residual:
        return {"code": "partial", "label": "TEILWEISE", "details": details}
    if proof_available:
        return {
            "code": "disabled_unreachable",
            "label": "AUS – laut Rückbau-Nachweis; Live-Prüfung unvollständig",
            "details": details,
        }
    return {"code": "unknown", "label": "UNBEKANNT", "details": details}


def _inventory_remote_management_status(
    windows: dict[str, Any],
    host_data: dict[str, Any],
) -> dict[str, Any]:
    """Ohne Live-Check nur belegbare Aussagen aus dem Inventory treffen."""
    from .remote import _connection_label

    disabled = _remote_management_disabled_state(host_data)
    if disabled and disabled["verified"]:
        suffix = "" if disabled["controller_cleanup_complete"] else "; Controller-Bereinigung mit Hinweis"
        return {
            "code": "disabled_recorded",
            "label": f"AUS – laut Rückbau-Nachweis (nicht live geprüft{suffix})",
            "details": [],
        }
    if disabled:
        return {
            "code": "legacy_disabled",
            "label": "UNBEKANNT – alter Rückbau-Eintrag ohne Rückbau-Nachweis",
            "details": [],
        }
    connection = _connection_label(windows, host_data)
    if connection in {"SSH", "PSRP", "WINRM"}:
        return {
            "code": "inventory_active",
            "label": f"AKTIV/TEILWEISE – laut Inventory ({connection}; nicht live geprüft)",
            "details": [],
        }
    return {"code": "unknown", "label": "UNBEKANNT – kein prüfbarer Verwaltungsstatus", "details": []}





def _remote_management_audit_play(
    *,
    winrm_root_thumbprint: str,
    winrm_root_certificate_der_base64: str,
    bootstrap_root_thumbprints: tuple[str, ...] | list[str],
    current_leaf_thumbprint: str,
    current_key_prefix: str,
    expected_fqdn: str = "",
    current_key_marker: str = "",
    openssh_firewall_rule: str = "",
    openssh_config_backup: str = "",
) -> list[dict[str, Any]]:
    """Reinen Lese-Audit für Mavi-Remote-Artefakte auf einem Windows-PC erzeugen."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$WinRmRootThumbprint = '',
    [string]$WinRmRootCertificateDerBase64 = '',
    [string[]]$BootstrapRootThumbprints = @(),
    [string]$CurrentLeafThumbprint = '',
    [string]$CurrentKeyPrefix = '',
    [string]$ExpectedFqdn = '',
    [string]$CurrentKeyMarker = '',
    [string]$OpenSshFirewallRuleName = '',
    [string]$OpenSshConfigBackupPath = ''
)

$ErrorActionPreference = 'Stop'
$WinRmRootThumbprint = ($WinRmRootThumbprint -replace '\s', '').ToUpperInvariant()
$WinRmRootCertificateDerBase64 = $WinRmRootCertificateDerBase64.Trim()
$BootstrapRootThumbprints = @(
    $BootstrapRootThumbprints |
    ForEach-Object { (([string]$_) -replace '\s', '').ToUpperInvariant() } |
    Select-Object -Unique
)
$CurrentLeafThumbprint = ($CurrentLeafThumbprint -replace '\s', '').ToUpperInvariant()
$ExpectedFqdn = $ExpectedFqdn.Trim().TrimEnd('.')
$bootstrapThumbprintsValid = (
    @($BootstrapRootThumbprints).Count -gt 0 -and
    @($BootstrapRootThumbprints | Where-Object { $_ -notmatch '^[A-F0-9]{40}$' }).Count -eq 0
)

$result = [ordered]@{
    Version = 1
    QueryErrors = @()
    CertificateChecks = [ordered]@{
        WinRmRootThumbprintProvided = ($WinRmRootThumbprint -match '^[A-F0-9]{40}$')
        WinRmRootIdentityProvided = $false
        WinRmLeafIdentityProvided = (-not [string]::IsNullOrWhiteSpace($ExpectedFqdn))
        BootstrapRootThumbprintProvided = $bootstrapThumbprintsValid
    }
    WinRM = [ordered]@{
        Exists = $false
        Status = ''
        Start = -1
        ListenerCheckSkippedDisabled = $false
        TotalListenerCount = -1
        MaviListenerCount = -1
        ForeignListenerCount = -1
        FirewallRuleCount = -1
        PolicyValueCount = -1
    }
    OpenSSH = [ordered]@{
        Exists = $false
        Status = ''
        Start = -1
        FirewallRuleCount = -1
        MaviKeyCount = -1
        MaviConfigBackupCount = -1
    }
    Certificates = [ordered]@{
        WinRmRootPresent = $false
        WinRmRootNotAfter = ''
        BootstrapRootPresent = $false
        BootstrapRoots = [ordered]@{}
        CurrentLeafPresent = $false
        CurrentLeafNotAfter = ''
        ManagedLeafCount = -1
        LatestManagedLeafNotAfter = ''
    }
}

function Add-MaviAuditError {
    param([string]$Area, [object]$ErrorRecord)
    $message = ''
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.Exception) {
        $message = [string]$ErrorRecord.Exception.Message
    }
    if ($message) {
        $result.QueryErrors += ($Area + ': ' + $message)
    }
    else {
        $result.QueryErrors += $Area
    }
}

$expectedWinRmRoot = $null
if (-not [string]::IsNullOrWhiteSpace($WinRmRootCertificateDerBase64)) {
    try {
        $expectedWinRmRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [Convert]::FromBase64String($WinRmRootCertificateDerBase64)
        )
        $expectedWinRmRootThumbprint = ([string]$expectedWinRmRoot.Thumbprint).ToUpperInvariant()
        if (
            $WinRmRootThumbprint -notmatch '^[A-F0-9]{40}$' -or
            -not $expectedWinRmRootThumbprint.Equals(
                $WinRmRootThumbprint,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw 'Root-Zertifikat und erwarteter Mavi-Root-Fingerabdruck stimmen nicht überein.'
        }
        $result.CertificateChecks.WinRmRootIdentityProvided = $true
    }
    catch { Add-MaviAuditError 'Mavi-WinRM-Root-Identität' $_ }
}
else {
    Add-MaviAuditError 'Mavi-WinRM-Root-Identität' $null
}

function Test-MaviAuditLeafCertificate {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedRoot,
        [string]$ExpectedFqdn
    )
    if (
        $null -eq $Certificate -or
        $null -eq $ExpectedRoot -or
        [string]::IsNullOrWhiteSpace($ExpectedFqdn)
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
        return ([string]$chainRoot.Thumbprint).Equals(
            [string]$ExpectedRoot.Thumbprint,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    }
    catch {
        return $false
    }
    finally {
        $chain.Dispose()
    }
}

try {
    $service = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $result.WinRM.Exists = $true
        $result.WinRM.Status = [string]$service.Status
    }
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM'
    if (Test-Path -LiteralPath $registryPath) {
        $result.WinRM.Start = [int](Get-ItemPropertyValue -LiteralPath $registryPath -Name Start -ErrorAction Stop)
    }
}
catch { Add-MaviAuditError 'WinRM-Dienst' $_ }

if (
    $result.WinRM.Exists -eq $true -and
    [string]$result.WinRM.Status -eq 'Stopped' -and
    [int]$result.WinRM.Start -eq 4
) {
    # Der WSMan:-Provider kann bei Stopped + Disabled lokal bis zum
    # Ansible-Timeout blockieren. Nach einem verifizierten v3-Rückbau ist der
    # Listener-Endzustand bereits Teil des signierten Ablaufbelegs; Python
    # akzeptiert dieses Überspringen nur zusammen mit genau diesem Nachweis.
    $result.WinRM.ListenerCheckSkippedDisabled = $true
    $result.WinRM.TotalListenerCount = 0
    $result.WinRM.MaviListenerCount = 0
    $result.WinRM.ForeignListenerCount = 0
}
else {
    try {
        $listeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop)
        $result.WinRM.TotalListenerCount = $listeners.Count
        if ($null -eq $expectedWinRmRoot) {
            throw 'Die exakte Mavi-WinRM-Root-Identität fehlt.'
        }
        $maviListenerCount = 0
        foreach ($listener in $listeners) {
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
            if (Test-MaviAuditLeafCertificate -Certificate $listenerCertificate -ExpectedRoot $expectedWinRmRoot -ExpectedFqdn $ExpectedFqdn) {
                $maviListenerCount++
            }
        }
        $result.WinRM.MaviListenerCount = $maviListenerCount
        $result.WinRM.ForeignListenerCount = $listeners.Count - $maviListenerCount
    }
    catch { Add-MaviAuditError 'WinRM-Listener' $_ }
}

try {
    $winrmRuleNames = @(
        'Mavi-WinRM-HTTPS-Ansible-In-TCP',
        'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP',
        'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
    )
    $ruleCount = 0
    foreach ($ruleName in $winrmRuleNames) {
        $ruleCount += @(
            Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.Group -eq 'Mavi Provisioner' }
        ).Count
    }
    $result.WinRM.FirewallRuleCount = $ruleCount
}
catch { Add-MaviAuditError 'WinRM-Firewall' $_ }

try {
    $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $policyCount = 0
    if (Test-Path -LiteralPath $policyPath) {
        $policy = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
        foreach ($policyName in @(
            'AllowUnencryptedTraffic',
            'AllowKerberos',
            'AllowNegotiate',
            'AllowBasic',
            'AllowCredSSP'
        )) {
            if ($null -ne $policy.PSObject.Properties[$policyName]) {
                $policyCount++
            }
        }
    }
    $result.WinRM.PolicyValueCount = $policyCount
}
catch { Add-MaviAuditError 'WinRM-Richtlinie' $_ }

try {
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $result.OpenSSH.Exists = $true
        $result.OpenSSH.Status = [string]$service.Status
    }
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
    if (Test-Path -LiteralPath $registryPath) {
        $result.OpenSSH.Start = [int](Get-ItemPropertyValue -LiteralPath $registryPath -Name Start -ErrorAction Stop)
    }
}
catch { Add-MaviAuditError 'OpenSSH-Dienst' $_ }

try {
    if ($OpenSshFirewallRuleName -notmatch '^Mavi-OpenSSH-[a-z0-9-]+-Ansible-In-TCP$') {
        throw 'Der exakte instanzgebundene Mavi-OpenSSH-Firewallregelname fehlt.'
    }
    $result.OpenSSH.FirewallRuleCount = @(
        Get-NetFirewallRule -Name $OpenSshFirewallRuleName -ErrorAction SilentlyContinue
    ).Count
}
catch { Add-MaviAuditError 'OpenSSH-Firewall' $_ }

try {
    $keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    $keyCount = 0
    if (Test-Path -LiteralPath $keyFile -PathType Leaf) {
        foreach ($lineObject in @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)) {
            $line = ([string]$lineObject).Trim()
            if (-not [string]::IsNullOrWhiteSpace($CurrentKeyMarker)) {
                $markerPattern = '(^|\s)' + [regex]::Escape($CurrentKeyMarker) + '(\s|$)'
                if ($line -match $markerPattern) {
                    $keyCount++
                    continue
                }
            }
            if (
                -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
                ($line -eq $CurrentKeyPrefix -or $line.StartsWith($CurrentKeyPrefix + ' '))
            ) {
                $keyCount++
            }
        }
    }
    $result.OpenSSH.MaviKeyCount = $keyCount
}
catch { Add-MaviAuditError 'OpenSSH-Keydatei' $_ }

try {
    if (
        $OpenSshConfigBackupPath -notmatch
        '^MaviProvisioner\\bootstrap\\[a-z0-9-]+\\sshd_config\.pre-mavi\.bak$'
    ) {
        throw 'Der exakte instanzgebundene Mavi-OpenSSH-Konfigurationssicherungspfad fehlt.'
    }
    $configBackup = Join-Path $env:ProgramData $OpenSshConfigBackupPath
    if (Test-Path -LiteralPath $configBackup -PathType Leaf) {
        $result.OpenSSH.MaviConfigBackupCount = 1
    }
    else {
        $result.OpenSSH.MaviConfigBackupCount = 0
    }
}
catch { Add-MaviAuditError 'OpenSSH-Mavi-Konfigurationssicherung' $_ }

try {
    $winRmRoot = $null
    if ($WinRmRootThumbprint -match '^[A-F0-9]{40}$') {
        $winRmRoot = Get-Item -LiteralPath ("Cert:\LocalMachine\Root\$WinRmRootThumbprint") -ErrorAction SilentlyContinue
        if ($null -ne $winRmRoot) {
            $result.Certificates.WinRmRootPresent = $true
            $result.Certificates.WinRmRootNotAfter = $winRmRoot.NotAfter.ToUniversalTime().ToString('o')
        }
    }
    foreach ($bootstrapRootThumbprint in $BootstrapRootThumbprints) {
        if ($bootstrapRootThumbprint -notmatch '^[A-F0-9]{40}$') { continue }
        $bootstrapRootResult = [ordered]@{
            Present = $false
            NotAfter = ''
        }
        $bootstrapRoot = Get-Item -LiteralPath ("Cert:\LocalMachine\Root\$bootstrapRootThumbprint") -ErrorAction SilentlyContinue
        if ($null -ne $bootstrapRoot) {
            $result.Certificates.BootstrapRootPresent = $true
            $bootstrapRootResult.Present = $true
            $bootstrapRootResult.NotAfter = $bootstrapRoot.NotAfter.ToUniversalTime().ToString('o')
        }
        $result.Certificates.BootstrapRoots[$bootstrapRootThumbprint] = $bootstrapRootResult
    }
    if ($CurrentLeafThumbprint -match '^[A-F0-9]{40}$') {
        $currentLeaf = Get-Item -LiteralPath ("Cert:\LocalMachine\My\$CurrentLeafThumbprint") -ErrorAction SilentlyContinue
        if ($null -ne $currentLeaf) {
            $result.Certificates.CurrentLeafPresent = $true
            $result.Certificates.CurrentLeafNotAfter = $currentLeaf.NotAfter.ToUniversalTime().ToString('o')
        }
    }

    $managedLeafCount = 0
    $latestManagedLeaf = $null
    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
        if (-not (Test-Path -LiteralPath $storePath)) { continue }
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction Stop)) {
            # Auch im Audit zählt ein Zertifikat nur mit Mavi-Namen und einer
            # verifizierten Kette bis zur exakt bekannten Mavi-Root-CA.
            if (Test-MaviAuditLeafCertificate -Certificate $certificate -ExpectedRoot $expectedWinRmRoot -ExpectedFqdn $ExpectedFqdn) {
                $managedLeafCount++
                if ($null -eq $latestManagedLeaf -or $certificate.NotAfter -gt $latestManagedLeaf.NotAfter) {
                    $latestManagedLeaf = $certificate
                }
            }
        }
    }
    $result.Certificates.ManagedLeafCount = $managedLeafCount
    if ($null -ne $latestManagedLeaf) {
        $result.Certificates.LatestManagedLeafNotAfter = $latestManagedLeaf.NotAfter.ToUniversalTime().ToString('o')
    }
}
catch { Add-MaviAuditError 'Mavi-Zertifikate' $_ }

$marker = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 6 -Compress))
)
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $false
'''
    return [{
        "name": "Mavi Remote-Verwaltung schreibgeschützt prüfen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi Remote-Verwaltungsartefakte ausschließlich lesen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "WinRmRootThumbprint": winrm_root_thumbprint,
                        "WinRmRootCertificateDerBase64": winrm_root_certificate_der_base64,
                        "BootstrapRootThumbprints": list(bootstrap_root_thumbprints),
                        "CurrentLeafThumbprint": current_leaf_thumbprint,
                        "CurrentKeyPrefix": current_key_prefix,
                        "ExpectedFqdn": expected_fqdn,
                        "CurrentKeyMarker": current_key_marker,
                        "OpenSshFirewallRuleName": openssh_firewall_rule,
                        "OpenSshConfigBackupPath": openssh_config_backup,
                    },
                },
                "register": "mavi_remote_management_audit",
            },
            {
                "name": "Mavi Remote-Verwaltungs-Audit auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_REMOTE_AUDIT_B64={{ mavi_remote_management_audit.result.Marker }}",
                },
            },
        ],
    }]


def _extract_remote_management_audit_result(play_output: str) -> dict[str, Any]:
    """Den schreibgeschützten Windows-Auditmarker auf seine Grundstruktur prüfen."""
    from .remote import _extract_json_marker

    payload = _extract_json_marker(play_output, "Mavi_REMOTE_AUDIT_B64=")
    for section in ("WinRM", "OpenSSH", "Certificates", "CertificateChecks"):
        if not isinstance(payload.get(section), dict):
            raise RuntimeError(f"Der Mavi-Remote-Audit enthält keinen gültigen Abschnitt {section}.")
    query_errors = payload.get("QueryErrors")
    if not isinstance(query_errors, list):
        raise RuntimeError("Der Mavi-Remote-Audit enthält keine gültige Fehlerliste.")
    return payload


def _print_live_audit_certificate_metadata(
    audit: dict[str, Any],
    *,
    winrm_root_thumbprint: str,
    bootstrap_root_thumbprints: tuple[str, ...],
    current_leaf_thumbprint: str,
) -> None:
    """Im Live-Audit gefundene, exakt adressierte Mavi-Zertifikate anzeigen."""
    certificates = audit.get("Certificates")
    if not isinstance(certificates, dict):
        return
    entries = (
        (
            "Live WinRM-Leaf",
            current_leaf_thumbprint,
            "CurrentLeafPresent",
            "CurrentLeafNotAfter",
            30,
            "WinRM-Serverzertifikat",
        ),
        (
            "Live WinRM-Root",
            winrm_root_thumbprint,
            "WinRmRootPresent",
            "WinRmRootNotAfter",
            90,
            "Mavi-WinRM-Root-CA",
        ),
    )
    for label, thumbprint, present_field, expiry_field, warning_days, kind in entries:
        if certificates.get(present_field) is not True:
            continue
        expiry, warning = _certificate_expiry_text(
            certificates.get(expiry_field),
            warning_days=warning_days,
        )
        print(f"{label}:       {thumbprint or '(exakt geprüft)'} — {expiry}")
        if warning:
            print(f"! {kind} läuft bald ab, ist abgelaufen oder das Ablaufdatum ist unlesbar.")

    raw_bootstrap_roots = certificates.get("BootstrapRoots")
    bootstrap_roots = raw_bootstrap_roots if isinstance(raw_bootstrap_roots, dict) else {}
    for thumbprint in bootstrap_root_thumbprints:
        raw_root = bootstrap_roots.get(thumbprint)
        root = raw_root if isinstance(raw_root, dict) else {}
        if root.get("Present") is not True:
            print(f"Live Bootstrap-CA: {thumbprint} — FEHLT")
            continue
        expiry, warning = _certificate_expiry_text(
            root.get("NotAfter"),
            warning_days=90,
        )
        print(f"Live Bootstrap-CA: {thumbprint} — {expiry}")
        if warning:
            print(
                "! Mavi-Bootstrap-Root-CA läuft bald ab, ist abgelaufen "
                "oder das Ablaufdatum ist unlesbar."
            )

    managed_leafs = _audit_nonnegative_count(audit, "Certificates", "ManagedLeafCount")
    if managed_leafs > 0 and certificates.get("CurrentLeafPresent") is not True:
        expiry, warning = _certificate_expiry_text(
            certificates.get("LatestManagedLeafNotAfter"),
            warning_days=30,
        )
        print(f"Live Mavi-Leaf:      {managed_leafs} gefunden — jüngstes: {expiry}")
        if warning:
            print("! Mavi-WinRM-Serverzertifikat läuft bald ab oder ist abgelaufen.")



def _live_audit_transport_options(
    project: Path,
    windows: dict[str, Any],
    host_data: dict[str, Any],
    *,
    requested_ssh_key: Path | None = None,
) -> dict[str, Any]:
    """Live-Audit auf den gespeicherten Kerberos-HTTPS-Transport festlegen."""
    from .remote import (
        _connection_label,
        _psrp_https_inventory_vars,
        _saved_winrm_https_transport,
    )

    connection = _connection_label(windows, host_data)
    options: dict[str, Any] = {"inherit_vault_psrp_credentials": False}
    if connection in {"PSRP", "WinRM"}:
        settings, fqdn, ca_cert, kerberos_principal = _saved_winrm_https_transport(
            project,
            host_data,
        )
        options.update(
            {
                "inherit_vault_psrp_credentials": True,
                "extra_vars": _psrp_https_inventory_vars(
                    settings,
                    fqdn=fqdn,
                    ca_cert=ca_cert,
                ),
                "use_vault_kerberos_ticket": True,
                "kerberos_principal": kerberos_principal,
                "kerberos_target_fqdn": fqdn,
            }
        )
    elif connection == "SSH" and requested_ssh_key is not None:
        options["extra_vars"] = {
            "ansible_ssh_private_key_file": str(requested_ssh_key.expanduser().resolve()),
        }
    return options


def cmd_ssh_status(args: argparse.Namespace) -> None:
    """Lokalen Status und optional einen strikt lesenden Mavi-Remote-Audit zeigen."""

    from .environment import die, ensure_initialized
    from .execution import (
        create_temporary_vault_password_file,
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import (
        _connection_label,
        _effective_host_var,
        _normalized_certificate_thumbprint,
        _run_winrm_temporary_play,
        _ssh_environment_marker,
        _winrm_https_settings,
        get_ssh_settings,
    )
    from .reports import redact_sensitive_text
    ensure_initialized(args.project, quiet=True)
    host = getattr(args, "host", None)
    all_hosts = bool(getattr(args, "all_hosts", False))
    live = bool(getattr(args, "live", False))
    if host and all_hosts:
        die("Bitte entweder einen PC-Namen oder --all verwenden, nicht beides.")
    if live and not host and not all_hosts:
        die("--live benötigt einen PC-Namen oder --all.")

    settings = get_ssh_settings(args.project)
    requested_key_raw = str(getattr(args, "key", None) or "").strip()
    requested_key_path = (
        Path(requested_key_raw).expanduser().resolve()
        if requested_key_raw
        else None
    )
    key_path = requested_key_path or Path(settings["private_key"]).expanduser().resolve()
    pub_path = Path(str(key_path) + ".pub")
    public_key, fingerprint = _public_key_summary(pub_path)
    version = _parse_ansible_core_version()
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()

    print("\nMavi REMOTE-VERWALTUNGSSTATUS")
    print("============================")
    print(f"ssh executable:     {'✓ ' + shutil.which('ssh') if shutil.which('ssh') else 'FEHLT'}")
    print(f"ssh-keygen:         {'✓ ' + shutil.which('ssh-keygen') if shutil.which('ssh-keygen') else 'FEHLT'}")
    if version:
        supported = version >= (2, 18, 0)
        print(f"Ansible Core:       {'.'.join(map(str, version))} {'✓' if supported else '! offiziell Windows-SSH erst ab 2.18'}")
    else:
        print("Ansible Core:       nicht erkannt")
    print(f"Private Key:        {'✓' if key_path.exists() else 'FEHLT'} {key_path}")
    print(f"Public Key:         {'✓' if public_key else 'FEHLT'} {pub_path}")
    print(f"known_hosts:        {'✓' if known_hosts.exists() else 'FEHLT'} {known_hosts}")
    if fingerprint:
        print(f"Fingerprint:        {fingerprint}")
    try:
        bootstrap = _bootstrap_settings(args.project)
        print(f"HTTPS-Basis-URL:    ✓ {bootstrap['base_url']}")
        print(f"HTTPS-Webroot:      {bootstrap['local_dir']}")
        print(f"Ansible-Server-IP:  ✓ {bootstrap['ansible_server_ip']}")
    except ValueError as exc:
        print(f"HTTPS-Bootstrap:    FEHLER — {redact_sensitive_text(exc)}")
    try:
        winrm = _winrm_https_settings(args.project)
        print(f"WinRM-Endziel:      ✓ HTTPS:{winrm['port']} / Kerberos-only")
    except ValueError as exc:
        print(f"WinRM-Endziel:      FEHLER — {redact_sensitive_text(exc)}")

    if not host and not all_hosts:
        print("\nTipp: ssh status <HOST>, ssh status --all oder jeweils mit --live verwenden.")
        return

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    raw_hosts = windows.get("hosts", {})
    hosts = raw_hosts if isinstance(raw_hosts, dict) else {}
    if host:
        if host not in hosts:
            die(f"PC '{host}' ist nicht im Inventory vorhanden.")
        selected_hosts = [host]
    else:
        selected_hosts = sorted(str(name) for name in hosts)
    if not selected_hosts:
        print("\nKeine Windows-PCs im Inventory.")
        return

    selected: list[tuple[str, dict[str, Any]]] = []
    for name in selected_hosts:
        raw_host_data = hosts.get(name)
        selected.append((name, raw_host_data if isinstance(raw_host_data, dict) else {}))

    live_results: dict[str, tuple[dict[str, Any] | None, str]] = {}
    if live:
        vault_file: Path | None = None
        vault_password = getpass.getpass("Vault password (nicht Windows-/Domänenpasswort): ")
        try:
            vault_file = create_temporary_vault_password_file(vault_password)
        except OSError as exc:
            die(f"Temporäre Vault-Datei konnte nicht sicher angelegt werden: {exc}")
        finally:
            vault_password = ""

        def run_live_audit(
            name: str,
            host_data: dict[str, Any],
        ) -> tuple[dict[str, Any] | None, str]:
            try:
                winrm_root_thumbprint, bootstrap_root_thumbprints = _host_known_ca_thumbprints(
                    args.project,
                    host_data,
                )
                winrm_root_der_base64 = _winrm_root_certificate_der_base64_for_thumbprint(
                    args.project,
                    winrm_root_thumbprint,
                )
                winrm_state = host_data.get("mavi_winrm_https")
                current_leaf_thumbprint = (
                    _normalized_certificate_thumbprint(winrm_state.get("certificate_thumbprint"))
                    if isinstance(winrm_state, dict)
                    else ""
                )
                expected_winrm_fqdn = _winrm_leaf_fqdn_for_host(
                    args.project,
                    name,
                    host_data,
                )
                live_key_path = _ssh_private_key_path_for_host(
                    args.project,
                    windows,
                    host_data,
                    requested_key=requested_key_path,
                )
                transport_options = _live_audit_transport_options(
                    args.project,
                    windows,
                    host_data,
                    requested_ssh_key=requested_key_path,
                )
                openssh_artifact_instance_id = _openssh_artifact_instance_id(
                    args.project,
                    host_data,
                )
                output = _run_winrm_temporary_play(
                    args.project,
                    host=name,
                    play=_remote_management_audit_play(
                        winrm_root_thumbprint=winrm_root_thumbprint,
                        winrm_root_certificate_der_base64=winrm_root_der_base64,
                        bootstrap_root_thumbprints=bootstrap_root_thumbprints,
                        current_leaf_thumbprint=current_leaf_thumbprint,
                        current_key_prefix=_public_key_prefix_for_private_key(
                            live_key_path
                        ),
                        expected_fqdn=expected_winrm_fqdn,
                        current_key_marker=_ssh_environment_marker(args.project),
                        openssh_firewall_rule=_openssh_firewall_rule_name(
                            args.project,
                            instance_id=openssh_artifact_instance_id,
                        ),
                        openssh_config_backup=_openssh_config_backup_relative_path(
                            args.project,
                            instance_id=openssh_artifact_instance_id,
                        ),
                    ),
                    vault_password_file=vault_file,
                    description=f"Mavi Live-Audit für {name}",
                    timeout=25.0,
                    **transport_options,
                )
                return _extract_remote_management_audit_result(output), ""
            except (OSError, RuntimeError, ValueError) as exc:
                return None, redact_sensitive_text(exc)

        try:
            worker_count = min(8, len(selected))
            print(
                f"\nLive-Audit: {len(selected)} Host(s), "
                f"maximal {worker_count} gleichzeitig.",
                flush=True,
            )
            with ThreadPoolExecutor(
                max_workers=worker_count,
                thread_name_prefix="mavi-live-audit",
            ) as executor:
                future_hosts = {
                    executor.submit(run_live_audit, name, host_data): name
                    for name, host_data in selected
                }
                for future in as_completed(future_hosts):
                    name = future_hosts[future]
                    result = future.result()
                    live_results[name] = result
                    _, live_error = result
                    progress = "nicht erreichbar/auswertbar" if live_error else "abgeschlossen"
                    symbol = "!" if live_error else "✓"
                    print(f"  {symbol} {name}: {progress}", flush=True)
        finally:
            if vault_file is not None:
                vault_file.unlink(missing_ok=True)

    classifications: list[dict[str, Any]] = []
    print("\nHOSTS")
    print("-----")
    for name, host_data in selected:
        disabled_state = _remote_management_disabled_state(host_data)
        audit, live_error = live_results.get(name, (None, ""))
        status = (
            _classify_remote_management_audit(audit, disabled_state)
            if live
            else _inventory_remote_management_status(windows, host_data)
        )
        classifications.append(status)
        target_host = str(host_data.get("ansible_host", "") or name)
        ssh_port = _ssh_host_key_port(windows, host_data, settings["port"])

        print(f"\n{name} ({target_host})")
        print(f"Remote-Verwaltung:  {status['label']}")
        print(f"Inventory-Eintrag:  {_connection_label(windows, host_data)}")
        print(f"SSH-Port:           {ssh_port}")
        print(f"Host-Key bekannt:   {'✓' if _known_host_present(known_hosts, target_host, ssh_port) else 'NEIN'}")
        if disabled_state:
            recorded = disabled_state.get("recorded_at") or "ohne Zeitstempel"
            print(f"Rückbau-Nachweis:   Version {disabled_state['version']} / {recorded}")
        for detail in status.get("details", []):
            print(f"Hinweis:            {detail}")

        _print_certificate_metadata(host_data)
        if live:
            if live_error:
                print(f"Live-Check:         nicht möglich — {live_error}")
            elif audit is not None:
                print("Live-Check:         abgeschlossen (nur lesend)")
                winrm_root_thumbprint, bootstrap_root_thumbprints = _host_known_ca_thumbprints(
                    args.project,
                    host_data,
                )
                winrm_state = host_data.get("mavi_winrm_https")
                current_leaf_thumbprint = (
                    _normalized_certificate_thumbprint(winrm_state.get("certificate_thumbprint"))
                    if isinstance(winrm_state, dict)
                    else ""
                )
                _print_live_audit_certificate_metadata(
                    audit,
                    winrm_root_thumbprint=winrm_root_thumbprint,
                    bootstrap_root_thumbprints=bootstrap_root_thumbprints,
                    current_leaf_thumbprint=current_leaf_thumbprint,
                )

    if all_hosts:
        counts: dict[str, int] = {}
        for status in classifications:
            code = str(status.get("code", "unknown"))
            counts[code] = counts.get(code, 0) + 1
        inventory_active_count = counts.get("inventory_active", 0)
        active_count = counts.get("active", 0)
        partial_count = counts.get("partial", 0)
        print(
            "\nÜbersicht: "
            f"{counts.get('confirmed_disabled', 0)} live aus, "
            f"{counts.get('disabled_recorded', 0) + counts.get('disabled_unreachable', 0)} "
            "laut Rückbau-Nachweis aus, "
            f"{active_count + partial_count + inventory_active_count} aktiv/teilweise, "
            f"{sum(value for code, value in counts.items() if code.startswith('unknown') or code.startswith('legacy'))} unbekannt."
        )


def ssh_menu(project: Path) -> None:
    from .catalogs import choose_host_interactive, prompt_choice, yes_no
    from .execution import cmd_ping

    while True:
        print()
        print("OPENSSH / WINDOWS")
        print("=================")
        print("  1) Mavi SSH-Key anlegen / anzeigen")
        print("  2) OpenSSH für neuen PC vollautomatisch vorbereiten")
        print("  3) PC auf OpenSSH umstellen")
        print("  4) PC auf geprüftes PSRP/WinRM HTTPS + Kerberos umstellen")
        print("  5) Remote-Verwaltungsstatus / Doctor")
        print("  6) Verbindung testen (win_ping)")
        print("  7) Mavi SSH-Key(s) von Windows-PC(s) entfernen")
        print("  8) nginx/HTTPS/Zertifikat automatisch einrichten oder prüfen")
        print("  9) WinRM über OpenSSH auf HTTPS + Kerberos-only härten")
        print(" 10) WinRM/Kerberos auf Stand 0 setzen (OpenSSH bleibt aktiv)")
        print(" 11) Mavi-Remote-Verwaltung vollständig deaktivieren")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_ssh_keygen(argparse.Namespace(project=project, key=None, yes=False))
            elif choice == "2":
                host = choose_host_interactive(project)
                cmd_ssh_guide(argparse.Namespace(project=project, host=host, key=None, msi=None, prompt_msi=True))
            elif choice == "3":
                host = choose_host_interactive(project)
                cmd_ssh_use(argparse.Namespace(project=project, host=host, key=None, port=None, yes=False))
            elif choice == "4":
                host = choose_host_interactive(project)
                cmd_ssh_use_psrp(argparse.Namespace(project=project, host=host))
            elif choice == "5":
                scope = prompt_choice(
                    "Statusumfang:",
                    [
                        ("1", "Einzelnen PC prüfen"),
                        ("2", "Alle Inventory-PCs prüfen"),
                    ],
                    "1",
                )
                host = choose_host_interactive(project) if scope == "1" else None
                live = yes_no(
                    "Live-Check über den aktuellen Verwaltungsweg ausführen?",
                    default=False,
                )
                cmd_ssh_status(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        all_hosts=(scope == "2"),
                        live=live,
                    )
                )
            elif choice == "6":
                host = choose_host_interactive(project)
                try:
                    cmd_ping(argparse.Namespace(project=project, host=host))
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"\nPing beendet mit Code {exc.code}.")
            elif choice == "7":
                ssh_remove_keys_menu(project)
            elif choice == "8":
                cmd_ssh_setup_check(argparse.Namespace(project=project, msi=None))
            elif choice == "9":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_https(argparse.Namespace(project=project, host=host))
            elif choice == "10":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=False,
                    )
                )
            elif choice == "11":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=True,
                    )
                )
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")

__all__ = (
    "_public_key_summary",
    "_known_hosts_lookup_name",
    "_known_host_present",
    "_fingerprint_known_host_line",
    "ensure_ssh_host_key",
    "cmd_ssh_keygen",
    "_powershell_single_quote",
    "_windows_msi_path_for_ssh_guide",
    "_ssh_bootstrap_ps1",
    "_software_local_and_windows_path",
    "_bootstrap_instance_id",
    "_bootstrap_settings",
    "_bootstrap_setup_instruction",
    "_atomic_write_bytes",
    "_atomic_copy_file",
    "_sha256_file",
    "_bootstrap_pki_paths",
    "_bootstrap_launcher_roots",
    "_root_command",
    "_install_bootstrap_server_packages",
    "_bootstrap_operator_ids",
    "_nginx_quote",
    "_openssl_server_config",
    "_certificate_valid_for",
    "_certificate_sha1_thumbprint",
    "_archive_bootstrap_pki_for_rotation",
    "_create_or_reuse_bootstrap_ca",
    "_archive_bootstrap_root_ca",
    "_controller_bound_bootstrap_root_certificates",
    "_issue_bootstrap_server_certificate",
    "_nginx_bootstrap_config",
    "_ufw_delete_tagged_rules",
    "_configure_bootstrap_firewall",
    "_remove_bootstrap_firewall",
    "_trust_bootstrap_ca_locally",
    "_untrust_bootstrap_ca_locally",
    "_enable_and_reload_nginx",
    "_tcp_port_is_bindable",
    "_tcp_listener_process_names",
    "_managed_nginx_is_active",
    "_bootstrap_url_with_port",
    "_persist_bootstrap_base_url",
    "_select_usable_bootstrap_port",
    "_relaunch_bootstrap_server_setup_as_root",
    "cmd_ssh_server_setup",
    "_ensure_automatic_https_server",
    "_RejectBootstrapRedirects",
    "_strict_https_probe",
    "_https_ssh_bootstrap_cmd",
    "_deliver_ssh_launcher_to_public_desktop",
    "_publish_https_ssh_bootstrap",
    "_local_windows_authenticode_status",
    "cmd_ssh_setup_check",
    "cmd_ssh_guide",
    "cmd_ssh_use",
    "cmd_ssh_winrm_https",
    "cmd_ssh_winrm_reset",
    "cmd_ssh_use_psrp",
    "_mavi_public_key_prefix",
    "_remove_mavi_ssh_keys_from_host",
    "cmd_ssh_remove_keys",
    "ssh_remove_keys_menu",
    "_parse_ansible_core_version",
    "cmd_ssh_status",
    "ssh_menu",
)
