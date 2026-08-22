# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Temporäre WinRM-Playbooks und Ergebnismarker.

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



def _run_winrm_temporary_play(
    project: Path,
    *,
    host: str,
    play: list[dict[str, Any]],
    vault_password_file: Path,
    description: str,
    extra_vars: dict[str, Any] | None = None,
    inherit_vault_psrp_credentials: bool = False,
    use_vault_kerberos_ticket: bool = False,
    kerberos_principal: str = "",
    kerberos_target_fqdn: str = "",
    timeout: float = 180.0,
) -> str:
    """Kurzlebigen Ansible-Play sicher ausführen und Fehler kompakt schwärzen."""

    from .remote import (
        _kerberos_cache_connection_overrides,
    )
    from .remote import (
        _acquire_vault_kerberos_ticket,
        _ansible_playbook_runtime,
        _ansible_runtime_environment,
        _discard_kerberos_ticket_cache,
        _temporary_single_host_inventory,
    )

    from .environment import (
        atomic_write_yaml,
    )
    from .execution import strip_ansi
    from .reports import redact_sensitive_text

    playbook_path: Path | None = None
    temporary_inventory_path: Path | None = None
    kerberos_ticket_directory: Path | None = None
    kerberos_ticket_path: Path | None = None
    effective_extra_vars = dict(extra_vars or {})
    try:
        fd, raw_path = tempfile.mkstemp(prefix=".mavi-winrm-tls-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_path)
        atomic_write_yaml(playbook_path, play)

        temporary_inventory_path = _temporary_single_host_inventory(
            project,
            host,
            inherit_vault_psrp_credentials=inherit_vault_psrp_credentials,
        )
        inventory_path = temporary_inventory_path

        ansible_executable, ansible_python = _ansible_playbook_runtime()
        runtime_environment = _ansible_runtime_environment(ansible_python)
        if use_vault_kerberos_ticket:
            kerberos_ticket_directory, kerberos_ticket_path, cache_principal = _acquire_vault_kerberos_ticket(
                project,
                host=host,
                vault_password_file=vault_password_file,
                kerberos_principal=kerberos_principal,
                ansible_python=ansible_python,
                target_fqdn=kerberos_target_fqdn,
            )
            runtime_environment["KRB5CCNAME"] = f"FILE:{kerberos_ticket_path}"
            # pyspnego verwendet bei einem nichtleeren Benutzernamen eine
            # benannte Cache-Credential. Das war der Auslöser für den echten
            # "Matching credential not found"-Fehler. Leere Werte sind hier
            # kein Fallback: Sie zwingen ausschließlich den vorher geprüften
            # Standard-CCache; weder Passwort noch NTLM stehen diesem Proof
            # zur Verfügung.
            effective_extra_vars.update(_kerberos_cache_connection_overrides())
            print(
                f"  ✓ Privater Kerberos-Cache: {cache_principal}; "
                f"host/{kerberos_target_fqdn} ist bestätigt."
            )
        command = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i", str(inventory_path),
            str(playbook_path),
            "--vault-password-file", str(vault_password_file),
        ]
        if effective_extra_vars:
            # Die Overlay-Variablen enthalten ausschließlich Transport- und
            # Zertifikatspfade sowie explizit leere Credential-Sperren, nie
            # ein Passwort oder privates Schlüsselmaterial.
            command.extend([
                "--extra-vars",
                json.dumps(effective_extra_vars, ensure_ascii=True, separators=(",", ":")),
            ])
        try:
            completed = subprocess.run(
                command,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{description} hat nach {int(timeout)} Sekunden nicht geantwortet.") from exc
        except OSError as exc:
            raise RuntimeError(f"{description} konnte nicht gestartet werden: {redact_sensitive_text(exc)}") from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        if completed.returncode != 0:
            folded = combined.casefold()
            if "decryption failed" in folded or "no vault secrets" in folded:
                raise RuntimeError(
                    "Der Ansible-Vault konnte nicht entschlüsselt werden. "
                    "Bitte das Mavi-Vault-Passwort eingeben, nicht das Domänen-/Windows-Passwort."
                )
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-12:])
            raise RuntimeError(
                f"{description} ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )
        return combined
    finally:
        if kerberos_ticket_directory is not None and kerberos_ticket_path is not None:
            _discard_kerberos_ticket_cache(kerberos_ticket_directory, kerberos_ticket_path)
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if temporary_inventory_path is not None:
            temporary_inventory_path.unlink(missing_ok=True)


def _winrm_csr_play(
    *,
    identity: dict[str, Any],
    request_id: str,
) -> list[dict[str, Any]]:
    """Play, der den privaten Schlüssel ausschließlich auf Windows erzeugt."""
    ip_san = str((identity.get("ip_sans") or [""])[0] or "")
    powershell = r'''[CmdletBinding()]
param(
    [string]$Fqdn,
    [string]$ShortName,
    [string]$IpSan,
    [string]$RequestId
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Fqdn) -or [string]::IsNullOrWhiteSpace($ShortName)) {
    throw 'Mavi WinRM TLS: FQDN oder Kurzname fehlt.'
}
if ($RequestId -notmatch '^[a-f0-9]{16,64}$') {
    throw 'Mavi WinRM TLS: interne Request-ID ist ungültig.'
}
if ($IpSan) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($IpSan, [ref]$parsedIp)) {
        throw "Mavi WinRM TLS: IP-SAN ist ungültig: $IpSan"
    }
}

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
if (-not (Test-Path -LiteralPath $certreq -PathType Leaf)) {
    throw "certreq.exe fehlt: $certreq"
}
$workDir = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$infPath = Join-Path $workDir ("request-$RequestId.inf")
$csrPath = Join-Path $workDir ("request-$RequestId.req")
Remove-Item -LiteralPath $infPath, $csrPath -Force -ErrorAction SilentlyContinue

$sanParts = @("dns=$Fqdn", "dns=$ShortName")
if (-not [string]::IsNullOrWhiteSpace($IpSan)) {
    $sanParts += "ipaddress=$IpSan"
}
$sanText = $sanParts -join '&'
$infLines = @(
    '[Version]',
    'Signature="$Windows NT$"',
    '',
    '[NewRequest]',
    ('Subject = "CN=' + $Fqdn + '"'),
    'KeyAlgorithm = RSA',
    'KeyLength = 3072',
    'HashAlgorithm = sha256',
    'MachineKeySet = TRUE',
    'Exportable = FALSE',
    'ProviderName = "Microsoft Software Key Storage Provider"',
    'RequestType = PKCS10',
    'KeyUsage = 0xa0',
    ('FriendlyName = "Mavi WinRM HTTPS ' + $Fqdn + '"'),
    '',
    '[Extensions]',
    '2.5.29.17 = "{text}"',
    ('_continue_ = "' + $sanText + '"'),
    '2.5.29.37 = "{text}"',
    '_continue_ = "1.3.6.1.5.5.7.3.1"'
)
Set-Content -LiteralPath $infPath -Value $infLines -Encoding ascii -Force
& $certreq -new $infPath $csrPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
    throw "certreq -new konnte keine CSR erzeugen (Exit-Code $LASTEXITCODE)."
}

$csrText = [System.IO.File]::ReadAllText($csrPath, [System.Text.Encoding]::ASCII)
if ($csrText -notmatch 'BEGIN (NEW )?CERTIFICATE REQUEST') {
    throw 'certreq lieferte keine PEM-kodierte Zertifikatsanfrage.'
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($csrText))
$Ansible.Result = @{ CsrMarker = $marker; RequestPath = $csrPath }
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM TLS CSR sicher auf Windows erzeugen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Nicht exportierbaren WinRM-Serverschlüssel und CSR erstellen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "Fqdn": identity["fqdn"],
                        "ShortName": identity["short_name"],
                        "IpSan": ip_san,
                        "RequestId": request_id,
                    },
                },
                "register": "mavi_winrm_csr",
            },
            {
                "name": "Mavi WinRM CSR an den Controller zurückgeben",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_CSR_B64_BEGIN={{ mavi_winrm_csr.result.CsrMarker }}_END",
                },
            },
        ],
    }]


def _extract_json_marker(play_output: str, marker: str) -> dict[str, Any]:
    """Einen von PowerShell erzeugten, Base64-kodierten JSON-Ergebnismarker prüfen."""
    escaped_marker = re.escape(str(marker or ""))
    matches = re.findall(
        escaped_marker + r"([A-Za-z0-9+/=]+)",
        str(play_output or ""),
    )
    if not matches:
        raise RuntimeError(f"Der erwartete Mavi-Ergebnismarker fehlt: {marker}")
    if len(matches) != 1:
        raise RuntimeError(
            f"Der Mavi-Ergebnismarker {marker} ist nicht eindeutig."
        )
    try:
        decoded = base64.b64decode(matches[0], validate=True)
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Der Mavi-Ergebnismarker {marker} ist nicht lesbar.") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Der Mavi-Ergebnismarker {marker} enthält kein Objekt.")
    return payload


def _bootstrap_certificate_identities(
    values: list[str] | tuple[str, ...],
) -> list[tuple[str, str]]:
    """DER-kodierte Controller-Zertifikate kanonisieren und per SHA-1 benennen."""
    from .remote import (
        _certificate_thumbprint_from_der,
    )

    identities: list[tuple[str, str]] = []
    by_thumbprint: dict[str, str] = {}
    for value in values:
        encoded = str(value or "").strip()
        try:
            certificate_der = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Eine Bootstrap-CA ist nicht als gültiges DER/Base64 kodiert.") from exc
        if not certificate_der or len(certificate_der) > 1024 * 1024:
            raise ValueError("Eine Bootstrap-CA besitzt eine ungültige DER-Größe.")
        canonical = base64.b64encode(certificate_der).decode("ascii")
        thumbprint = _certificate_thumbprint_from_der(certificate_der)
        existing = by_thumbprint.get(thumbprint)
        if existing is not None:
            if not secrets.compare_digest(existing, canonical):
                raise ValueError("Bootstrap-CA-DER kollidiert unter demselben Thumbprint.")
            continue
        by_thumbprint[thumbprint] = canonical
        identities.append((thumbprint, canonical))
    return identities


def _bootstrap_ca_probe_play(
    *,
    current_root_certificate_der_base64: str,
    candidate_root_certificates_der_base64: list[str],
    require_current_root: bool = True,
) -> list[dict[str, Any]]:
    """Controllergebundene Bootstrap-CA-DER direkt auf dem Zielhost belegen."""
    from .remote import (
        _bootstrap_certificate_identities,
    )

    current_identities = _bootstrap_certificate_identities(
        [current_root_certificate_der_base64]
    )
    identities = _bootstrap_certificate_identities(
        [
            current_root_certificate_der_base64,
            *candidate_root_certificates_der_base64,
        ]
    )
    if len(current_identities) != 1 or not identities:
        raise ValueError("Die aktuelle Mavi-Bootstrap-CA besitzt keine gültige DER-Identität.")
    current_der_base64 = current_identities[0][1]
    candidates = [encoded for _thumbprint, encoded in identities]

    powershell = r'''[CmdletBinding()]
param(
    [string]$CurrentRootCertificateDerBase64,
    [string[]]$CandidateRootCertificatesDerBase64,
    [int]$RequireCurrentRootValue = 1
)

$ErrorActionPreference = 'Stop'
$requireCurrentRoot = ($RequireCurrentRootValue -eq 1)
$expectedRoots = [ordered]@{}
foreach ($encodedCandidate in @($CandidateRootCertificatesDerBase64)) {
    try {
        [byte[]]$expectedDer = [Convert]::FromBase64String(([string]$encodedCandidate).Trim())
        if ($expectedDer.Count -eq 0 -or $expectedDer.Count -gt 1MB) {
            throw 'ungültige DER-Größe'
        }
        $expectedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $expectedDer
        )
    }
    catch {
        throw 'Mavi Bootstrap-Nachweis: Eine controllerseitige Root-CA ist kein gültiges DER-Zertifikat.'
    }
    $thumbprint = (([string]$expectedCertificate.Thumbprint) -replace '\s', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'Mavi Bootstrap-Nachweis: Eine controllerseitige Root-CA besitzt keinen gültigen Fingerabdruck.'
    }
    $basicConstraints = @(
        $expectedCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.19' }
    ) | Select-Object -First 1
    if ($null -eq $basicConstraints) {
        throw 'Mavi Bootstrap-Nachweis: Das erwartete Zertifikat besitzt keine CA-BasicConstraints.'
    }
    $decodedConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
    $decodedConstraints.CopyFrom($basicConstraints)
    if (-not $decodedConstraints.CertificateAuthority) {
        throw 'Mavi Bootstrap-Nachweis: Das erwartete Zertifikat ist keine CA.'
    }
    $canonicalDerBase64 = [Convert]::ToBase64String($expectedCertificate.RawData)
    if ($expectedRoots.Contains($thumbprint)) {
        if ([string]$expectedRoots[$thumbprint] -cne $canonicalDerBase64) {
            throw 'Mavi Bootstrap-Nachweis: Zwei Controller-Zertifikate kollidieren unter demselben Thumbprint.'
        }
        continue
    }
    $expectedRoots[$thumbprint] = $canonicalDerBase64
}
if ($expectedRoots.Count -eq 0) {
    throw 'Mavi Bootstrap-Nachweis: Es wurden keine controllergebundenen Root-Identitäten übergeben.'
}
try {
    $currentCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($CurrentRootCertificateDerBase64.Trim())
    )
}
catch {
    throw 'Mavi Bootstrap-Nachweis: Die aktuelle controllerseitige Root-CA ist ungültig.'
}
$CurrentRootThumbprint = (([string]$currentCertificate.Thumbprint) -replace '\s', '').ToUpperInvariant()
$currentDerBase64 = [Convert]::ToBase64String($currentCertificate.RawData)
if (
    $CurrentRootThumbprint -notmatch '^[A-F0-9]{40}$' -or
    -not $expectedRoots.Contains($CurrentRootThumbprint) -or
    [string]$expectedRoots[$CurrentRootThumbprint] -cne $currentDerBase64
) {
    throw 'Mavi Bootstrap-Nachweis: Die aktuelle Root-CA gehört nicht zum controllergebundenen Zertifikatssatz.'
}
$CandidateRootThumbprints = @($expectedRoots.Keys)

$presentThumbprints = @()
foreach ($thumbprint in $CandidateRootThumbprints) {
    $certificate = Get-Item -LiteralPath ("Cert:\LocalMachine\Root\$thumbprint") -ErrorAction SilentlyContinue
    if ($null -eq $certificate) {
        continue
    }
    $actualThumbprint = (([string]$certificate.Thumbprint) -replace '\s', '').ToUpperInvariant()
    if (-not $actualThumbprint.Equals($thumbprint, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mavi Bootstrap-Nachweis: Zertifikatspfad und Zertifikat-Fingerabdruck widersprechen sich.'
    }
    $actualDerBase64 = [Convert]::ToBase64String($certificate.RawData)
    if ($actualDerBase64 -cne [string]$expectedRoots[$thumbprint]) {
        throw 'Mavi Bootstrap-Nachweis: Das Root-Store-Zertifikat stimmt nicht bytegenau mit der Controller-CA überein.'
    }
    $presentThumbprints += $actualThumbprint
}

if ($requireCurrentRoot -and $presentThumbprints -notcontains $CurrentRootThumbprint) {
    throw 'Mavi Bootstrap-Nachweis: Die aktuell veröffentlichte Bootstrap-CA ist auf diesem Windows-Host nicht installiert.'
}
if (-not $requireCurrentRoot -and @($presentThumbprints).Count -eq 0) {
    throw 'Mavi Bootstrap-Nachweis: Keine der exakt bekannten Bootstrap-CAs ist auf diesem Windows-Host installiert.'
}

$result = [ordered]@{
    CurrentRootThumbprint = $CurrentRootThumbprint
    PresentRootThumbprints = @($presentThumbprints)
}
$marker = [Convert]::ToBase64String(
    [System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 4 -Compress))
)
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $false
'''
    return [{
        "name": "Mavi Bootstrap-CA direkt auf dem Windows-Host belegen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Exakte Mavi-Bootstrap-CA im Windows Root Store prüfen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CurrentRootCertificateDerBase64": current_der_base64,
                        "CandidateRootCertificatesDerBase64": candidates,
                        "RequireCurrentRootValue": 1 if require_current_root else 0,
                    },
                },
                "register": "mavi_bootstrap_ca_probe",
            },
            {
                "name": "Mavi Bootstrap-CA-Nachweis auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_BOOTSTRAP_CA_B64={{ mavi_bootstrap_ca_probe.result.Marker }}",
                },
            },
        ],
    }]


def _extract_bootstrap_ca_probe_result(
    play_output: str,
    *,
    require_current_root: bool = True,
) -> dict[str, Any]:
    """Den hostseitigen Bootstrap-CA-Nachweis strikt validieren."""

    from .remote import (
        _extract_json_marker,
        _normalized_certificate_thumbprint,
    )

    payload = _extract_json_marker(play_output, "Mavi_BOOTSTRAP_CA_B64=")
    current = _normalized_certificate_thumbprint(payload.get("CurrentRootThumbprint"))
    raw_present = payload.get("PresentRootThumbprints")
    if isinstance(raw_present, str):
        raw_present = [raw_present]
    if not isinstance(raw_present, list):
        raise RuntimeError("Der Mavi-Bootstrap-Nachweis enthält keine gültige CA-Liste.")
    present: list[str] = []
    for value in raw_present:
        thumbprint = _normalized_certificate_thumbprint(value)
        if not thumbprint:
            raise RuntimeError("Der Mavi-Bootstrap-Nachweis enthält einen ungültigen CA-Fingerabdruck.")
        if thumbprint not in present:
            present.append(thumbprint)
    if not current:
        raise RuntimeError("Der Mavi-Bootstrap-Nachweis enthält keine gültige Bezugs-CA.")
    if require_current_root and current not in present:
        raise RuntimeError(
            "Der Mavi-Bootstrap-Nachweis bestätigt die aktuelle CA nicht auf dem Zielhost."
        )
    if not present:
        raise RuntimeError(
            "Der Mavi-Bootstrap-Nachweis bestätigt keine der exakt bekannten CAs auf dem Zielhost."
        )
    return {
        "current_root_thumbprint": current,
        "present_root_thumbprints": present,
    }


def _normalized_certificate_timestamp(value: Any, *, label: str) -> str:
    """Ein mit Zeitzone geliefertes Zertifikatsablaufdatum in UTC normalisieren."""
    raw = str(value or "").strip()
    if not raw:
        raise RuntimeError(f"{label} fehlt.")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{label} ist kein gültiges ISO-8601-Datum.") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"{label} enthält keine Zeitzone.")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _marker_nonnegative_int(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool):
        raise RuntimeError(f"Der Mavi-Ergebniswert {field} ist ungültig.")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"Der Mavi-Ergebniswert {field} fehlt oder ist ungültig.") from exc
    if normalized < 0:
        raise RuntimeError(f"Der Mavi-Ergebniswert {field} darf nicht negativ sein.")
    return normalized


def _extract_winrm_https_install_result(play_output: str) -> dict[str, Any]:
    """Den Abschlussbeleg der Windows-HTTPS-Installation strikt validieren."""

    from .remote import (
        _extract_json_marker,
        _marker_nonnegative_int,
        _normalized_certificate_thumbprint,
        _normalized_certificate_timestamp,
    )

    payload = _extract_json_marker(play_output, "Mavi_WINRM_HTTPS_B64=")
    thumbprint = _normalized_certificate_thumbprint(payload.get("Thumbprint"))
    root_thumbprint = _normalized_certificate_thumbprint(payload.get("RootThumbprint"))
    certificate_sha256 = str(payload.get("CertificateSha256", "") or "").strip().lower()
    fqdn = str(payload.get("Fqdn", "") or "").strip().lower()
    if not thumbprint or not root_thumbprint:
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg enthält keinen gültigen Zertifikat-Thumbprint.")
    if not re.fullmatch(r"[a-f0-9]{64}", certificate_sha256):
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg enthält keinen gültigen Zertifikat-SHA-256.")
    if not fqdn:
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg enthält keinen FQDN.")
    try:
        port = int(payload.get("Port"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg enthält keinen gültigen Port.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg enthält einen ungültigen Port.")
    if payload.get("KerberosOnly") is not True or payload.get("Http5985Blocked") is not True:
        raise RuntimeError("Der Mavi-WinRM-HTTPS-Abschlussbeleg bestätigt nicht den Kerberos-only-Endzustand.")
    return {
        "thumbprint": thumbprint,
        "root_thumbprint": root_thumbprint,
        "certificate_sha256": certificate_sha256,
        "certificate_not_after": _normalized_certificate_timestamp(
            payload.get("NotAfterUtc"),
            label="Das Ablaufdatum des Mavi-WinRM-Serverzertifikats",
        ),
        "root_not_after": _normalized_certificate_timestamp(
            payload.get("RootNotAfterUtc"),
            label="Das Ablaufdatum der Mavi-WinRM-Root-CA",
        ),
        "pruned_server_certificates": _marker_nonnegative_int(payload, "PrunedServerCertificates"),
        "fqdn": fqdn,
        "port": port,
    }


def _extract_winrm_reset_result(play_output: str) -> dict[str, Any]:
    """Den atomaren Rückbau-Nachweis des Windows-Hosts validieren."""

    from .remote import (
        _extract_json_marker,
        _marker_nonnegative_int,
        _normalized_certificate_thumbprint,
    )

    payload = _extract_json_marker(play_output, "Mavi_REMOTE_RESET_B64=")
    raw_bootstrap_thumbprints = payload.get("BootstrapRootThumbprints")
    if isinstance(raw_bootstrap_thumbprints, str):
        raw_bootstrap_thumbprints = [raw_bootstrap_thumbprints]
    if not isinstance(raw_bootstrap_thumbprints, list):
        raw_bootstrap_thumbprints = [payload.get("BootstrapRootThumbprint")]
    bootstrap_thumbprints: list[str] = []
    for value in raw_bootstrap_thumbprints:
        thumbprint = _normalized_certificate_thumbprint(value)
        if str(value or "").strip() and not thumbprint:
            raise RuntimeError(
                "Der Mavi-Rückbau-Nachweis enthält einen ungültigen Bootstrap-CA-Fingerabdruck."
            )
        if thumbprint and thumbprint not in bootstrap_thumbprints:
            bootstrap_thumbprints.append(thumbprint)
    result = {
        "removed_listeners": _marker_nonnegative_int(payload, "RemovedListeners"),
        "removed_certificates": _marker_nonnegative_int(payload, "RemovedCertificates"),
        "removed_firewall_rules": _marker_nonnegative_int(payload, "RemovedFirewallRules"),
        "removed_openssh_firewall_rules": _marker_nonnegative_int(
            payload, "RemovedOpenSshFirewallRules"
        ),
        "removed_openssh_keys": _marker_nonnegative_int(payload, "RemovedOpenSshKeys"),
        "removed_openssh_config_backups": _marker_nonnegative_int(
            payload, "RemovedOpenSshConfigBackups"
        ),
        "removed_bootstrap_certificates": _marker_nonnegative_int(
            payload, "RemovedBootstrapCertificates"
        ),
        "bootstrap_scope_verified": payload.get("BootstrapScopeVerified") is True,
        "openssh_disable_scheduled": payload.get("OpenSshDisableScheduled") is True,
        "openssh_startup_disabled": payload.get("OpenSshStartupDisabled") is True,
        "openssh_stopped_verified": payload.get("OpenSshStoppedVerified") is True,
        "openssh_state": str(payload.get("OpenSshState", "") or ""),
        "openssh_start_mode": str(payload.get("OpenSshStartMode", "") or ""),
        "winrm_state": str(payload.get("WinRMState", "") or ""),
        "winrm_start_mode": str(payload.get("WinRMStartMode", "") or ""),
        "winrm_scope_verified": payload.get("WinRmScopeVerified") is True,
        "winrm_listeners_cleared": payload.get("WinRmListenersCleared") is True,
        "preserved_foreign_winrm_listeners": _marker_nonnegative_int(
            payload, "PreservedForeignWinRmListeners"
        ),
        "winrm_root_thumbprint": _normalized_certificate_thumbprint(
            payload.get("WinRmRootThumbprint")
        ),
        "bootstrap_root_thumbprint": _normalized_certificate_thumbprint(
            payload.get("BootstrapRootThumbprint")
        ),
        "bootstrap_root_thumbprints": bootstrap_thumbprints,
    }
    if result["winrm_state"].casefold() != "stopped" or result["winrm_start_mode"].casefold() != "disabled":
        raise RuntimeError("Der Mavi-Rückbau-Nachweis bestätigt keinen gestoppten und deaktivierten WinRM-Dienst.")
    if result["winrm_listeners_cleared"] != (
        result["preserved_foreign_winrm_listeners"] == 0
    ):
        raise RuntimeError(
            "Der Mavi-Rückbau-Nachweis widerspricht sich beim verbleibenden WinRM-Listener-Bestand."
        )
    if result["openssh_stopped_verified"] != (
        result["openssh_state"].casefold() == "stopped"
    ):
        raise RuntimeError(
            "Der Mavi-Rückbau-Nachweis widerspricht sich beim tatsächlichen sshd-Endzustand."
        )
    if result["openssh_startup_disabled"] != (
        result["openssh_start_mode"].casefold() == "disabled"
    ):
        raise RuntimeError(
            "Der Mavi-Rückbau-Nachweis widerspricht sich beim sshd-Startmodus."
        )
    if result["bootstrap_scope_verified"] and not result["bootstrap_root_thumbprints"]:
        raise RuntimeError(
            "Der Mavi-Rückbau-Nachweis bestätigt eine Bootstrap-Bereinigung ohne exakte CA-Identität."
        )
    if (
        result["bootstrap_root_thumbprints"]
        and result["bootstrap_root_thumbprint"] != result["bootstrap_root_thumbprints"][0]
    ):
        raise RuntimeError(
            "Der Mavi-Rückbau-Nachweis widerspricht sich bei der primären Bootstrap-CA."
        )
    return result


def _extract_winrm_csr(play_output: str) -> bytes:
    """Die nur öffentliche CSR aus der Ansible-Ausgabe eindeutig entnehmen."""
    match = re.search(
        r"Mavi_WINRM_CSR_B64_BEGIN=([A-Za-z0-9+/=\s]+?)_END",
        str(play_output or ""),
    )
    if not match:
        raise RuntimeError("Die Windows-CSR wurde nicht vollständig an Mavi zurückgegeben.")
    encoded = re.sub(r"\s+", "", match.group(1))
    try:
        csr = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("Die Windows-CSR ist nicht gültig Base64-kodiert.") from exc
    decoded = csr.decode("ascii", errors="replace")
    if "BEGIN CERTIFICATE REQUEST" not in decoded and "BEGIN NEW CERTIFICATE REQUEST" not in decoded:
        raise RuntimeError("Die zurückgegebene Windows-CSR hat kein erwartetes PEM-Format.")
    return csr
