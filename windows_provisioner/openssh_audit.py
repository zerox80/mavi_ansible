# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Remote-Verwaltungs-Audit.

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
    from .openssh import (
        _bootstrap_state_thumbprints,
    )

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
    from .openssh import (
        _remote_management_disabled_state,
        _verified_bootstrap_root_thumbprints,
    )

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

    from .openssh import (
        _remote_management_disabled_state,
        _stored_bootstrap_root_thumbprints,
    )

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
    from .openssh import (
        _certificate_expiry_text,
    )

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
    from .openssh import (
        _audit_value,
    )

    value = _audit_value(audit, section, field, -1)
    if isinstance(value, bool):
        return -1
    try:
        number = int(value)
    except (TypeError, ValueError):
        return -1
    return number if number >= 0 else -1


def _audit_service_is_disabled_or_absent(audit: dict[str, Any], section: str) -> bool:
    from .openssh import (
        _audit_value,
    )

    exists = _audit_value(audit, section, "Exists", None)
    if exists is False:
        return True
    start = _audit_value(audit, section, "Start", -1)
    status = str(_audit_value(audit, section, "Status", "") or "").casefold()
    return start == 4 and status == "stopped"


def _audit_service_state_is_unknown(audit: dict[str, Any], section: str) -> bool:
    """Nur einen tatsächlich gelesenen Dienstzustand als aktiv/inaktiv werten."""
    from .openssh import (
        _audit_value,
    )

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
    from .openssh import (
        _audit_nonnegative_count,
        _audit_service_is_disabled_or_absent,
        _audit_service_state_is_unknown,
        _audit_value,
    )

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

    from .openssh import (
        _remote_management_disabled_state,
    )

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

    from .openssh import (
        _audit_nonnegative_count,
        _certificate_expiry_text,
    )

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

    from .openssh import (
        _openssh_artifact_instance_id,
        _openssh_config_backup_relative_path,
        _openssh_firewall_rule_name,
    )

    from .openssh import (
        _bootstrap_settings,
        _classify_remote_management_audit,
        _extract_remote_management_audit_result,
        _host_known_ca_thumbprints,
        _inventory_remote_management_status,
        _known_host_present,
        _live_audit_transport_options,
        _parse_ansible_core_version,
        _print_certificate_metadata,
        _print_live_audit_certificate_metadata,
        _public_key_prefix_for_private_key,
        _public_key_summary,
        _remote_management_audit_play,
        _remote_management_disabled_state,
        _ssh_host_key_port,
        _ssh_private_key_path_for_host,
        _winrm_leaf_fqdn_for_host,
        _winrm_root_certificate_der_base64_for_thumbprint,
    )


    from .environment import die, ensure_initialized
    from .execution import (
        create_temporary_vault_password_file,
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import (
        _connection_label,
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
