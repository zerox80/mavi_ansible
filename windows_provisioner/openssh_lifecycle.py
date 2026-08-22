# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Mavi-eigene OpenSSH-Artefakte und deren Lifecycle."""

from __future__ import annotations


from ._dependencies import (
    Any,
    Path,
    hashlib,
    json,
    os,
    re,
    shutil,
    ssl,
    subprocess,
    tempfile,
    time,
    yaml,
)


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

    from .openssh import (
        _atomic_write_bytes,
        _sha256_file,
    )
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


def _ufw_delete_tagged_rules(ufw: str, tag: str) -> None:
    """Nur eindeutig mit der aktuellen Instanz markierte UFW-Regeln entfernen."""

    from .openssh import (
        _root_command,
    )
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


def _remove_bootstrap_firewall(state: dict[str, Any]) -> None:
    """Nur im Serverstatus ausgewiesene Firewall-Ressourcen dieser Instanz entfernen."""

    from .openssh import (
        _root_command,
    )
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


def _untrust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    """Nur die Vertrauensanker der aktuellen Bootstrap-Instanz entfernen."""

    from .openssh import (
        _root_command,
    )
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


def _mavi_public_key_prefix(project: Path) -> str:
    """Nur Key-Typ + Base64-Payload, ohne Kommentar, für exakten Remote-Abgleich."""

    from .openssh import (
        _public_key_prefix_from_path,
    )
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
