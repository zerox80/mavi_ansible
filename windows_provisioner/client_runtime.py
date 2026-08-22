# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible-Laufzeit für Clientaktionen.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    binascii,
    getpass,
    json,
    re,
    subprocess,
    time,
)

from .remote import (
    _close_client_ansible_session,
    _open_client_ansible_session,
)

from .settings import DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES


def _monitor_timeout_minutes(value: str) -> int:
    try:
        minutes = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Minuten müssen eine ganze Zahl sein."
        ) from exc
    if not 0 <= minutes <= 71_582_788:
        raise argparse.ArgumentTypeError(
            "Minuten müssen zwischen 0 und 71582788 liegen."
        )
    return minutes


def _client_uninstall_timeout_minutes(value: str) -> int:
    try:
        minutes = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Das Zeitlimit muss eine ganze Zahl sein."
        ) from exc
    if not 1 <= minutes <= 1440:
        raise argparse.ArgumentTypeError(
            "Das Zeitlimit muss zwischen 1 und 1440 Minuten liegen."
        )
    return minutes


def _create_prompted_client_vault_file() -> Path:
    from .execution import create_temporary_vault_password_file

    vault_password = getpass.getpass("Vault password: ")
    try:
        return create_temporary_vault_password_file(vault_password)
    finally:
        vault_password = ""


def _wait_for_client_host_ready(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    max_wait_seconds: float = 180.0,
) -> bool:
    """win_ping mit derselben Ansible-/Kerberos-Sitzung wie die Client-Läufe."""
    if str(ansible_session.get("host") or "") != host:
        raise RuntimeError("Die Client-Ansible-Sitzung gehört zu einem anderen PC.")
    ansible_executable = ansible_session.get("ansible_executable")
    ansible_python = ansible_session.get("ansible_python")
    inventory_path = ansible_session.get("inventory_path")
    if not all(isinstance(value, Path) for value in (
        ansible_executable,
        ansible_python,
        inventory_path,
    )):
        raise RuntimeError("Die Client-Ansible-Sitzung ist unvollständig.")

    ansible_ad_hoc = ansible_executable.with_name("ansible")
    if not ansible_ad_hoc.is_file():
        raise RuntimeError(
            "Das ansible-Kommando fehlt in der erkannten Ansible-Umgebung."
        )

    command = [
        str(ansible_python),
        "-I",
        str(ansible_ad_hoc),
        "-i",
        str(inventory_path),
        host,
        "-m",
        "ansible.windows.win_ping",
        "--vault-password-file",
        str(vault_password_file),
    ]
    transport_vars = dict(ansible_session.get("extra_vars") or {})
    if transport_vars:
        command.extend([
            "--extra-vars",
            json.dumps(transport_vars, ensure_ascii=True, separators=(",", ":")),
        ])

    deadline = time.monotonic() + max(1.0, max_wait_seconds)
    first_failure = True
    while True:
        try:
            result = subprocess.run(
                command,
                cwd=str(project),
                env=dict(ansible_session.get("environment") or {}),
                capture_output=True,
                text=True,
                timeout=20.0,
            )
        except (subprocess.TimeoutExpired, OSError):
            result = None

        if result is not None and result.returncode == 0:
            if not first_failure:
                print("[MAVI SMART] Windows-PC ist wieder per Ansible erreichbar.")
            return True
        if time.monotonic() >= deadline:
            return False
        if first_failure:
            print()
            print("[MAVI SMART] Ziel-PC antwortet gerade nicht auf win_ping.")
            print("  Falls eine Deinstallation neu gestartet hat, wartet MAVI automatisch")
            print(f"  bis zu {max_wait_seconds:g}s auf die Rückkehr des PCs.")
            first_failure = False
        time.sleep(10.0)


def _client_playbook_failure_detail(
    output: str,
    marker_name: str,
) -> str:
    """Die echte Ansible-Fehlerzeile ohne PLAY-RECAP-Rauschen liefern."""
    from .reports import redact_sensitive_text

    candidates: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or marker_name in line:
            continue
        if line.upper().startswith("PLAY RECAP"):
            continue
        if re.search(
            r"\bok=\d+\s+changed=\d+\s+unreachable=\d+\s+failed=\d+",
            line,
            flags=re.IGNORECASE,
        ):
            continue
        candidates.append(line)

    if not candidates:
        return ""

    failure_lines = [
        line
        for line in candidates
        if re.search(
            r"(?:\bfatal:|FAILED!|UNREACHABLE!|\[ERROR\]|\bERROR!|"
            r"Task failed|Module failed|Exception|\bmsg\s*[:=])",
            line,
            flags=re.IGNORECASE,
        )
    ]
    detail = failure_lines[-1] if failure_lines else candidates[-1]
    return redact_sensitive_text(detail[:1200])


def _run_client_playbook_result(
    *,
    project: Path,
    host: str,
    playbook: Path,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    extra_vars: dict[str, Any],
    marker_name: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    from .clients import (
        _client_playbook_failure_detail,
    )

    from .execution import strip_ansi
    from .remote import _host_inventory_entry
    from .reports import redact_sensitive_text

    _host_inventory_entry(project, host)
    if str(ansible_session.get("host") or "") != host:
        raise RuntimeError("Die Client-Ansible-Sitzung gehört zu einem anderen PC.")
    ansible_executable = ansible_session.get("ansible_executable")
    ansible_python = ansible_session.get("ansible_python")
    inventory_path = ansible_session.get("inventory_path")
    if not all(isinstance(value, Path) for value in (
        ansible_executable,
        ansible_python,
        inventory_path,
    )):
        raise RuntimeError("Die Client-Ansible-Sitzung ist unvollständig.")

    effective_extra_vars = dict(extra_vars)
    effective_extra_vars.update(dict(ansible_session.get("extra_vars") or {}))

    command = [
        str(ansible_python),
        "-I",
        str(ansible_executable),
        "-i",
        str(inventory_path),
        str(playbook),
        "--limit",
        host,
        "--vault-password-file",
        str(vault_password_file),
        "--extra-vars",
        json.dumps(
            effective_extra_vars,
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=str(project),
            env=dict(ansible_session.get("environment") or {}),
            capture_output=True,
            text=True,
            timeout=max(10.0, timeout_seconds),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Der Windows-PC hat innerhalb des vorgesehenen Zeitlimits "
            "kein auswertbares Ergebnis geliefert."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"Ansible konnte nicht gestartet werden: {redact_sensitive_text(exc)}"
        ) from exc

    combined = strip_ansi(
        (completed.stdout or "") + "\n" + (completed.stderr or "")
    )
    matches = re.findall(
        rf"{re.escape(marker_name)}=([A-Za-z0-9+/=]+)",
        combined,
    )

    if completed.returncode != 0 or len(matches) != 1:
        failure_detail = _client_playbook_failure_detail(
            combined,
            marker_name,
        )
        detail = ""
        if failure_detail:
            detail = ": " + failure_detail
        raise RuntimeError(
            "Der Client-Playbooklauf konnte nicht ausgewertet werden"
            + detail
        )

    encoded = matches[0]
    if len(encoded) > 16 * 1024 * 1024:
        raise RuntimeError("Das Client-Ergebnis ist unerwartet groß.")

    try:
        decoded = json.loads(
            base64.b64decode(encoded, validate=True).decode("utf-8")
        )
    except (
        binascii.Error,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise RuntimeError(
            "Der Windows-PC lieferte ein ungültiges Client-Ergebnis."
        ) from exc

    if not isinstance(decoded, dict) or int(decoded.get("schema", decoded.get("Schema", 0)) or 0) != 1:
        raise RuntimeError("Das Client-Ergebnis hat ein unbekanntes Format.")
    return decoded
