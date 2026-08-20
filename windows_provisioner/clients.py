# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""Windows-Clientoptimierung und Programmbereinigung."""

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


def _run_client_optimize(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    disable_fast_startup: bool = False,
    monitor_timeout_ac: int | None = None,
    monitor_timeout_dc: int | None = None,
) -> dict[str, Any]:
    from .environment import project_paths

    return _run_client_playbook_result(
        project=project,
        host=host,
        playbook=project_paths(project)["client_optimize_playbook"],
        vault_password_file=vault_password_file,
        ansible_session=ansible_session,
        extra_vars={
            "client_disable_fast_startup": bool(disable_fast_startup),
            "client_monitor_timeout_ac_minutes": (
                -1 if monitor_timeout_ac is None else monitor_timeout_ac
            ),
            "client_monitor_timeout_dc_minutes": (
                -1 if monitor_timeout_dc is None else monitor_timeout_dc
            ),
        },
        marker_name="MAVI_CLIENT_OPTIMIZE_B64",
        timeout_seconds=180.0,
    )


def _format_client_timeout(seconds: Any) -> str:
    if seconds is None:
        return "unbekannt"
    try:
        total_seconds = int(seconds)
    except (TypeError, ValueError):
        return "unbekannt"
    if total_seconds == 0:
        return "Nie"
    if total_seconds % 60 == 0:
        minutes = total_seconds // 60
        return f"{minutes} Minute(n)"
    return f"{total_seconds} Sekunde(n)"


def _format_fast_startup_state(value: Any) -> str:
    if value is True:
        return "aktiviert"
    if value is False:
        return "deaktiviert"
    return "unbekannt"


def _print_client_optimization_state(result: dict[str, Any]) -> None:
    from .reports import redact_sensitive_text

    fast = result.get("FastStartup", {}) or {}
    power = result.get("Power", {}) or {}
    scheme = power.get("ActiveScheme", {}) or {}
    ac = power.get("Ac", {}) or {}
    dc = power.get("Dc", {}) or {}

    print()
    print("WINDOWS-CLIENT: AKTUELLER ZUSTAND")
    print("=================================")
    print(
        "  Schnellstart:       "
        + _format_fast_startup_state(fast.get("EnabledAfter"))
    )
    print(
        "  Bildschirm am Netz: "
        + _format_client_timeout(ac.get("AfterSeconds"))
    )
    print(
        "  Bildschirm am Akku: "
        + _format_client_timeout(dc.get("AfterSeconds"))
    )
    scheme_name = str(scheme.get("Name") or "").strip()
    scheme_guid = str(scheme.get("Guid") or "").strip()
    if scheme_name or scheme_guid:
        label = scheme_name or scheme_guid
        print(f"  Energieschema:       {label}")

    errors = result.get("Errors", []) or []
    for entry in errors:
        if not isinstance(entry, dict):
            continue
        area = str(entry.get("Area") or "Client")
        message = redact_sensitive_text(entry.get("Message") or "Unbekannter Fehler")
        print(f"  ! {area}: {message}")


def _prompt_monitor_timeout(
    label: str,
    current_seconds: Any,
) -> int | None:
    current = _format_client_timeout(current_seconds)
    while True:
        raw = input(
            f"{label} in Minuten (Enter = unverändert, 0 = Nie; aktuell {current}): "
        ).strip()
        if not raw:
            return None
        try:
            return _monitor_timeout_minutes(raw)
        except argparse.ArgumentTypeError as exc:
            print(f"Ungültige Eingabe: {exc}")


def _prompt_client_optimize_changes(
    current: dict[str, Any],
) -> tuple[bool, int | None, int | None] | None:
    power = current.get("Power", {}) or {}
    ac = power.get("Ac", {}) or {}
    dc = power.get("Dc", {}) or {}

    print()
    print("Was soll geändert werden?")
    print("  1) Schnellstart deaktivieren")
    print("  2) Bildschirmtimeout einstellen")
    print("  3) Beides")
    print("  0) Abbrechen")
    print()

    while True:
        choice = input("> ").strip()
        if choice == "0":
            return None
        if choice not in {"1", "2", "3"}:
            print("Ungültige Auswahl.")
            continue

        disable_fast = choice in {"1", "3"}
        timeout_ac: int | None = None
        timeout_dc: int | None = None
        if choice in {"2", "3"}:
            timeout_ac = _prompt_monitor_timeout(
                "Netzbetrieb",
                ac.get("AfterSeconds"),
            )
            timeout_dc = _prompt_monitor_timeout(
                "Akkubetrieb",
                dc.get("AfterSeconds"),
            )
            if timeout_ac is None and timeout_dc is None and not disable_fast:
                print("Keine Änderung gewählt.")
                return None
        return disable_fast, timeout_ac, timeout_dc


def _print_client_optimize_result(result: dict[str, Any]) -> None:
    _print_client_optimization_state(result)
    if bool(result.get("Success", False)):
        if bool(result.get("Changed", False)):
            print("\n✓ Client-Optimierung angewendet. Ein Neustart wurde nicht ausgelöst.")
        else:
            print("\n✓ Die gewählten Client-Einstellungen waren bereits so gesetzt.")
    else:
        print("\n! Mindestens eine Client-Einstellung konnte nicht angewendet werden.")


def cmd_client_optimize(args: argparse.Namespace) -> None:
    from .environment import (
        die,
        ensure_initialized,
    )
    from .remote import (
        _close_client_ansible_session,
        _host_inventory_entry,
        _open_client_ansible_session,
    )

    ensure_initialized(args.project, quiet=True)
    _host_inventory_entry(args.project, str(args.host))

    vault_password_file: Path | None = None
    ansible_session: dict[str, Any] | None = None
    try:
        vault_password_file = _create_prompted_client_vault_file()
        ansible_session = _open_client_ansible_session(
            project=args.project,
            host=args.host,
            vault_password_file=vault_password_file,
        )
        disable_fast = bool(getattr(args, "disable_fast_startup", False))
        timeout_ac = getattr(args, "monitor_timeout_ac", None)
        timeout_dc = getattr(args, "monitor_timeout_dc", None)

        if not disable_fast and timeout_ac is None and timeout_dc is None:
            current = _run_client_optimize(
                project=args.project,
                host=args.host,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
            )
            _print_client_optimization_state(current)
            changes = _prompt_client_optimize_changes(current)
            if changes is None:
                print("Keine Client-Einstellung geändert.")
                return
            disable_fast, timeout_ac, timeout_dc = changes

        result = _run_client_optimize(
            project=args.project,
            host=args.host,
            vault_password_file=vault_password_file,
            ansible_session=ansible_session,
            disable_fast_startup=disable_fast,
            monitor_timeout_ac=timeout_ac,
            monitor_timeout_dc=timeout_dc,
        )
        _print_client_optimize_result(result)
        if not bool(result.get("Success", False)):
            raise SystemExit(2)
    except RuntimeError as exc:
        die(str(exc), code=2)
    finally:
        _close_client_ansible_session(ansible_session)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)


def _query_client_classic_programs(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
) -> dict[str, Any]:
    from .environment import project_paths
    from .reports import redact_sensitive_text
    from .settings import DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES

    result = _run_client_playbook_result(
        project=project,
        host=host,
        playbook=project_paths(project)["client_uninstall_playbook"],
        vault_password_file=vault_password_file,
        ansible_session=ansible_session,
        extra_vars={
            "client_uninstall_action": "inventory",
            "client_uninstall_program_id": "",
            "client_uninstall_timeout_minutes": DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
        },
        marker_name="MAVI_CLIENT_UNINSTALL_B64",
        timeout_seconds=120.0,
    )

    if result.get("action") != "inventory" or not bool(result.get("success", False)):
        message = redact_sensitive_text(
            result.get("message") or "Programminventar konnte nicht gelesen werden."
        )
        raise RuntimeError(message)

    clean_programs: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw in result.get("programs", []) or []:
        if not isinstance(raw, dict):
            continue
        stable_id = str(raw.get("id") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", stable_id) or stable_id in seen_ids:
            continue
        seen_ids.add(stable_id)
        method = str(raw.get("silent_method") or "unsupported").lower()
        if method not in {"quiet", "msi", "office_c2r", "unsupported"}:
            method = "unsupported"
        scope = str(raw.get("scope") or "machine").lower()
        if scope not in {"machine", "user"}:
            scope = "machine"
        clean_programs.append({
            "id": stable_id,
            "display_name": str(raw.get("display_name") or "(ohne Namen)"),
            "display_version": str(raw.get("display_version") or ""),
            "publisher": str(raw.get("publisher") or ""),
            "scope": scope,
            "registry_hive": str(raw.get("registry_hive") or ""),
            "registry_view": str(raw.get("registry_view") or ""),
            "user_sid": str(raw.get("user_sid") or ""),
            "uninstall_key": str(raw.get("uninstall_key") or ""),
            "source": str(raw.get("source") or ""),
            "silent_method": method,
            "can_uninstall": bool(raw.get("can_uninstall", False)) and method != "unsupported",
            "is_m365": bool(raw.get("is_m365", False)),
        })

    clean_programs.sort(
        key=lambda row: (
            row["display_name"].casefold(),
            row["scope"],
            row["display_version"].casefold(),
            row["id"],
        )
    )
    result["programs"] = clean_programs
    return result


def _client_program_search_text(program: dict[str, Any]) -> str:
    return " ".join(
        str(program.get(key) or "")
        for key in (
            "display_name",
            "display_version",
            "publisher",
            "source",
        )
    ).casefold()


def choose_client_programs_interactive(
    programs: list[dict[str, Any]],
    *,
    preselect_m365: bool = False,
) -> list[dict[str, Any]]:
    from .catalogs import _parse_multi_program_selection

    selected: set[str] = set()
    if preselect_m365:
        selected.update(
            str(program["id"])
            for program in programs
            if bool(program.get("is_m365"))
        )

    search = ""
    while True:
        visible = [
            program
            for program in programs
            if not search or search in _client_program_search_text(program)
        ]

        print()
        print("INSTALLIERTE KLASSISCHE PROGRAMME")
        print("================================")
        if search:
            print(f"Filter: {search!r} | {len(visible)} Treffer")
        print(f"Markiert: {len(selected)} von {len(programs)}")
        print()

        if visible:
            for index, program in enumerate(visible, 1):
                mark = "X" if program["id"] in selected else " "
                scope = "PC" if program["scope"] == "machine" else "USER"
                method = {
                    "quiet": "Silent",
                    "msi": "MSI",
                    "office_c2r": "M365 C2R",
                    "unsupported": "KEIN SILENT",
                }.get(program["silent_method"], "KEIN SILENT")
                version = program["display_version"] or "–"
                publisher = program["publisher"] or "–"
                print(
                    f" {index:>3}) [{mark}] {program['display_name']}"
                    f" | {version} | {publisher} | {scope}/{program['registry_view']} | {method}"
                )
        else:
            print("  Keine Treffer für diesen Filter.")

        print()
        print("Nummern/Bereiche = umschalten, a = sichtbare markieren, c = leeren")
        print("m = nur Microsoft 365 markieren, f TEXT oder /TEXT = suchen, r = Filter löschen")
        print("Enter = Auswahl übernehmen, 0 = abbrechen")
        raw = input("> ").strip()
        lowered = raw.casefold()

        if raw == "":
            if not selected:
                print("Noch keine Programme markiert.")
                continue
            return [
                program
                for program in programs
                if program["id"] in selected
            ]
        if lowered == "0":
            return []
        if lowered in {"a", "alle", "all", "*"}:
            selected.update(str(program["id"]) for program in visible)
            continue
        if lowered in {"c", "clear", "leeren"}:
            selected.clear()
            continue
        if lowered == "m":
            m365_ids = {
                str(program["id"])
                for program in programs
                if bool(program.get("is_m365"))
            }
            selected.clear()
            selected.update(m365_ids)
            print(f"{len(m365_ids)} Microsoft-365-Eintrag/Einträge markiert.")
            continue
        if lowered == "r":
            search = ""
            continue
        if lowered.startswith("f "):
            search = raw[2:].strip().casefold()
            continue
        if raw.startswith("/"):
            search = raw[1:].strip().casefold()
            continue

        try:
            numbers = _parse_multi_program_selection(raw, len(visible))
        except ValueError as exc:
            print(str(exc))
            continue
        for number in numbers:
            stable_id = str(visible[number - 1]["id"])
            if stable_id in selected:
                selected.remove(stable_id)
            else:
                selected.add(stable_id)


def _prompt_client_uninstall_timeout(default_minutes: int) -> int:
    while True:
        raw = input(
            f"Zeitlimit pro Programm in Minuten [{default_minutes}]: "
        ).strip()
        if not raw:
            return default_minutes
        try:
            return _client_uninstall_timeout_minutes(raw)
        except argparse.ArgumentTypeError as exc:
            print(f"Ungültige Eingabe: {exc}")


def _print_client_uninstall_preview(
    programs: list[dict[str, Any]],
    timeout_minutes: int,
) -> None:
    print()
    print("MAVI DEINSTALLATIONSPLAN")
    print("=======================")
    print("Programme laufen strikt nacheinander; MAVI löst keinen Neustart aus.")
    print(f"Zeitlimit je Programm: {timeout_minutes} Minute(n)")
    print()
    for index, program in enumerate(programs, 1):
        scope = "PC/SYSTEM" if program["scope"] == "machine" else "aktueller Benutzer"
        method = program["silent_method"]
        note = ""
        if not program["can_uninstall"]:
            note = " | wird übersprungen: kein Silent-Uninstaller"
        elif program.get("is_m365"):
            note = " | Microsoft 365"
        print(
            f"  {index:>2}) {program['display_name']}"
            f" [{program['display_version'] or 'ohne Version'}; {scope}; {method}]{note}"
        )


def _uninstall_client_program_once(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    program: dict[str, Any],
    timeout_minutes: int,
) -> dict[str, Any]:
    from .environment import project_paths
    from .reports import redact_sensitive_text

    result = _run_client_playbook_result(
        project=project,
        host=host,
        playbook=project_paths(project)["client_uninstall_playbook"],
        vault_password_file=vault_password_file,
        ansible_session=ansible_session,
        extra_vars={
            "client_uninstall_action": "uninstall",
            "client_uninstall_program_id": program["id"],
            "client_uninstall_expected_display_name": program["display_name"],
            "client_uninstall_expected_scope": program["scope"],
            "client_uninstall_expected_user_sid": program["user_sid"],
            "client_uninstall_timeout_minutes": timeout_minutes,
        },
        marker_name="MAVI_CLIENT_UNINSTALL_B64",
        timeout_seconds=(timeout_minutes * 60.0) + 240.0,
    )
    if result.get("action") != "uninstall":
        raise RuntimeError("Der Windows-PC lieferte kein Deinstallationsergebnis.")

    allowed_statuses = {
        "ENTFERNT",
        "BEREITS ENTFERNT",
        "ÜBERSPRUNGEN",
        "FEHLER",
    }
    if result.get("status") not in allowed_statuses:
        result["status"] = "FEHLER"
        result["message"] = "Unbekannter Ergebnisstatus des Windows-PCs."

    result["id"] = program["id"]
    result["name"] = str(result.get("name") or program["display_name"])
    result["message"] = redact_sensitive_text(result.get("message") or "")
    return result


def _client_uninstall_base_result(
    program: dict[str, Any],
    *,
    status: str,
    message: str,
) -> dict[str, Any]:
    return {
        "id": program["id"],
        "name": program["display_name"],
        "status": status,
        "method": program["silent_method"],
        "scope": program["scope"],
        "execution_user": "",
        "exit_code": None,
        "reboot_required": False,
        "still_running": False,
        "stop_series": status == "NICHT GESTARTET",
        "message": message,
    }


def _run_client_uninstall_sequence(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    selected: list[dict[str, Any]],
    timeout_minutes: int,
) -> list[dict[str, Any]]:
    from .reports import redact_sensitive_text

    results: list[dict[str, Any]] = []

    for index, program in enumerate(selected):
        if index > 0 and not _wait_for_client_host_ready(
            project=project,
            host=host,
            vault_password_file=vault_password_file,
            ansible_session=ansible_session,
            max_wait_seconds=180.0,
        ):
            for remaining in selected[index:]:
                results.append(
                    _client_uninstall_base_result(
                        remaining,
                        status="NICHT GESTARTET",
                        message="Ziel-PC nicht erreichbar; Serie beendet.",
                    )
                )
            break

        print()
        print("=" * 72)
        print(
            f"MAVI DEINSTALLATION {index + 1}/{len(selected)}: "
            f"{program['display_name']}"
        )
        print("=" * 72)

        try:
            result = _uninstall_client_program_once(
                project=project,
                host=host,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
                program=program,
                timeout_minutes=timeout_minutes,
            )
        except RuntimeError as exc:
            result = _client_uninstall_base_result(
                program,
                status="FEHLER",
                message=redact_sensitive_text(str(exc)),
            )
            result["stop_series"] = True

        results.append(result)
        code = result.get("exit_code")
        code_text = "" if code is None else f" | Code {code}"
        print(
            f"{result['status']}: {result['name']}{code_text}"
            + (f" | {result['message']}" if result.get("message") else "")
        )
        if result.get("reboot_required"):
            print("  ! Windows meldet Neustartbedarf; MAVI startet nicht automatisch neu.")

        if bool(result.get("stop_series")):
            for remaining in selected[index + 1:]:
                results.append(
                    _client_uninstall_base_result(
                        remaining,
                        status="NICHT GESTARTET",
                        message="Serie nach Zeitlimit oder Verbindungsverlust beendet.",
                    )
                )
            break

    return results


def _print_client_uninstall_summary(results: list[dict[str, Any]]) -> None:
    print()
    print("MAVI DEINSTALLATIONS-ZUSAMMENFASSUNG")
    print("==================================")
    for result in results:
        code = result.get("exit_code")
        code_text = "" if code is None else f" | Code {code}"
        message = f" | {result['message']}" if result.get("message") else ""
        print(
            f"  {str(result.get('status') or 'FEHLER'):<20} "
            f"{result.get('name') or '(unbekannt)'}{code_text}{message}"
        )

    removed = sum(1 for row in results if row.get("status") == "ENTFERNT")
    already = sum(1 for row in results if row.get("status") == "BEREITS ENTFERNT")
    skipped = sum(1 for row in results if row.get("status") == "ÜBERSPRUNGEN")
    failed = sum(1 for row in results if row.get("status") in {"FEHLER", "NICHT GESTARTET"})
    print()
    print(
        f"Entfernt: {removed} | Bereits weg: {already} | "
        f"Übersprungen: {skipped} | Fehler/nicht gestartet: {failed}"
    )


def client_uninstall_interactive(
    project: Path,
    *,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    preselect_m365: bool = False,
    timeout_minutes: int = DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
    prompt_timeout: bool = False,
) -> bool:
    from .catalogs import yes_no

    print("\nInstallierte klassische Programme werden vom Windows-PC gelesen ...")
    inventory = _query_client_classic_programs(
        project=project,
        host=host,
        vault_password_file=vault_password_file,
        ansible_session=ansible_session,
    )
    programs = inventory.get("programs", []) or []
    if not programs:
        print("Keine klassischen Programme im Maschinen- oder aktuellen Benutzerkontext gefunden.")
        return True

    user = str(inventory.get("interactive_user") or "").strip()
    print(f"Gefunden: {len(programs)} Programme.")
    print(f"Aktuell angemeldeter Benutzer: {user or '(keiner)'}")

    selected = choose_client_programs_interactive(
        programs,
        preselect_m365=preselect_m365,
    )
    if not selected:
        print("Deinstallation abgebrochen. Keine Programme ausgewählt.")
        return True

    if prompt_timeout:
        timeout_minutes = _prompt_client_uninstall_timeout(timeout_minutes)
    _print_client_uninstall_preview(selected, timeout_minutes)
    if not yes_no(
        f"Diese {len(selected)} Auswahl(en) jetzt nacheinander verarbeiten?",
        default=False,
    ):
        print("Deinstallation abgebrochen.")
        return True

    results = _run_client_uninstall_sequence(
        project=project,
        host=host,
        vault_password_file=vault_password_file,
        ansible_session=ansible_session,
        selected=selected,
        timeout_minutes=timeout_minutes,
    )
    _print_client_uninstall_summary(results)
    return not any(
        row.get("status") in {"FEHLER", "NICHT GESTARTET"}
        for row in results
    )


def cmd_client_uninstall(args: argparse.Namespace) -> None:
    from .environment import (
        die,
        ensure_initialized,
    )
    from .remote import (
        _close_client_ansible_session,
        _host_inventory_entry,
        _open_client_ansible_session,
    )
    from .settings import DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES

    ensure_initialized(args.project, quiet=True)
    _host_inventory_entry(args.project, str(args.host))

    vault_password_file: Path | None = None
    ansible_session: dict[str, Any] | None = None
    try:
        vault_password_file = _create_prompted_client_vault_file()
        ansible_session = _open_client_ansible_session(
            project=args.project,
            host=args.host,
            vault_password_file=vault_password_file,
        )
        success = client_uninstall_interactive(
            args.project,
            host=args.host,
            vault_password_file=vault_password_file,
            ansible_session=ansible_session,
            preselect_m365=bool(getattr(args, "m365", False)),
            timeout_minutes=int(
                getattr(
                    args,
                    "timeout_minutes",
                    DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
                )
            ),
            prompt_timeout=False,
        )
        if not success:
            raise SystemExit(2)
    except RuntimeError as exc:
        die(str(exc), code=2)
    finally:
        _close_client_ansible_session(ansible_session)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)


def client_menu(project: Path) -> None:
    from .catalogs import (
        choose_host_interactive,
        yes_no,
    )
    from .environment import ensure_initialized
    from .remote import (
        _close_client_ansible_session,
        _host_inventory_entry,
        _open_client_ansible_session,
    )
    from .reports import redact_sensitive_text
    from .settings import DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES

    ensure_initialized(project, quiet=True)
    host = choose_host_interactive(project)
    _host_inventory_entry(project, host)

    vault_password_file: Path | None = None
    ansible_session: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    try:
        vault_password_file = _create_prompted_client_vault_file()
        ansible_session = _open_client_ansible_session(
            project=project,
            host=host,
            vault_password_file=vault_password_file,
        )
        try:
            current = _run_client_optimize(
                project=project,
                host=host,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
            )
        except RuntimeError as exc:
            print(f"! Energiezustand konnte nicht gelesen werden: {exc}")

        while True:
            print()
            print(f"WINDOWS-CLIENT OPTIMIEREN: {host}")
            print("============================================")
            if current is not None:
                fast = current.get("FastStartup", {}) or {}
                power = current.get("Power", {}) or {}
                ac = power.get("Ac", {}) or {}
                dc = power.get("Dc", {}) or {}
                print(
                    "  Schnellstart: "
                    + _format_fast_startup_state(fast.get("EnabledAfter"))
                )
                print(
                    "  Bildschirm:   Netz "
                    + _format_client_timeout(ac.get("AfterSeconds"))
                    + " | Akku "
                    + _format_client_timeout(dc.get("AfterSeconds"))
                )
                print()
            print("  1) Schnellstart deaktivieren")
            print("  2) Bildschirmtimeout einstellen")
            print("  3) Programme mehrfach auswählen und deinstallieren")
            print("  0) Zurück")
            print()
            choice = input("> ").strip()

            if choice == "0":
                return
            try:
                if choice == "1":
                    if not yes_no(
                        "Schnellstart deaktivieren? Der Ruhezustand bleibt erhalten.",
                        default=True,
                    ):
                        continue
                    current = _run_client_optimize(
                        project=project,
                        host=host,
                        vault_password_file=vault_password_file,
                        ansible_session=ansible_session,
                        disable_fast_startup=True,
                    )
                    _print_client_optimize_result(current)
                elif choice == "2":
                    if current is None:
                        current = _run_client_optimize(
                            project=project,
                            host=host,
                            vault_password_file=vault_password_file,
                            ansible_session=ansible_session,
                        )
                    power = current.get("Power", {}) or {}
                    ac = power.get("Ac", {}) or {}
                    dc = power.get("Dc", {}) or {}
                    timeout_ac = _prompt_monitor_timeout(
                        "Netzbetrieb",
                        ac.get("AfterSeconds"),
                    )
                    timeout_dc = _prompt_monitor_timeout(
                        "Akkubetrieb",
                        dc.get("AfterSeconds"),
                    )
                    if timeout_ac is None and timeout_dc is None:
                        print("Keine Timeout-Einstellung geändert.")
                        continue
                    current = _run_client_optimize(
                        project=project,
                        host=host,
                        vault_password_file=vault_password_file,
                        ansible_session=ansible_session,
                        monitor_timeout_ac=timeout_ac,
                        monitor_timeout_dc=timeout_dc,
                    )
                    _print_client_optimize_result(current)
                elif choice == "3":
                    client_uninstall_interactive(
                        project,
                        host=host,
                        vault_password_file=vault_password_file,
                        ansible_session=ansible_session,
                        preselect_m365=False,
                        timeout_minutes=DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
                        prompt_timeout=True,
                    )
                else:
                    print("Ungültige Auswahl.")
            except RuntimeError as exc:
                print(f"\nFEHLER: {redact_sensitive_text(exc)}")
            except SystemExit as exc:
                if exc.code not in (0, None):
                    print(f"\nClient-Aktion beendet mit Code {exc.code}.")
    except RuntimeError as exc:
        print(f"\nFEHLER: {redact_sensitive_text(exc)}")
    finally:
        _close_client_ansible_session(ansible_session)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)

__all__ = (
    "_monitor_timeout_minutes",
    "_client_uninstall_timeout_minutes",
    "_create_prompted_client_vault_file",
    "_wait_for_client_host_ready",
    "_client_playbook_failure_detail",
    "_run_client_playbook_result",
    "_run_client_optimize",
    "_format_client_timeout",
    "_format_fast_startup_state",
    "_print_client_optimization_state",
    "_prompt_monitor_timeout",
    "_prompt_client_optimize_changes",
    "_print_client_optimize_result",
    "cmd_client_optimize",
    "_query_client_classic_programs",
    "_client_program_search_text",
    "choose_client_programs_interactive",
    "_prompt_client_uninstall_timeout",
    "_print_client_uninstall_preview",
    "_uninstall_client_program_once",
    "_client_uninstall_base_result",
    "_run_client_uninstall_sequence",
    "_print_client_uninstall_summary",
    "client_uninstall_interactive",
    "cmd_client_uninstall",
    "client_menu",
)
