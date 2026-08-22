# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Programmermittlung und Deinstallation.

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



def _query_client_classic_programs(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
) -> dict[str, Any]:
    from .clients import (
        _run_client_playbook_result,
    )

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
    from .clients import (
        _client_program_search_text,
    )

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
    from .clients import (
        _client_uninstall_timeout_minutes,
    )

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
    from .clients import (
        _run_client_playbook_result,
    )

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
    from .clients import (
        _client_uninstall_base_result,
        _uninstall_client_program_once,
        _wait_for_client_host_ready,
    )

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
    from .clients import (
        _print_client_uninstall_preview,
        _print_client_uninstall_summary,
        _prompt_client_uninstall_timeout,
        _query_client_classic_programs,
        _run_client_uninstall_sequence,
        choose_client_programs_interactive,
    )

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
    from .clients import (
        _create_prompted_client_vault_file,
        client_uninstall_interactive,
    )

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
