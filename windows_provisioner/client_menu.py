# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktives Clientmenü.

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



def client_menu(project: Path) -> None:
    from .clients import (
        _create_prompted_client_vault_file,
        _format_client_timeout,
        _format_fast_startup_state,
        _print_client_optimize_result,
        _prompt_monitor_timeout,
        _run_client_optimize,
        client_uninstall_interactive,
    )

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
