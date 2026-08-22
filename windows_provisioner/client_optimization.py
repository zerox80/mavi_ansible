# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Windows-Clientoptimierung.

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
    from .clients import (
        _run_client_playbook_result,
    )

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
    from .clients import (
        _format_client_timeout,
        _format_fast_startup_state,
    )

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
    from .clients import (
        _format_client_timeout,
        _monitor_timeout_minutes,
    )

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
    from .clients import (
        _prompt_monitor_timeout,
    )

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
    from .clients import (
        _print_client_optimization_state,
    )

    _print_client_optimization_state(result)
    if bool(result.get("Success", False)):
        if bool(result.get("Changed", False)):
            print("\n✓ Client-Optimierung angewendet. Ein Neustart wurde nicht ausgelöst.")
        else:
            print("\n✓ Die gewählten Client-Einstellungen waren bereits so gesetzt.")
    else:
        print("\n! Mindestens eine Client-Einstellung konnte nicht angewendet werden.")


def cmd_client_optimize(args: argparse.Namespace) -> None:
    from .clients import (
        _create_prompted_client_vault_file,
        _print_client_optimization_state,
        _print_client_optimize_result,
        _prompt_client_optimize_changes,
        _run_client_optimize,
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
