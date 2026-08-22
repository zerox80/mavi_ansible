# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Terminaldarstellung des Softwarekatalogs.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    html,
    ipaddress,
    os,
    re,
    shutil,
    socket,
    subprocess,
    sys,
    time,
    urllib,
    yaml,
)



def _clip_cell(value: Any, width: int) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ").strip()
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1].rstrip() + "…"


def _software_mode_meta(app: dict[str, Any]) -> dict[str, str]:
    from .catalogs import (
        _context_label,
        _normalize_context_value,
    )
    from .software import _is_msstore_app

    context = _normalize_context_value(str(app.get("context", "machine")))
    mapping = {
        "machine": ("Machine/Admin", "PC", "Direkt"),
        "system": ("SYSTEM", "SYSTEM", "Direkt"),
        "user_interactive": ("User interaktiv", "USER", "GUI"),
        "machine_detached": ("SYSTEM detached", "SYSTEM", "Task"),
        "machine_interactive": ("User + Highest", "USER", "GUI/Admin"),
        "user_uac": ("User → UAC Fallback", "USER", "GUI/User→UAC"),
    }
    mode, scope, execution = mapping.get(context, (context, "?", "?"))
    app_type = str(app.get("type", "")).lower()
    if app_type == "office_odt":
        # Der ODT-Pfad im Playbook läuft unabhängig vom historischen Kontextfeld
        # immer als SYSTEM über einen detached Scheduled Task.
        mode = "ODT SYSTEM detached"
        scope = "SYSTEM"
        execution = "Task/ODT"
    elif app_type == "winget":
        winget_scope = str(app.get("winget_scope", scope)).lower()
        scope = "USER" if winget_scope == "user" else "PC"
        if _is_msstore_app(app):
            mode = "Microsoft Store USER"
            scope = "USER"
            execution = "WinGet/msstore"
        else:
            mode = f"WinGet {scope}"
            execution = "WinGet"
    return {
        "context": context,
        "mode": mode,
        "scope": scope,
        "execution": execution,
        "long": _context_label(context),
    }


def _software_installer_display(app: dict[str, Any]) -> str:
    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        return str(app.get("winget_id") or app.get("installer") or "(WinGet-ID fehlt)")
    installer = str(app.get("installer", "") or "")
    if not installer:
        return "(kein Installer)"
    normalized = installer.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] or installer


def _software_parameters_display(app: dict[str, Any]) -> str:
    from .reports import (
        redact_sensitive_text,
    )

    from .software import _is_msstore_app

    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        if _is_msstore_app(app):
            return "source=msstore | scope=user"
        parts = [f"scope={app.get('winget_scope', 'machine')}"]
        if app.get("winget_version"):
            parts.append(f"v={app.get('winget_version')}")
        return " | ".join(parts)
    args = redact_sensitive_text(app.get("arguments", "")).strip()
    return args or "(keine)"


def _software_detection_display(app: dict[str, Any]) -> str:
    from .software import _is_msstore_app

    if str(app.get("type", "")).lower() == "winget":
        return "WinGet list · msstore" if _is_msstore_app(app) else "WinGet list"
    creates = str(app.get("creates_path", "") or "").strip()
    if creates:
        return creates
    return "Auto-Scan"


def _software_timeout_display(app: dict[str, Any]) -> str:
    from .catalogs import _normalize_context_value

    context = _normalize_context_value(str(app.get("context", "machine")))
    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
        "user_uac",
    } or (str(app.get("type", "")).lower() == "winget" and str(app.get("winget_scope", "machine")) == "user"):
        return f"{int(app.get('install_timeout_minutes', 30) or 30)}m"
    return "-"


def _render_catalog_terminal_table(catalog: dict[str, Any]) -> None:
    from .reports import (
        _clip_cell,
        _software_detection_display,
        _software_installer_display,
        _software_mode_meta,
        _software_parameters_display,
        _software_timeout_display,
    )

    from .software import _software_type_label

    terminal_width = shutil.get_terminal_size((160, 30)).columns
    terminal_width = max(78, min(terminal_width, 220))

    rows: list[dict[str, str]] = []
    for index, (key, raw_app) in enumerate(catalog.items(), start=1):
        app = raw_app if isinstance(raw_app, dict) else {}
        meta = _software_mode_meta(app)
        rows.append({
            "nr": str(index),
            "key": str(key),
            "name": str(app.get("name", key)),
            "type": _software_type_label(app),
            "mode": meta["mode"],
            "scope": meta["scope"],
            "installer": _software_installer_display(app),
            "params": _software_parameters_display(app),
            "detect": _software_detection_display(app),
            "timeout": _software_timeout_display(app),
        })

    if terminal_width < 105:
        for row in rows:
            print(f"[{row['nr']}] {row['name']}  ({row['type']})")
            print(f"    Schlüssel: {row['key']}")
            print(f"    Modus:     {row['mode']} | Ziel: {row['scope']} | Timeout: {row['timeout']}")
            print(f"    Installer: {row['installer']}")
            print(f"    Parameter: {row['params']}")
            print(f"    Erkennung: {row['detect']}")
            print()
        return

    columns: list[tuple[str, str, int]] = [
        ("nr", "#", 3),
        ("name", "NAME", 25),
        ("type", "TYP", 8),
        ("mode", "INSTALL-MODUS", 18),
        ("scope", "ZIEL", 7),
        ("installer", "INSTALLER / ID", 25),
    ]
    if terminal_width >= 125:
        columns.insert(1, ("key", "SCHLÜSSEL", 20))
    if terminal_width >= 165:
        columns.append(("params", "PARAMETER", 23))
    if terminal_width >= 195:
        columns.append(("detect", "ERKENNUNG", 20))
        columns.append(("timeout", "TIMEOUT", 7))

    def table_width(cols: list[tuple[str, str, int]]) -> int:
        return sum(width for _, _, width in cols) + (3 * (len(cols) - 1)) + 4

    while table_width(columns) > terminal_width and len(columns) > 5:
        removable = next(
            (i for i, col in reversed(list(enumerate(columns))) if col[0] in {"detect", "params", "timeout", "key"}),
            None,
        )
        if removable is None:
            break
        columns.pop(removable)

    top = "┌" + "┬".join("─" * (width + 2) for _, _, width in columns) + "┐"
    mid = "├" + "┼".join("─" * (width + 2) for _, _, width in columns) + "┤"
    bottom = "└" + "┴".join("─" * (width + 2) for _, _, width in columns) + "┘"

    print(top)
    print("│" + "│".join(f" {_clip_cell(header, width):<{width}} " for _, header, width in columns) + "│")
    print(mid)
    for row in rows:
        print("│" + "│".join(f" {_clip_cell(row.get(field, ''), width):<{width}} " for field, _, width in columns) + "│")
    print(bottom)
