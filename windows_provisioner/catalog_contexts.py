# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Installationskontexte und Optionen.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    os,
    re,
    sys,
    yaml,
)






EDITABLE_CONTEXTS: list[tuple[str, str, str]] = [
    ("1", "machine", "Machine / normal administrativ"),
    ("2", "system", "SYSTEM / LocalSystem"),
    (
        "3",
        "user_interactive",
        "Angemeldeter Benutzer INTERAKTIV / GUI sichtbar / NICHT erhöht",
    ),
    (
        "4",
        "machine_detached",
        "SYSTEM DETACHED / LocalSystem / unbeaufsichtigt / keine sichtbare GUI",
    ),
    (
        "5",
        "machine_interactive",
        "Angemeldeter Benutzer INTERAKTIV + ELEVATED / GUI sichtbar / höchste verfügbare Rechte",
    ),
    (
        "6",
        "user_uac",
        "Angemeldeter Benutzer INTERAKTIV / zuerst USER, bei benötigten Adminrechten Fallback UAC",
    ),
]


def _context_label(context: str) -> str:
    from .catalogs import (
        EDITABLE_CONTEXTS,
    )

    normalized = str(context or "machine")

    if normalized == "user_non_elevated":
        normalized = "user_interactive"

    for _, value, label in EDITABLE_CONTEXTS:
        if value == normalized:
            return label

    return normalized


DEFAULT_VISIBLE_INSTALL_CONTEXTS = [value for _, value, _ in EDITABLE_CONTEXTS]


def _normalize_context_value(value: str) -> str:
    normalized = str(value or "machine").strip()
    if normalized == "user_non_elevated":
        normalized = "user_interactive"
    return normalized


def get_visible_install_contexts(project: Path) -> list[str]:
    from .catalogs import (
        DEFAULT_VISIBLE_INSTALL_CONTEXTS,
        _normalize_context_value,
    )

    from .environment import get_config

    config = get_config(project)
    raw = config.get("ui", {}).get(
        "visible_install_contexts",
        DEFAULT_VISIBLE_INSTALL_CONTEXTS,
    )
    if not isinstance(raw, list):
        raw = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)

    allowed = set(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
    selected: list[str] = []
    for item in raw:
        value = _normalize_context_value(str(item))
        if value in allowed and value not in selected:
            selected.append(value)

    if not selected:
        selected = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
    return selected


def _visible_context_choices(project: Path) -> list[tuple[str, str, str]]:
    from .catalogs import (
        EDITABLE_CONTEXTS,
        get_visible_install_contexts,
    )

    visible = set(get_visible_install_contexts(project))
    rows = [row for row in EDITABLE_CONTEXTS if row[1] in visible]
    return [
        (str(index), value, label)
        for index, (_, value, label) in enumerate(rows, start=1)
    ]


def prompt_install_context(project: Path, default_context: str = "machine") -> str:
    from .catalogs import (
        _context_label,
        _normalize_context_value,
        _visible_context_choices,
        prompt_choice,
    )

    choices = _visible_context_choices(project)
    if not choices:
        choices = [("1", "machine", _context_label("machine"))]

    normalized_default = _normalize_context_value(default_context)
    default_number = next(
        (number for number, value, _ in choices if value == normalized_default),
        choices[0][0],
    )

    if normalized_default not in {value for _, value, _ in choices}:
        print(
            f"! Vorgeschlagener/aktueller Kontext '{_context_label(normalized_default)}' "
            "ist in Optionen ausgeblendet."
        )

    selected = prompt_choice(
        "Installationskontext:",
        [(number, label) for number, _, label in choices],
        default_number,
    )
    return next(value for number, value, _ in choices if number == selected)


def install_context_options_menu(project: Path) -> None:
    from .catalogs import (
        DEFAULT_VISIBLE_INSTALL_CONTEXTS,
        EDITABLE_CONTEXTS,
        get_visible_install_contexts,
    )

    from .environment import (
        atomic_write_yaml,
        load_yaml,
        project_paths,
    )

    while True:
        visible_list = get_visible_install_contexts(project)
        visible = set(visible_list)

        print("\nINSTALLATIONSKONTEXTE ANZEIGEN / AUSBLENDEN")
        print("===========================================")
        print("Nur die Auswahl in der TUI wird vereinfacht.")
        print("Bestehende Katalogeinträge bleiben unverändert.\n")

        for number, value, label in EDITABLE_CONTEXTS:
            mark = "X" if value in visible else " "
            print(f"  {number}) [{mark}] {label}")

        print("  7) Alle anzeigen")
        print("  8) Kurzansicht: Machine / SYSTEM / Benutzer")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()
        values_by_number = {number: value for number, value, _ in EDITABLE_CONTEXTS}

        if choice == "0":
            return
        if choice == "7":
            new_visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
        elif choice == "8":
            new_visible = ["machine", "system", "user_interactive"]
        elif choice in values_by_number:
            value = values_by_number[choice]
            new_visible = list(visible_list)
            if value in new_visible:
                if len(new_visible) <= 1:
                    print("! Mindestens ein Installationskontext muss sichtbar bleiben.")
                    continue
                new_visible.remove(value)
            else:
                enabled = set(new_visible) | {value}
                new_visible = [
                    item for item in DEFAULT_VISIBLE_INSTALL_CONTEXTS if item in enabled
                ]
        else:
            print("Ungültige Auswahl.")
            continue

        config_path = project_paths(project)["config"]
        config = load_yaml(config_path, {}) or {}
        ui = dict(config.get("ui", {}) or {})
        ui["visible_install_contexts"] = new_visible
        config["ui"] = ui
        atomic_write_yaml(config_path, config)
        print("✓ Sichtbare Installationskontexte gespeichert.")


def options_menu(project: Path) -> None:
    from .catalogs import (
        install_context_options_menu,
    )

    while True:
        print("\nOPTIONEN")
        print("========")
        print("  1) Installationskontexte anzeigen / ausblenden")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()
        if choice == "1":
            install_context_options_menu(project)
        elif choice == "0":
            return
        else:
            print("Ungültige Auswahl.")
