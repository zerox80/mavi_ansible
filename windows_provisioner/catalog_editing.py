# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Katalogbearbeitung und Mehrfachänderungen.

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



def _save_quick_edit(
    project: Path,
    catalog_name: str,
    catalog: dict[str, Any],
    key: str,
) -> None:
    from .catalogs import (
        backup_parameter_profile,
        save_catalog,
    )

    from .software import sanitize_catalog_data

    app = catalog["software_catalog"][key]
    catalog["software_catalog"][key] = sanitize_catalog_data(app)

    save_catalog(
        project,
        catalog,
        catalog_name,
    )

    backup_parameter_profile(
        project,
        catalog_name,
        key,
        catalog["software_catalog"][key],
    )

    print("✓ Änderung gespeichert.")


def cmd_software_edit(args: argparse.Namespace) -> None:
    """
    Bestehenden Katalogeintrag schnell ändern.
    Kein Löschen und Neuanlegen nötig.
    """

    from .catalogs import (
        validate_software_key,
    )
    from .catalogs import (
        CTRL2_SENTINEL,
        _context_label,
        _input_with_ctrl2,
        _save_quick_edit,
        bulk_install_context_menu,
        choose_software_interactive,
        get_catalog,
        prompt,
        prompt_choice,
        prompt_install_context,
        resolve_catalog_name,
    )

    from .environment import (
        die,
        get_config,
        normalize_path,
        resolve_installer_path,
        sha256_file,
    )
    from .reports import (
        redact_sensitive_text,
        validate_installer_arguments,
    )
    from .software import (
        _is_msstore_app,
        _software_type_label,
    )

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)
    software_catalog = catalog["software_catalog"]

    key = getattr(args, "key", None)
    if not key:
        key = choose_software_interactive(
            args.project,
            catalog_name,
        )
    key = validate_software_key(key)

    if key not in software_catalog:
        die(f"'{key}' ist nicht im Katalog '{catalog_name}'.")

    while True:
        app = software_catalog[key]
        app_type = str(app.get("type", "exe")).lower()

        context = str(app.get("context", "machine"))
        arguments = str(app.get("arguments", ""))
        creates_path = str(app.get("creates_path", ""))
        timeout_value = int(
            app.get("install_timeout_minutes", 30)
            or 30
        )

        desktop_shortcut = app.get("desktop_shortcut")
        shortcut_text = "(keine)"

        if (
            isinstance(desktop_shortcut, dict)
            and desktop_shortcut.get("enabled")
        ):
            shortcut_text = (
                f"{desktop_shortcut.get('name', app.get('name', key))} -> "
                f"{desktop_shortcut.get('target', '(kein Ziel)')}"
            )

        print()
        print("PROGRAMM SCHNELL BEARBEITEN")
        print("===========================")
        print(f"Katalog:     {catalog_name}")
        print(f"Schlüssel:   {key}")
        print(f"Name:        {app.get('name', key)}")
        print(f"Installer:   {app.get('installer', '')}")
        print(f"Typ:         {_software_type_label(app)}")
        if app_type == "winget":
            if _is_msstore_app(app):
                print(f"Store-ID:    {app.get('winget_id', '(fehlt)')}")
                print("Store:       Microsoft Store / WinGet msstore | Scope=USER")
            else:
                print(f"WinGet-ID:   {app.get('winget_id', '(fehlt)')}")
                print(f"WinGet:      Scope={app.get('winget_scope', '?')} | Quelle={app.get('winget_source', 'winget')} | Version={app.get('winget_version', 'aktuell')}")
        print(f"Kontext:     {_context_label(context)}")
        print(f"Parameter:   {redact_sensitive_text(arguments) or '(KEINE)'}")

        if context in {
            "machine_detached",
            "machine_interactive",
            "user_interactive",
            "user_non_elevated",
            "user_uac",
        }:
            print(f"Timeout:     {timeout_value} Min.")
        else:
            print("Timeout:     (für diesen Kontext nicht verwendet)")

        print(f"Erkennung:   {creates_path or '(KEINER)'}")
        print(f"Shortcut:    {shortcut_text}")
        print()
        print("  1) Installationskontext ändern")
        print("  2) Parameter / Flags ändern")
        print("  3) Timeout ändern")
        print("  4) Erkennungspfad ändern")
        print("  5) Anzeigename ändern")
        print("  6) Installer-Datei ändern")
        print("  7) Installer-Typ ändern")
        print("  8) Desktop-Verknüpfung ändern")
        print("  9) Kompletten YAML-Eintrag anzeigen")
        print("  0) Fertig / zurück")
        print()
        print("  Strg+2 / m) MEHRFACHAUSWAHL: mehrere Programme markieren + Installationsmodus ändern")
        print()

        choice = _input_with_ctrl2("> ").strip()

        if choice == CTRL2_SENTINEL or choice.lower() in {"m", "multi", "mehrfach"}:
            bulk_install_context_menu(args.project, catalog_name)
            # Bulk-Modus speichert den Katalog selbst. Danach frisch laden,
            # damit die Schnellbearbeitung sofort den neuen Modus zeigt.
            catalog = get_catalog(args.project, catalog_name)
            software_catalog = catalog["software_catalog"]
            if key not in software_catalog:
                print("! Der aktuell bearbeitete Eintrag ist nicht mehr vorhanden.")
                return
            continue

        if choice == "1":
            if app_type == "winget" and _is_msstore_app(app):
                print()
                print("Microsoft-Store-Apps bleiben in Mavi im USER-Kontext.")
                print("Für SYSTEM/MACHINE-AppX-Provisioning wäre ein anderer Bereitstellungsweg nötig.")
                continue
            if app_type == "winget":
                picked = prompt_choice(
                    "WinGet-Installationsbereich:",
                    [("1", "MACHINE / für den ganzen PC"), ("2", "USER / aktuell angemeldeter Benutzer")],
                    "2" if str(app.get("winget_scope", "machine")) == "user" else "1",
                )
                scope = "user" if picked == "2" else "machine"
                app["winget_scope"] = scope
                app["context"] = "user_interactive" if scope == "user" else "machine"
                if scope == "user":
                    app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
                else:
                    app.pop("install_timeout_minutes", None)
            else:
                new_context = prompt_install_context(
                    args.project,
                    context,
                )
                app["context"] = new_context

                if new_context in {
                    "machine_detached",
                    "machine_interactive",
                    "user_interactive",
                    "user_uac",
                }:
                    app["install_timeout_minutes"] = int(
                        app.get("install_timeout_minutes", 30)
                        or 30
                    )
                else:
                    app.pop("install_timeout_minutes", None)

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "2":
            if app_type == "winget":
                print("Microsoft-Store-/WinGet-Pakete verwenden keine normalen EXE/MSI-Flags in diesem Menü.")
                print("Version/Scope stehen direkt im WinGet-Katalogeintrag.")
                continue
            print()
            print(f"Aktuell: {redact_sensitive_text(arguments) or '(KEINE)'}")
            print("Enter = unverändert")
            print("-     = Parameter komplett entfernen")
            new_value = input("Neue Parameter: ").strip()

            if not new_value:
                print("Unverändert.")
                continue

            if new_value == "-":
                app.pop("arguments", None)
            else:
                app["arguments"] = validate_installer_arguments(
                    new_value,
                    context=f"Katalogeintrag '{key}'",
                )

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "3":
            if context not in {
                "machine_detached",
                "machine_interactive",
                "user_interactive",
                "user_non_elevated",
                "user_uac",
            }:
                print()
                print(
                    "Der aktuelle Kontext verwendet keinen eigenen "
                    "Mavi-Task-Timeout."
                )
                print(
                    "Timeout wird bei DETACHED und INTERAKTIVEN "
                    "Task-Scheduler-Modi verwendet."
                )
                continue

            while True:
                raw = prompt(
                    "Timeout in Minuten",
                    str(timeout_value),
                )

                try:
                    new_timeout = int(raw)
                except ValueError:
                    print("Bitte eine ganze Zahl eingeben.")
                    continue

                if new_timeout < 1:
                    print("Timeout muss mindestens 1 Minute sein.")
                    continue

                app["install_timeout_minutes"] = new_timeout
                break

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "4":
            print()
            print(f"Aktuell: {creates_path or '(KEINER)'}")
            print("Enter = unverändert")
            print("-     = Erkennungspfad entfernen")
            new_value = input("Neuer Erkennungspfad: ").strip()

            if not new_value:
                print("Unverändert.")
                continue

            if new_value == "-":
                app.pop("creates_path", None)
            else:
                app["creates_path"] = new_value

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "5":
            current_name = str(app.get("name", key))
            new_name = prompt(
                "Anzeigename",
                current_name,
            ).strip()

            if not new_name or new_name == current_name:
                print("Unverändert.")
                continue

            app["name"] = new_name

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "6":
            if app_type == "winget":
                print("Store-/WinGet-Eintrag hat keine lokale Installer-Datei. Für eine andere Paket-ID den Eintrag neu anlegen.")
                continue
            config = get_config(args.project)
            current_installer = str(app.get("installer", ""))

            print()
            print(f"Aktuell: {current_installer}")
            print("Enter = unverändert")
            raw_path = input("Neue Installer-Datei: ").strip()

            if not raw_path:
                print("Unverändert.")
                continue

            new_path = resolve_installer_path(
                normalize_path(raw_path, config),
                config,
            )

            if not new_path.exists():
                print(f"Installer nicht gefunden: {new_path}")
                continue

            if not new_path.is_file():
                print(f"Pfad ist keine Datei: {new_path}")
                continue

            app["installer"] = str(new_path)

            suffix = new_path.suffix.lower()
            if suffix == ".msi":
                app["type"] = "msi"
            elif suffix == ".exe":
                app["type"] = "exe"

            print("Berechne verpflichtenden SHA-256 ...")
            app["sha256"] = sha256_file(new_path)
            app.pop("allow_unsafe_missing_sha256", None)

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "7":
            if app_type == "winget":
                print("Store/WinGet wird absichtlich nicht blind in EXE/MSI umgewandelt. Bitte neuen Eintrag anlegen.")
                continue
            current_type = str(
                app.get("type", "exe")
            ).lower()

            new_type = prompt_choice(
                "Installer-Typ:",
                [
                    ("1", "EXE"),
                    ("2", "MSI"),
                ],
                "2" if current_type == "msi" else "1",
            )

            app["type"] = (
                "msi"
                if new_type == "2"
                else "exe"
            )

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "8":
            enabled = (
                isinstance(desktop_shortcut, dict)
                and bool(desktop_shortcut.get("enabled"))
            )

            if enabled:
                print()
                print(f"Aktuell: {shortcut_text}")
                print("  1) Verknüpfung ändern")
                print("  2) Verknüpfung entfernen")
                print("  0) Abbrechen")

                sub_choice = input("> ").strip()

                if sub_choice == "0":
                    continue

                if sub_choice == "2":
                    app.pop("desktop_shortcut", None)

                    _save_quick_edit(
                        args.project,
                        catalog_name,
                        catalog,
                        key,
                    )
                    continue

                if sub_choice != "1":
                    print("Ungültige Auswahl.")
                    continue

            current_shortcut = (
                desktop_shortcut
                if isinstance(desktop_shortcut, dict)
                else {}
            )

            shortcut_name = prompt(
                "Name der Desktop-Verknüpfung",
                str(
                    current_shortcut.get(
                        "name",
                        app.get("name", key),
                    )
                ),
            )

            shortcut_target = prompt(
                "Ziel-EXE der Desktop-Verknüpfung",
                str(
                    current_shortcut.get(
                        "target",
                        "",
                    )
                ),
            )

            if not shortcut_target:
                print("Kein Ziel angegeben. Unverändert.")
                continue

            app["desktop_shortcut"] = {
                "enabled": True,
                "name": shortcut_name,
                "target": shortcut_target,
            }

            _save_quick_edit(
                args.project,
                catalog_name,
                catalog,
                key,
            )

        elif choice == "9":
            print()
            print(
                redact_sensitive_text(
                    yaml.safe_dump(
                        {key: app},
                        allow_unicode=True,
                        sort_keys=False,
                    ).rstrip()
                )
            )

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")



def _parse_multi_program_selection(raw: str, item_count: int) -> list[int]:
    """Mehrfachauswahl wie 1,3,5-8 / 1 3 5-8 / alle parsen."""
    value = str(raw or "").strip().lower()
    if not value:
        return []
    if value in {"alle", "all", "*", "a"}:
        return list(range(1, item_count + 1))

    normalized = value.replace(";", ",").replace(" ", ",")
    tokens = [part.strip() for part in normalized.split(",") if part.strip()]
    selected: set[int] = set()

    for token in tokens:
        if "-" in token:
            if token.count("-") != 1:
                raise ValueError(f"Ungültiger Bereich: {token}")
            start_raw, end_raw = token.split("-", 1)
            if not start_raw.isdigit() or not end_raw.isdigit():
                raise ValueError(f"Ungültiger Bereich: {token}")
            start = int(start_raw)
            end = int(end_raw)
            if start > end:
                start, end = end, start
            if start < 1 or end > item_count:
                raise ValueError(f"Auswahl außerhalb 1-{item_count}: {token}")
            selected.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Ungültige Auswahl: {token}")
            number = int(token)
            if number < 1 or number > item_count:
                raise ValueError(f"Auswahl außerhalb 1-{item_count}: {token}")
            selected.add(number)

    return sorted(selected)


def _bulk_context_compatibility(app: dict[str, Any], target_context: str) -> tuple[bool, str]:
    from .catalogs import (
        _normalize_context_value,
    )

    from .software import _is_msstore_app

    app_type = str(app.get("type", "exe") or "exe").lower()
    target_context = _normalize_context_value(target_context)

    if app_type == "office_odt":
        return (
            False,
            "Office ODT läuft in Mavi fest als SYSTEM DETACHED; Kontextfeld wird nicht umgestellt.",
        )

    if app_type == "winget":
        if _is_msstore_app(app):
            if target_context == "user_interactive":
                return True, "Microsoft Store bleibt im USER-Kontext (msstore)."
            return (
                False,
                "Microsoft-Store-Apps bleiben in Mavi im USER-Kontext; Machine/SYSTEM wird nicht erzwungen.",
            )
        if target_context == "machine":
            return True, "WinGet wird auf Scope=MACHINE umgestellt."
        if target_context == "user_interactive":
            return True, "WinGet wird auf Scope=USER umgestellt."
        return (
            False,
            "WinGet unterstützt hier nur Machine oder Benutzer INTERAKTIV (Scope user).",
        )

    return True, ""


def _apply_bulk_install_context(app: dict[str, Any], target_context: str) -> None:
    """Installationskontext konsistent auf einen Katalogeintrag anwenden."""
    from .catalogs import (
        _normalize_context_value,
    )

    from .software import _is_msstore_app

    target_context = _normalize_context_value(target_context)
    app_type = str(app.get("type", "exe") or "exe").lower()

    if app_type == "winget":
        if _is_msstore_app(app):
            if target_context != "user_interactive":
                raise ValueError("Microsoft-Store-App darf nur USER-Kontext verwenden")
            app["context"] = "user_interactive"
            app["winget_scope"] = "user"
            app["winget_source"] = "msstore"
            app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
            return
        if target_context == "machine":
            app["context"] = "machine"
            app["winget_scope"] = "machine"
            app.pop("install_timeout_minutes", None)
            return
        if target_context == "user_interactive":
            app["context"] = "user_interactive"
            app["winget_scope"] = "user"
            app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
            return
        raise ValueError("Unzulässiger WinGet-Kontext")

    app["context"] = target_context
    if target_context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
        "user_uac",
    }:
        app["install_timeout_minutes"] = int(app.get("install_timeout_minutes", 30) or 30)
    else:
        app.pop("install_timeout_minutes", None)


def bulk_install_context_menu(project: Path, catalog_name: str | None = None) -> None:
    """Mehrere Katalogprogramme markieren und deren Installationsmodus gemeinsam ändern."""
    from .catalogs import (
        _apply_bulk_install_context,
        _bulk_context_compatibility,
        _context_label,
        backup_parameter_profile,
        choose_catalog_by_number,
        choose_software_multi_interactive,
        get_catalog,
        get_default_catalog_name,
        prompt_install_context,
        resolve_catalog_name,
        save_catalog,
        yes_no,
    )

    from .reports import _software_mode_meta
    from .software import sanitize_catalog_data

    if catalog_name is None:
        default_name = get_default_catalog_name(project)
        catalog_name = choose_catalog_by_number(
            project,
            default_name=default_name,
            title="Katalog für Mehrfachänderung auswählen",
        )
    else:
        catalog_name = resolve_catalog_name(project, catalog_name)
    catalog = get_catalog(project, catalog_name)
    software_catalog = catalog.get("software_catalog", {}) or {}

    if not software_catalog:
        print(f"Katalog '{catalog_name}' ist leer.")
        return

    items = list(software_catalog.items())

    while True:
        selected_keys = choose_software_multi_interactive(
            project,
            catalog_name,
            title="MEHRERE PROGRAMME · INSTALLATIONSMODUS ÄNDERN",
        )
        if not selected_keys:
            return

        by_key = {key: (idx, app) for idx, (key, app) in enumerate(items, start=1)}
        selected = [
            (by_key[key][0], key, by_key[key][1])
            for key in selected_keys
            if key in by_key
        ]
        print()
        print(f"Markiert: {len(selected)} Programm(e)")
        for number, key, app in selected:
            meta = _software_mode_meta(app if isinstance(app, dict) else {})
            print(f"  [{number:>2}] {app.get('name', key)}  |  {meta['mode']}")

        print()
        target_context = prompt_install_context(project, "machine")
        target_label = _context_label(target_context)

        applicable: list[tuple[int, str, dict[str, Any], str]] = []
        skipped: list[tuple[int, str, dict[str, Any], str]] = []

        for number, key, raw_app in selected:
            app = raw_app if isinstance(raw_app, dict) else {}
            ok, note = _bulk_context_compatibility(app, target_context)
            if ok:
                applicable.append((number, key, app, note))
            else:
                skipped.append((number, key, app, note))

        print()
        print("ÄNDERUNGSVORSCHAU")
        print("=================")
        print(f"Neuer Modus: {target_label}")
        print()
        for number, key, app, note in applicable:
            current = _software_mode_meta(app)["mode"]
            suffix = f"  ({note})" if note else ""
            print(f"  ✓ [{number:>2}] {app.get('name', key)}: {current} -> {target_label}{suffix}")
        for number, key, app, note in skipped:
            print(f"  ! [{number:>2}] {app.get('name', key)}: ÜBERSPRUNGEN | {note}")

        if not applicable:
            print()
            print("! Für den gewählten Modus ist keines der markierten Programme kompatibel.")
            return

        print()
        if skipped:
            print(f"Hinweis: {len(skipped)} inkompatible Einträge werden nicht verändert.")
        if not yes_no(f"Installationsmodus bei {len(applicable)} Programm(en) jetzt ändern?", False):
            print("Abgebrochen. Keine Änderung gespeichert.")
            return

        changed_keys: list[str] = []
        for _, key, app, _ in applicable:
            before = sanitize_catalog_data(dict(app))
            _apply_bulk_install_context(app, target_context)
            software_catalog[key] = sanitize_catalog_data(app)
            if software_catalog[key] != before:
                changed_keys.append(key)

        if not changed_keys:
            print("✓ Alle markierten Programme hatten diesen Modus bereits. Nichts zu speichern.")
            return

        save_catalog(project, catalog, catalog_name)
        for key in changed_keys:
            backup_parameter_profile(
                project,
                catalog_name,
                key,
                software_catalog[key],
            )

        print()
        print(f"✓ Installationsmodus für {len(changed_keys)} Programm(e) geändert.")
        if skipped:
            print(f"! {len(skipped)} inkompatible Einträge wurden sicher übersprungen.")
        print("✓ Parameter-Profile der geänderten Programme wurden aktualisiert.")
        return
