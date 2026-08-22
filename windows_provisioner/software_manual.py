# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Manuelle Softwareaufnahme.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    ET,
    Path,
    argparse,
    base64,
    getpass,
    json,
    os,
    re,
    subprocess,
    sys,
    tempfile,
    yaml,
)



def cmd_software_add(args: argparse.Namespace) -> None:
    from .software import (
        cmd_add_office_odt,
        looks_like_office_candidate,
        sanitize_catalog_data,
    )

    from .catalogs import (
        backup_parameter_profile,
        choose_catalog_interactive,
        get_catalog,
        prompt,
        prompt_choice,
        prompt_install_context,
        save_catalog,
        slugify,
        validate_software_key,
        yes_no,
    )
    from .environment import (
        _mavi_drive_label,
        _mavi_source_root,
        browse_installer,
        choose_installer_path,
        die,
        ensure_initialized,
        get_config,
        normalize_path,
        resolve_installer_path,
        sha256_file,
    )
    from .installer_analysis import analyze_installer
    from .reports import (
        redact_sensitive_text,
        validate_installer_arguments,
    )
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    if args.path:
        path = normalize_path(args.path, config)
        if path.exists() and path.is_dir() and sys.stdin.isatty():
            path = browse_installer(
                path,
                _mavi_drive_label(
                    (config.get("software_source", {}) or {}).get("drive")
                ),
            )
    else:
        path = choose_installer_path(config)

    path = resolve_installer_path(path, config)

    if not path.exists():
        local_root = _mavi_source_root(config)
        die(
            f"Installer nicht gefunden: {path}\n"
            f"Bekannte Softwarequelle: {local_root or '(nicht eingerichtet)'}"
        )

    if not path.is_file():
        die(f"Pfad ist keine Datei: {path}")

    catalog_name = choose_catalog_interactive(
        args.project,
        getattr(args, "catalog", None),
        purpose="verwenden",
        ask_other=True,
    )
    print(f"Zielkatalog: {catalog_name}")

    if looks_like_office_candidate(path):
        print()
        print(
            "! Microsoft Office / Project / Visio erkannt."
        )
        if yes_no(
            "Zum Microsoft-Assistenten wechseln?",
            True,
        ):
            cmd_add_office_odt(
                args,
                path,
                catalog_name,
                config,
            )
            return

    analysis = analyze_installer(
        path,
        args.project,
        use_known_rules=True,
        use_learned_rules=False,
    )

    # Microsoft TeamsBootstrapper ist absichtlich eine headless CLI.
    # Für die Bereitstellung ist -p der normale Provisioning-Schalter.
    if path.name.lower() == "teamsbootstrapper.exe":
        analysis["arguments"] = analysis.get("arguments") or "-p"
        analysis["context"] = "machine"
        reasons = list(analysis.get("reasons", []) or [])
        reasons.append("Microsoft TeamsBootstrapper erkannt: Provisioning mit -p vorgeschlagen.")
        analysis["reasons"] = reasons
        print()
        print("✓ Microsoft TeamsBootstrapper erkannt.")
        print("  Empfehlung: Machine + Parameter -p (headless Provisioning).")
        print("  Falls der Aufruf im Benutzerkontext erhöhte Rechte verlangt,")
        print("  kann der Kontext 'USER → UAC FALLBACK' automatisch sichtbar nach UAC wechseln.")

    print()
    print("Installer-Grunddaten")
    print("====================")
    print(f"Pfad:    {path}")
    print(f"Typ:     {analysis['type']}")
    print(f"Regel:   {analysis['engine']}")
    print(
        "Flags:   "
        + (
            redact_sensitive_text(analysis["arguments"])
            or "(manuell / keine)"
        )
    )
    print()
    print(
        "Deep-Scan: AUS. Es werden keine Silent-Flags "
        "aus Binärdaten geraten."
    )

    name = args.name or prompt(
        "Anzeigename",
        analysis["name_guess"],
    )
    key = validate_software_key(
        args.key or prompt(
            "Katalog-Schlüssel",
            slugify(name),
        )
    )

    typ = analysis["type"]
    if typ not in {"msi", "exe"}:
        typ = prompt_choice(
            "Installer-Typ:",
            [("msi", "MSI"), ("exe", "EXE")],
            "exe",
        )

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]
    existing = sw.get(key)
    preserve_existing = False

    if isinstance(existing, dict):
        print()
        print(f"! '{key}' existiert bereits.")
        print(
            f"  Aktueller Installer: "
            f"{existing.get('installer', '')}"
        )
        print(
            f"  Gespeicherte Flags:  "
            f"{redact_sensitive_text(existing.get('arguments')) or '(keine)'}"
        )
        print(
            f"  Kontext:             "
            f"{existing.get('context', 'machine')}"
        )

        if not yes_no(
            "Mit neuer Installer-Datei überschreiben?",
            False,
        ):
            print("Abgebrochen.")
            return

        # Vor JEDEM Versionswechsel automatisch sichern.
        backup_parameter_profile(
            args.project,
            catalog_name,
            key,
            existing,
        )
        print(
            "✓ Vorhandene Parameter automatisch gesichert."
        )

        same_type = (
            str(existing.get("type", "")).lower()
            == typ.lower()
        )

        if not same_type:
            print(
                "! Installer-Typ hat sich geändert. Alte Flags "
                "werden nicht blind übernommen."
            )
        else:
            preserve_existing = yes_no(
                "Vorhandene Parameter/Flags für die neue "
                "Version übernehmen?",
                True,
            )

    known_arguments = str(
        analysis.get("arguments", "")
    )

    if preserve_existing:
        arguments = str(
            existing.get("arguments", "")
        )
        context = str(
            existing.get("context", "machine")
        )
        creates_path = str(
            existing.get("creates_path", "")
        )
        desktop_shortcut = existing.get(
            "desktop_shortcut"
        )
        install_timeout_minutes = int(
            existing.get("install_timeout_minutes", 30)
            or 30
        )
        print()
        print("Übernommen:")
        print(
            f"  Flags:   {redact_sensitive_text(arguments) or '(keine)'}"
        )
        print(f"  Kontext: {context}")
        print(
            f"  Detect:  "
            f"{creates_path or '(keiner)'}"
        )
    else:
        if typ == "exe":
            if known_arguments:
                print()
                print(
                    "Feste Produktregel im Skript:"
                )
                print(f"  {redact_sensitive_text(known_arguments)}")
                if yes_no(
                    "Diese Parameter übernehmen?",
                    True,
                ):
                    arguments = known_arguments
                else:
                    arguments = prompt(
                        "Silent-Parameter "
                        "(Enter = keine)",
                        "",
                    )
            else:
                print()
                print(
                    "Keine feste Produktregel vorhanden."
                )
                arguments = prompt(
                    "Silent-Parameter "
                    "(Enter = keine)",
                    "",
                )
        else:
            arguments = ""

        recommended = str(
            analysis.get("context", "machine")
        )

        context = prompt_install_context(
            args.project,
            recommended,
        )

        install_timeout_minutes = 30
        if context in {
            "machine_detached",
            "machine_interactive",
            "user_interactive",
            "user_uac",
        }:
            timeout_label = (
                "DETACHED"
                if context == "machine_detached"
                else "INTERAKTIV"
            )
            while True:
                timeout_raw = prompt(
                    f"Timeout für {timeout_label}-Installation in Minuten",
                    "30",
                )

                try:
                    install_timeout_minutes = int(timeout_raw)
                except ValueError:
                    print("Bitte eine ganze Zahl in Minuten eingeben.")
                    continue

                if install_timeout_minutes < 1:
                    print("Timeout muss mindestens 1 Minute sein.")
                    continue

                break

        creates_path = prompt(
            "Optionaler Erkennungspfad nach Installation "
            "(Enter = keiner)",
            str(analysis.get("creates_path", "")),
        )

        is_forticlient = (
            analysis["engine"] == "FortiClient VPN"
        )
        shortcut_default_target = (
            r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
            if is_forticlient
            else ""
        )

        create_shortcut = yes_no(
            "Desktop-Verknüpfung für ALLE Benutzer "
            "sicherstellen?",
            is_forticlient,
        )

        desktop_shortcut = None
        if create_shortcut:
            shortcut_name = prompt(
                "Name der Desktop-Verknüpfung",
                name,
            )
            shortcut_target = prompt(
                "Ziel-EXE der Desktop-Verknüpfung",
                shortcut_default_target,
            )
            if shortcut_target:
                desktop_shortcut = {
                    "enabled": True,
                    "name": shortcut_name,
                    "target": shortcut_target,
                }

    app = {
        "name": name,
        "installer": str(path),
        "type": typ,
        "context": context,
        "installer_engine": analysis["engine"],
        "analysis": {
            "mode": "manual_parameters",
            "scanner_version": VERSION,
            "reasons": analysis.get("reasons", []),
        },
    }

    if arguments:
        app["arguments"] = validate_installer_arguments(
            arguments,
            context=f"Katalogeintrag '{key}'",
        )

    if creates_path:
        app["creates_path"] = creates_path

    if desktop_shortcut:
        app["desktop_shortcut"] = desktop_shortcut

    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
    }:
        app["install_timeout_minutes"] = int(
            install_timeout_minutes
        )

    if bool(getattr(args, "allow_unsafe_missing_sha256", False)):
        print(
            "! UNSICHERE AUSNAHME: Dieser Eintrag wird ausdrücklich ohne "
            "gebundenen Installer-Hash gespeichert."
        )
        app["allow_unsafe_missing_sha256"] = True
    else:
        print("Berechne verpflichtenden SHA-256 ...")
        app["sha256"] = sha256_file(path)

    app = sanitize_catalog_data(app)

    print()
    print("Wird gespeichert:")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {key: app},
                allow_unicode=True,
                sort_keys=False,
            ).rstrip()
        )
    )

    if not yes_no(
        "Zum Katalog hinzufügen?",
        True,
    ):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(
        args.project,
        catalog,
        catalog_name,
    )

    # Nach erfolgreichem Speichern direkt aktuellen Stand sichern.
    backup_parameter_profile(
        args.project,
        catalog_name,
        key,
        app,
    )

    print(
        f"\n✓ '{key}' wurde zum Katalog "
        f"'{catalog_name}' hinzugefügt."
    )
    print(
        "✓ Parameter-Profil wurde ebenfalls aktualisiert."
    )
