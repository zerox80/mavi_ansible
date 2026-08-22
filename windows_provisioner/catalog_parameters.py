# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Parameterprofile und Sicherungen.

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




PARAMETER_PROFILE_FIELDS = (
    "arguments",
    "context",
    "creates_path",
    "installer_engine",
    "desktop_shortcut",
    "install_timeout_minutes",
)


def load_parameter_backups(project: Path) -> dict[str, Any]:
    from .environment import (
        ensure_initialized,
        load_yaml,
        project_paths,
    )
    from .settings import PARAMETER_BACKUP_TEMPLATE

    ensure_initialized(project, quiet=True)
    path = project_paths(project)["parameter_backups"]
    data = load_yaml(path, PARAMETER_BACKUP_TEMPLATE) or {}
    profiles = data.get("parameter_profiles")
    if not isinstance(profiles, dict):
        data["parameter_profiles"] = {}
    return _scrub_parameter_backup_secrets(data)


def save_parameter_backups(project: Path, data: dict[str, Any]) -> None:
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .software import sanitize_catalog_data

    atomic_write_yaml(
        project_paths(project)["parameter_backups"],
        sanitize_catalog_data(_scrub_parameter_backup_secrets(data)),
    )


def parameter_profile_from_app(
    key: str,
    app: dict[str, Any],
    catalog_name: str,
) -> dict[str, Any]:

    from .catalogs import (
        PARAMETER_PROFILE_FIELDS,
    )

    from .reports import _literal_secret_argument_names
    from .software import sanitize_catalog_data

    profile: dict[str, Any] = {
        "name": str(app.get("name", key)),
        "source_catalog": catalog_name,
        "type": str(app.get("type", "")),
    }

    for field in PARAMETER_PROFILE_FIELDS:
        if field == "arguments":
            arguments = str(app.get(field, ""))
            if _literal_secret_argument_names(arguments):
                profile["arguments_omitted"] = (
                    "Klartext-Geheimwert nicht gesichert; zuerst Vault-Referenz verwenden."
                )
            else:
                profile[field] = arguments
        elif field == "context":
            profile[field] = str(app.get(field, "machine"))
        elif field in app:
            profile[field] = app[field]

    return sanitize_catalog_data(profile)


def backup_parameter_profile(
    project: Path,
    catalog_name: str,
    key: str,
    app: dict[str, Any],
) -> None:
    from .catalogs import (
        load_parameter_backups,
        parameter_profile_from_app,
        save_parameter_backups,
    )

    data = load_parameter_backups(project)
    profiles = data.setdefault("parameter_profiles", {})
    profiles[key] = parameter_profile_from_app(
        key,
        app,
        catalog_name,
    )
    save_parameter_backups(project, data)


def cmd_params_backup(args: argparse.Namespace) -> None:
    from .catalogs import (
        get_catalog,
        load_parameter_backups,
        parameter_profile_from_app,
        resolve_catalog_name,
        save_parameter_backups,
    )

    from .environment import (
        die,
        ensure_initialized,
        project_paths,
    )

    ensure_initialized(args.project, quiet=True)
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(
        args.project,
        catalog_name,
    ).get("software_catalog", {})

    requested = list(getattr(args, "software", []) or [])
    backup_all = bool(getattr(args, "all", False)) or not requested

    if backup_all:
        keys = list(catalog.keys())
    else:
        keys = requested

    if not keys:
        die(f"Katalog '{catalog_name}' ist leer.")

    missing = [key for key in keys if key not in catalog]
    if missing:
        die(
            "Nicht im Katalog gefunden: "
            + ", ".join(missing)
        )

    data = load_parameter_backups(args.project)
    profiles = data.setdefault("parameter_profiles", {})

    for key in keys:
        profiles[key] = parameter_profile_from_app(
            key,
            catalog[key],
            catalog_name,
        )

    save_parameter_backups(args.project, data)

    print()
    print(
        f"✓ {len(keys)} Parameter-Profil(e) gesichert."
    )
    print(
        "  Datei: "
        + str(project_paths(args.project)["parameter_backups"])
    )


def cmd_params_list(args: argparse.Namespace) -> None:

    from .catalogs import (
        load_parameter_backups,
    )

    from .reports import redact_sensitive_text

    data = load_parameter_backups(args.project)
    profiles = data.get("parameter_profiles", {})

    print("PARAMETER-BACKUPS")
    print("=================")

    if not profiles:
        print("Noch keine Parameter-Backups vorhanden.")
        return

    print()
    print(
        f"{'KEY':<25} {'NAME':<32} {'TYP':<6} "
        f"{'KONTEXT':<20} ARGUMENTE"
    )
    print("-" * 120)

    for key, profile in profiles.items():
        print(
            f"{key[:24]:<25} "
            f"{str(profile.get('name', key))[:31]:<32} "
            f"{str(profile.get('type', ''))[:5]:<6} "
            f"{str(profile.get('context', ''))[:19]:<20} "
            f"{redact_sensitive_text(profile.get('arguments', ''))}"
        )


def _restore_parameter_profile(
    project: Path,
    catalog_name: str,
    profile_key: str,
    target_key: str,
    *,
    force: bool = False,
) -> bool:
    from .catalogs import (
        get_catalog,
        load_parameter_backups,
        save_catalog,
    )

    from .environment import die
    from .reports import validate_installer_arguments
    from .software import sanitize_catalog_data

    data = load_parameter_backups(project)
    profiles = data.get("parameter_profiles", {})
    profile = profiles.get(profile_key)

    if not isinstance(profile, dict):
        die(f"Parameter-Profil '{profile_key}' nicht gefunden.")

    catalog = get_catalog(project, catalog_name)
    sw = catalog.get("software_catalog", {})
    app = sw.get(target_key)

    if not isinstance(app, dict):
        die(
            f"'{target_key}' ist nicht im Katalog "
            f"'{catalog_name}'."
        )

    old_type = str(profile.get("type", "")).lower()
    new_type = str(app.get("type", "")).lower()

    if (
        old_type
        and new_type
        and old_type != new_type
        and not force
    ):
        die(
            f"Typ hat sich geändert: Backup={old_type}, "
            f"aktueller Installer={new_type}. "
            "Nicht blind wiederhergestellt. "
            "Mit --force erzwingen, falls wirklich gewollt."
        )

    # Installerpfad, SHA256 und aktuelle Analyse bleiben absichtlich erhalten.
    if "arguments" in profile:
        arguments = str(profile.get("arguments", ""))
        validate_installer_arguments(
            arguments,
            context=f"Parameter-Profil '{profile_key}'",
        )
        if arguments:
            app["arguments"] = arguments
        else:
            app.pop("arguments", None)

    if profile.get("context"):
        app["context"] = str(profile["context"])

    if profile.get("creates_path"):
        app["creates_path"] = profile["creates_path"]
    else:
        app.pop("creates_path", None)

    if profile.get("installer_engine"):
        app["installer_engine"] = profile["installer_engine"]

    if "desktop_shortcut" in profile:
        app["desktop_shortcut"] = profile["desktop_shortcut"]
    else:
        app.pop("desktop_shortcut", None)

    if "install_timeout_minutes" in profile:
        try:
            timeout_value = int(profile["install_timeout_minutes"])
        except (TypeError, ValueError):
            timeout_value = 30

        if timeout_value < 1:
            timeout_value = 30

        app["install_timeout_minutes"] = timeout_value
    else:
        app.pop("install_timeout_minutes", None)

    sw[target_key] = sanitize_catalog_data(app)
    save_catalog(project, catalog, catalog_name)
    return True


def cmd_params_restore(args: argparse.Namespace) -> None:
    from .catalogs import (
        _restore_parameter_profile,
        get_catalog,
        load_parameter_backups,
        resolve_catalog_name,
    )

    from .environment import (
        die,
        ensure_initialized,
    )

    ensure_initialized(args.project, quiet=True)
    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )

    if getattr(args, "all", False):
        profiles = load_parameter_backups(
            args.project
        ).get("parameter_profiles", {})
        catalog = get_catalog(
            args.project,
            catalog_name,
        ).get("software_catalog", {})

        restored = 0
        skipped = 0

        for profile_key in profiles:
            if profile_key not in catalog:
                skipped += 1
                continue

            _restore_parameter_profile(
                args.project,
                catalog_name,
                profile_key,
                profile_key,
                force=bool(getattr(args, "force", False)),
            )
            restored += 1

        print(
            f"✓ Wiederhergestellt: {restored}, "
            f"übersprungen: {skipped}"
        )
        return

    profile_key = getattr(args, "profile", None)
    if not profile_key:
        data = load_parameter_backups(args.project)
        profiles = data.get("parameter_profiles", {})
        if not profiles:
            die("Keine Parameter-Backups vorhanden.")

        keys = list(profiles.keys())
        print()
        print("Parameter-Profil auswählen:")
        for i, key in enumerate(keys, 1):
            profile = profiles[key]
            print(
                f"  {i}) {key} - "
                f"{profile.get('name', key)}"
            )

        while True:
            raw = input("> ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(keys):
                profile_key = keys[int(raw) - 1]
                break
            print("Ungültige Auswahl.")

    target_key = getattr(args, "target_key", None) or profile_key

    _restore_parameter_profile(
        args.project,
        catalog_name,
        profile_key,
        target_key,
        force=bool(getattr(args, "force", False)),
    )

    print(
        f"✓ Parameter '{profile_key}' auf "
        f"'{target_key}' in '{catalog_name}' wiederhergestellt."
    )


def parameter_backup_menu(project: Path) -> None:
    from .catalogs import (
        choose_catalog_by_number,
        choose_software_interactive,
        cmd_params_backup,
        cmd_params_list,
        cmd_params_restore,
        get_default_catalog_name,
    )

    while True:
        print()
        print("PARAMETER-BACKUPS")
        print("=================")
        print("  1) Backups anzeigen")
        print("  2) Parameter eines Programms sichern")
        print("  3) ALLE Parameter eines Katalogs sichern")
        print("  4) Parameter wiederherstellen")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()

        if choice == "1":
            cmd_params_list(
                argparse.Namespace(project=project)
            )

        elif choice in {"2", "3"}:
            catalog_name = choose_catalog_by_number(
                project,
                default_name=get_default_catalog_name(project),
                title="Katalog auswählen",
            )

            if choice == "2":
                key = choose_software_interactive(
                    project,
                    catalog_name,
                )
                software = [key]
                all_ = False
            else:
                software = []
                all_ = True

            cmd_params_backup(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    software=software,
                    all=all_,
                )
            )

        elif choice == "4":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=get_default_catalog_name(project),
                title="Zielkatalog auswählen",
            )
            cmd_params_restore(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    profile=None,
                    target_key=None,
                    all=False,
                    force=False,
                )
            )

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")


def _scrub_parameter_backup_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Never retain a legacy literal credential in the backup data model."""
    from .reports import _literal_secret_argument_names

    profiles = data.get("parameter_profiles", {})
    if not isinstance(profiles, dict):
        return {"parameter_profiles": {}}
    for raw_profile in profiles.values():
        if not isinstance(raw_profile, dict):
            continue
        arguments = str(raw_profile.get("arguments", "") or "")
        if _literal_secret_argument_names(arguments):
            raw_profile.pop("arguments", None)
            raw_profile["arguments_omitted"] = (
                "Legacy-Klartext-Geheimwert wurde nicht in das Parameter-Backup übernommen."
            )
    return data
