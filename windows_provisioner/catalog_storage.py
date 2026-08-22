# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Katalogspeicherung und Katalogbefehle.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations


from ._dependencies import (
    ipaddress,
)
from ._dependencies import (
    Any,
    Path,
    argparse,
    os,
    re,
    sys,
    yaml,
)



CATALOG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def validate_catalog_name(name: str) -> str:
    from .catalogs import (
        CATALOG_NAME_RE,
    )

    from .environment import die

    name = str(name).strip()
    if not name:
        die("Katalogname darf nicht leer sein.")
    if not CATALOG_NAME_RE.fullmatch(name):
        die(
            "Ungültiger Katalogname. Erlaubt sind Buchstaben, Zahlen, "
            "Punkt, Bindestrich und Unterstrich."
        )
    return name


def catalog_path(project: Path, catalog_name: str) -> Path:
    from .catalogs import (
        validate_catalog_name,
    )

    from .environment import project_paths

    name = validate_catalog_name(catalog_name)
    return project_paths(project)["catalogs_dir"] / f"{name}.yml"


def list_catalog_names(project: Path) -> list[str]:
    from .environment import (
        ensure_initialized,
        project_paths,
    )

    ensure_initialized(project, quiet=True)
    directory = project_paths(project)["catalogs_dir"]
    return sorted(
        [p.stem for p in directory.glob("*.yml") if p.is_file()],
        key=str.lower,
    )


def get_default_catalog_name(project: Path) -> str:
    from .catalogs import (
        catalog_path,
        validate_catalog_name,
    )

    from .environment import (
        atomic_write_yaml,
        ensure_initialized,
        get_config,
    )
    from .settings import CATALOG_TEMPLATE

    ensure_initialized(project, quiet=True)
    config = get_config(project)
    name = validate_catalog_name(str(config.get("default_catalog", "default")))
    path = catalog_path(project, name)

    # Sollte normalerweise bereits durch init existieren.
    if not path.exists():
        atomic_write_yaml(path, CATALOG_TEMPLATE)

    return name


def resolve_catalog_name(
    project: Path,
    requested: str | None = None,
    *,
    must_exist: bool = True,
) -> str:
    from .catalogs import (
        catalog_path,
        get_default_catalog_name,
        list_catalog_names,
        validate_catalog_name,
    )

    from .environment import die

    name = validate_catalog_name(requested) if requested else get_default_catalog_name(project)
    path = catalog_path(project, name)

    if must_exist and not path.exists():
        available = ", ".join(list_catalog_names(project)) or "(keine)"
        die(f"Katalog '{name}' existiert nicht. Vorhanden: {available}")

    return name


def choose_catalog_interactive(
    project: Path,
    requested: str | None = None,
    *,
    purpose: str = "verwenden",
    ask_other: bool = True,
) -> str:
    from .catalogs import (
        choose_catalog_by_number,
        get_default_catalog_name,
        resolve_catalog_name,
        yes_no,
    )

    if requested:
        return resolve_catalog_name(project, requested)

    default_name = get_default_catalog_name(project)

    if not ask_other or not sys.stdin.isatty():
        return default_name

    print()
    print("Katalog")
    print("=======")
    print(f"Standardkatalog: {default_name}")

    if yes_no(f"Standardkatalog '{default_name}' {purpose}?", True):
        return default_name

    return choose_catalog_by_number(
        project,
        default_name=default_name,
        title="Anderen Katalog auswählen",
    )



def get_catalog(
    project: Path,
    catalog_name: str | None = None,
) -> dict[str, Any]:
    from .catalogs import (
        catalog_path,
        resolve_catalog_name,
    )

    from .environment import (
        ensure_initialized,
        load_yaml,
    )
    from .settings import CATALOG_TEMPLATE

    ensure_initialized(project, quiet=True)
    name = resolve_catalog_name(project, catalog_name)
    path = catalog_path(project, name)
    data = load_yaml(path, CATALOG_TEMPLATE)

    if "software_catalog" not in (data or {}):
        data = {"software_catalog": data or {}}

    return data


def save_catalog(
    project: Path,
    data: dict[str, Any],
    catalog_name: str | None = None,
) -> None:
    from .catalogs import (
        catalog_path,
        resolve_catalog_name,
    )

    from .environment import atomic_write_yaml
    from .software import sanitize_catalog_data

    name = resolve_catalog_name(project, catalog_name)
    sanitized = sanitize_catalog_data(data)
    _validate_catalog_for_persistence(sanitized)
    atomic_write_yaml(catalog_path(project, name), sanitized)


def cmd_catalog_list(args: argparse.Namespace) -> None:
    from .catalogs import (
        get_catalog,
        get_default_catalog_name,
        list_catalog_names,
    )

    from .environment import ensure_initialized

    ensure_initialized(args.project, quiet=True)
    default_name = get_default_catalog_name(args.project)
    names = list_catalog_names(args.project)

    print(f"{'KATALOG':<30} {'PAKETE':>8}  STATUS")
    print("-" * 55)

    for name in names:
        count = len(get_catalog(args.project, name).get("software_catalog", {}))
        status = "DEFAULT" if name == default_name else ""
        print(f"{name:<30} {count:>8}  {status}")


def cmd_catalog_create(args: argparse.Namespace) -> None:
    from .catalogs import (
        catalog_path,
        cmd_catalog_set_default,
        get_catalog,
        resolve_catalog_name,
        validate_catalog_name,
    )

    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
    )
    from .settings import CATALOG_TEMPLATE

    ensure_initialized(args.project, quiet=True)
    name = validate_catalog_name(args.name)
    dest = catalog_path(args.project, name)

    if dest.exists():
        die(f"Katalog '{name}' existiert bereits.")

    if args.copy_from:
        source_name = resolve_catalog_name(args.project, args.copy_from)
        source_data = get_catalog(args.project, source_name)
        atomic_write_yaml(dest, source_data)
        print(f"✓ Katalog '{name}' als Kopie von '{source_name}' erstellt.")
    else:
        atomic_write_yaml(dest, CATALOG_TEMPLATE)
        print(f"✓ Katalog '{name}' erstellt.")

    if args.set_default:
        ns = argparse.Namespace(project=args.project, name=name)
        cmd_catalog_set_default(ns)


def cmd_catalog_set_default(args: argparse.Namespace) -> None:
    from .catalogs import (
        resolve_catalog_name,
    )

    from .environment import (
        atomic_write_yaml,
        get_config,
        project_paths,
    )

    name = resolve_catalog_name(args.project, args.name)
    config = get_config(args.project)
    config["default_catalog"] = name
    atomic_write_yaml(project_paths(args.project)["config"], config)
    print(f"✓ Standardkatalog ist jetzt '{name}'.")


def cmd_catalog_copy(args: argparse.Namespace) -> None:
    from .catalogs import (
        catalog_path,
        choose_software_interactive,
        get_catalog,
        resolve_catalog_name,
        save_catalog,
        validate_catalog_name,
        yes_no,
    )

    from .environment import (
        atomic_write_yaml,
        die,
    )
    from .settings import CATALOG_TEMPLATE

    source_name = resolve_catalog_name(args.project, args.source)
    dest_name = validate_catalog_name(args.destination)
    dest_path = catalog_path(args.project, dest_name)

    if not dest_path.exists():
        if getattr(args, "create_destination", False):
            atomic_write_yaml(dest_path, CATALOG_TEMPLATE)
            print(f"✓ Zielkatalog '{dest_name}' wurde automatisch erstellt.")
        elif sys.stdin.isatty() and yes_no(
            f"Zielkatalog '{dest_name}' existiert nicht. Jetzt erstellen?",
            True,
        ):
            atomic_write_yaml(dest_path, CATALOG_TEMPLATE)
            print(f"✓ Zielkatalog '{dest_name}' erstellt.")
        else:
            die(
                f"Zielkatalog '{dest_name}' existiert nicht. "
                "Erst 'catalog create' verwenden oder --create-destination setzen."
            )

    source = get_catalog(args.project, source_name)
    dest = get_catalog(args.project, dest_name)
    source_sw = source["software_catalog"]
    dest_sw = dest["software_catalog"]

    keys = list(args.software or [])

    if args.all:
        keys = list(source_sw.keys())
    elif not keys:
        if not sys.stdin.isatty():
            die("Software-Schlüssel angeben oder --all verwenden.")

        print()
        print("Was soll kopiert werden?")
        print("  1) ALLE Programme (Standard)")
        print("  2) Ein einzelnes Programm")
        print()

        mode = input("> [1] ").strip() or "1"

        if mode == "1":
            keys = list(source_sw.keys())
        elif mode == "2":
            keys = [
                choose_software_interactive(
                    args.project,
                    source_name,
                )
            ]
        else:
            die("Ungültige Auswahl.")

    missing = [key for key in keys if key not in source_sw]
    if missing:
        die(
            f"Nicht in '{source_name}' vorhanden: "
            + ", ".join(missing)
        )

    copied = 0
    skipped = 0

    for key in keys:
        incoming = source_sw[key]

        if key in dest_sw:
            if dest_sw[key] == incoming:
                print(f"= {key}: bereits identisch in '{dest_name}'")
                skipped += 1
                continue

            overwrite = bool(args.overwrite)
            if not overwrite and sys.stdin.isatty():
                overwrite = yes_no(
                    f"'{key}' existiert in '{dest_name}' anders. Überschreiben?",
                    False,
                )

            if not overwrite:
                print(f"- {key}: übersprungen")
                skipped += 1
                continue

        dest_sw[key] = incoming
        print(f"✓ {key}: {source_name} → {dest_name}")
        copied += 1

    save_catalog(args.project, dest, dest_name)
    print(f"\nFertig. Kopiert: {copied}, übersprungen: {skipped}.")


SOFTWARE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_software_key(key: str) -> str:
    """Validate the shared software/Office/WinGet identifier namespace."""
    from .environment import die

    key = str(key or "").strip()
    if not SOFTWARE_KEY_RE.fullmatch(key) or key in {".", ".."}:
        die(
            "Ungültiger Software-Schlüssel. Er muss mit einer Zahl oder einem "
            "Buchstaben beginnen, darf höchstens 64 Zeichen lang sein und nur "
            "Buchstaben, Zahlen, Punkt, Bindestrich und Unterstrich enthalten."
        )
    return key


def validate_host_address(value: str) -> str:
    """Accept exactly one IPv4 address or a DNS FQDN, never an Ansible pattern."""
    from .environment import die

    value = str(value or "").strip().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass

    if not value or len(value) > 253 or "." not in value:
        die("Zieladresse muss eine gültige IPv4-Adresse oder ein FQDN sein.")
    if re.fullmatch(r"[0-9.]+", value):
        die("Ungültige IPv4-Adresse.")
    labels = value.split(".")
    if any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        die("FQDN enthält ein ungültiges DNS-Label.")
    return value.lower()


def _validate_catalog_for_persistence(
    data: dict[str, Any],
    *,
    require_installer_integrity: bool = False,
) -> None:
    """Central fail-closed validation for every catalog writer and installer."""
    from .environment import die
    from .reports import validate_installer_arguments
    from .software import (
        _winget_validate_identifier,
        _winget_validate_source,
        _winget_validate_version,
    )

    if not isinstance(data, dict):
        die("Katalog muss ein YAML-Objekt sein.")
    software_catalog = data.get("software_catalog", {})
    if not isinstance(software_catalog, dict):
        die("software_catalog muss ein YAML-Objekt sein.")

    for raw_key, raw_app in software_catalog.items():
        key = validate_software_key(str(raw_key))
        if not isinstance(raw_app, dict):
            die(f"Katalogeintrag '{key}' muss ein YAML-Objekt sein.")

        validate_installer_arguments(
            raw_app.get("arguments", ""),
            context=f"Katalogeintrag '{key}'",
        )

        app_type = str(raw_app.get("type", "") or "").strip().lower()
        if app_type not in {"msi", "exe", "office_odt", "winget"}:
            die(f"Katalogeintrag '{key}' hat einen ungültigen Typ: {app_type!r}.")

        if app_type == "winget":
            _winget_validate_identifier(raw_app.get("winget_id", ""))
            _winget_validate_source(raw_app.get("winget_source", "winget"))
            _winget_validate_version(raw_app.get("winget_version", ""))
            continue

        sha256 = str(raw_app.get("sha256", "") or "").strip().lower()
        unsafe_without_hash = raw_app.get("allow_unsafe_missing_sha256") is True
        if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
            die(
                f"Katalogeintrag '{key}' enthält keinen gültigen SHA-256. "
                "Erwartet werden exakt 64 hexadezimale Zeichen."
            )
        if require_installer_integrity and not sha256 and not unsafe_without_hash:
            die(
                f"SICHERHEITSABBRUCH: Für den lokalen Installer '{key}' fehlt SHA-256. "
                "Den Eintrag erneut hinzufügen/bearbeiten und hashen. Nur für eine "
                "bewusste Legacy-Ausnahme darf allow_unsafe_missing_sha256: true "
                "direkt im Katalog gesetzt werden."
            )
