# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""Softwarekataloge, Parameterprofile und interaktive Auswahl."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    ipaddress,
    os,
    re,
    sys,
    yaml,
)

def slugify(value: str) -> str:
    value = value.strip().lower()
    for a, b in {
        "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
        "Ä": "ae", "Ö": "oe", "Ü": "ue",
    }.items():
        value = value.replace(a, b)
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "software"


def prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    value = input(f"{text}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def prompt_choice(text: str, choices: list[tuple[str, str]], default: str) -> str:
    print(text)
    for key, label in choices:
        mark = " (Standard)" if key == default else ""
        print(f"  {key}) {label}{mark}")
    valid = {k for k, _ in choices}
    while True:
        value = input("> ").strip() or default
        if value in valid:
            return value
        print("Ungültige Auswahl.")



def select_from_list(
    title: str,
    items: list[tuple[str, str]],
    *,
    default_key: str | None = None,
    allow_name: bool = True,
) -> str:
    """
    Nummerierte Auswahl. Akzeptiert optional weiterhin den Schlüssel/Namen.
    Enter übernimmt default_key, falls gesetzt.
    """
    from .environment import die

    if not items:
        die(f"Keine Einträge für '{title}' vorhanden.")

    keys = [key for key, _ in items]

    print()
    print(title)
    print("=" * len(title))

    for idx, (key, label) in enumerate(items, start=1):
        default_mark = "  [Standard]" if default_key == key else ""
        if label and label != key:
            print(f"  {idx}) {label}  ({key}){default_mark}")
        else:
            print(f"  {idx}) {key}{default_mark}")

    print()

    while True:
        suffix = ""
        if default_key is not None:
            try:
                default_index = keys.index(default_key) + 1
                suffix = f" [{default_index}]"
            except ValueError:
                suffix = ""

        value = input(f">{suffix} ").strip()

        if not value and default_key is not None:
            return default_key

        if value.isdigit():
            idx = int(value) - 1
            if 0 <= idx < len(items):
                return items[idx][0]
            print("Ungültige Nummer.")
            continue

        if allow_name:
            # Exakter Key
            for key, _ in items:
                if value.lower() == key.lower():
                    return key

            # Exaktes Label
            for key, label in items:
                if value.lower() == label.lower():
                    return key

        print("Bitte eine Nummer auswählen" + (" oder Namen eingeben." if allow_name else "."))


def choose_host_interactive(project: Path) -> str:
    from .environment import die
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import _connection_label

    inv = load_inventory(project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}

    if not hosts:
        die("Keine Windows-PCs im Inventory vorhanden.")

    items = []
    for host_name, data in hosts.items():
        data = data or {}
        ip = str(data.get("ansible_host", ""))
        connection = _connection_label(windows, data)
        label = f"{host_name}  [{ip}]  [{connection}]" if ip else f"{host_name}  [{connection}]"
        items.append((host_name, label))

    return select_from_list(
        "Ziel-PC auswählen",
        items,
        allow_name=True,
    )


def choose_software_interactive(
    project: Path,
    catalog_name: str,
) -> str:
    from .environment import die

    catalog = get_catalog(project, catalog_name)["software_catalog"]

    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    items = []
    for key, app in catalog.items():
        name = str(app.get("name", key))
        typ = str(app.get("type", "?")).upper()
        context = str(app.get("context", "machine"))
        label = f"{name}  [{typ}, {context}]"
        items.append((key, label))

    return select_from_list(
        f"Programm aus '{catalog_name}' auswählen",
        items,
        allow_name=True,
    )


CTRL2_SENTINEL = "__Mavi_CTRL2__"


def _input_with_ctrl2(prompt_text: str = "> ") -> str:
    """
    Kleine TUI-Eingabe mit sofortigem Strg+2-Shortcut.

    Viele Linux-Terminals senden Strg+2 als NUL (0x00). In einem echten TTY
    lesen wir deshalb zeichenweise im cbreak-Modus. Auf nicht-interaktiven
    Eingaben fällt die Funktion sauber auf input() zurück. Zusätzlich kann
    jeder Aufrufer 'm' als gut sichtbaren Fallback anbieten.
    """
    if os.name != "posix" or not sys.stdin.isatty() or not sys.stdout.isatty():
        return input(prompt_text).strip()

    try:
        import termios
        import tty
    except ImportError:
        return input(prompt_text).strip()

    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except (termios.error, OSError):
        return input(prompt_text).strip()

    buffer = bytearray()
    sys.stdout.write(prompt_text)
    sys.stdout.flush()

    try:
        tty.setcbreak(fd)
        while True:
            raw = os.read(fd, 1)
            if not raw:
                sys.stdout.write("\n")
                return buffer.decode("utf-8", errors="replace").strip()

            # Strg+2 wird in den üblichen xterm/SSH-Terminals als NUL gesendet.
            if raw == b"\x00":
                sys.stdout.write("^2  → Mehrfachmodus\n")
                sys.stdout.flush()
                return CTRL2_SENTINEL

            if raw in {b"\r", b"\n"}:
                sys.stdout.write("\n")
                sys.stdout.flush()
                return buffer.decode("utf-8", errors="replace").strip()

            if raw in {b"\x7f", b"\x08"}:
                if buffer:
                    # Menüs erwarten überwiegend ASCII/Nummern; ein Byte reicht
                    # hier für den schnellen Rückschritt vollständig aus.
                    buffer.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue

            # Escape-Sequenzen (Pfeiltasten etc.) nicht als Menütext übernehmen.
            if raw == b"\x1b":
                continue

            buffer.extend(raw)
            try:
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            except Exception:
                sys.stdout.write(raw.decode("utf-8", errors="ignore"))
                sys.stdout.flush()
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass


def _software_selection_rows(catalog: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (str(key), raw_app if isinstance(raw_app, dict) else {})
        for key, raw_app in catalog.items()
    ]


def choose_software_single_with_multi_shortcut(
    project: Path,
    catalog_name: str,
    *,
    title: str | None = None,
) -> tuple[str | None, bool]:
    """Ein Programm wählen; Strg+2/M signalisiert Wechsel in Mehrfachmodus."""
    from .environment import die
    from .reports import _software_mode_meta

    catalog = get_catalog(project, catalog_name)["software_catalog"]
    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    rows = _software_selection_rows(catalog)
    heading = title or f"Programm aus '{catalog_name}' auswählen"

    while True:
        print()
        print(heading)
        print("=" * len(heading))
        for idx, (key, app) in enumerate(rows, start=1):
            meta = _software_mode_meta(app)
            name = str(app.get("name", key))
            typ = str(app.get("type", "?")).upper()
            print(f"  {idx:>2}) {name}  [{typ} | {meta['mode']}]  ({key})")
        print()
        print("  Strg+2  → MEHRFACHAUSWAHL / Programme markieren")
        print("  m       → dasselbe als Fallback")
        print()

        value = _input_with_ctrl2("> ").strip()
        if value == CTRL2_SENTINEL or value.lower() in {"m", "multi", "mehrfach"}:
            return None, True

        if value.isdigit():
            idx = int(value) - 1
            if 0 <= idx < len(rows):
                return rows[idx][0], False
            print("Ungültige Nummer.")
            continue

        for key, app in rows:
            name = str(app.get("name", key))
            if value.casefold() in {key.casefold(), name.casefold()}:
                return key, False

        print("Bitte Nummer, Schlüssel oder exakten Namen eingeben. Strg+2 = Mehrfachmodus.")


def choose_software_multi_interactive(
    project: Path,
    catalog_name: str,
    *,
    title: str = "PROGRAMME MARKIEREN",
) -> list[str]:
    """
    Checklisten-artige Mehrfachauswahl.

    Nummern/Bereiche toggeln die Markierung. Enter bestätigt die aktuelle
    Auswahl. Dadurch kann man z.B. nacheinander 2, 5 und 8-10 markieren.
    """
    from .environment import die
    from .reports import _software_mode_meta

    catalog = get_catalog(project, catalog_name)["software_catalog"]
    if not catalog:
        die(f"Katalog '{catalog_name}' ist leer.")

    rows = _software_selection_rows(catalog)
    selected: set[int] = set()

    while True:
        print()
        print(title)
        print("=" * len(title))
        print(f"Katalog: {catalog_name} | Markiert: {len(selected)}")
        print()

        for idx, (key, app) in enumerate(rows, start=1):
            mark = "X" if idx in selected else " "
            meta = _software_mode_meta(app)
            name = str(app.get("name", key))
            typ = str(app.get("type", "?")).upper()
            print(f"  {idx:>2}) [{mark}] {name}  [{typ} | {meta['mode']}]  ({key})")

        print()
        print("Nummern toggeln:  1,3,5   |   2-6   |   1,4,7-10")
        print("a = alle markieren   c = leeren   Enter = Auswahl übernehmen   0 = abbrechen")
        print()

        raw = input("Markieren > ").strip()
        lowered = raw.casefold()

        if raw == "0":
            return []
        if not raw:
            if not selected:
                print("! Noch kein Programm markiert.")
                continue
            return [rows[idx - 1][0] for idx in sorted(selected)]
        if lowered in {"a", "alle", "all", "*"}:
            selected = set(range(1, len(rows) + 1))
            continue
        if lowered in {"c", "clear", "leer", "leeren"}:
            selected.clear()
            continue

        try:
            toggles = _parse_multi_program_selection(raw, len(rows))
        except ValueError as exc:
            print(f"! {exc}")
            continue

        for number in toggles:
            if number in selected:
                selected.remove(number)
            else:
                selected.add(number)


def choose_catalog_by_number(
    project: Path,
    *,
    default_name: str | None = None,
    title: str = "Katalog auswählen",
) -> str:
    from .environment import die

    names = list_catalog_names(project)

    if not names:
        die("Keine Kataloge vorhanden.")

    if default_name is None:
        default_name = get_default_catalog_name(project)

    items = []
    for name in names:
        label = name
        if name == get_default_catalog_name(project):
            label = f"{name} [DEFAULT]"
        items.append((name, label))

    return select_from_list(
        title,
        items,
        default_key=default_name if default_name in names else None,
        allow_name=True,
    )

def yes_no(text: str, default: bool = True) -> bool:
    suffix = "[J/n]" if default else "[j/N]"
    value = input(f"{text} {suffix} ").strip().lower()
    if not value:
        return default
    return value in {"j", "ja", "y", "yes"}


CATALOG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
SOFTWARE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_catalog_name(name: str) -> str:
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


def catalog_path(project: Path, catalog_name: str) -> Path:
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
    from .environment import atomic_write_yaml
    from .software import sanitize_catalog_data

    name = resolve_catalog_name(project, catalog_name)
    sanitized = sanitize_catalog_data(data)
    _validate_catalog_for_persistence(sanitized)
    atomic_write_yaml(catalog_path(project, name), sanitized)


def cmd_catalog_list(args: argparse.Namespace) -> None:
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
    data = load_parameter_backups(project)
    profiles = data.setdefault("parameter_profiles", {})
    profiles[key] = parameter_profile_from_app(
        key,
        app,
        catalog_name,
    )
    save_parameter_backups(project, data)


def cmd_params_backup(args: argparse.Namespace) -> None:
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
    visible = set(get_visible_install_contexts(project))
    rows = [row for row in EDITABLE_CONTEXTS if row[1] in visible]
    return [
        (str(index), value, label)
        for index, (_, value, label) in enumerate(rows, start=1)
    ]


def prompt_install_context(project: Path, default_context: str = "machine") -> str:
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


def _save_quick_edit(
    project: Path,
    catalog_name: str,
    catalog: dict[str, Any],
    key: str,
) -> None:
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


def catalog_menu(project: Path) -> None:
    from .reports import (
        cmd_software_list,
        cmd_software_remove,
    )
    from .software import cmd_catalog_repair

    while True:
        default_name = get_default_catalog_name(project)

        print()
        print("KATALOGE VERWALTEN")
        print("==================")
        print(f"Standard: {default_name}")
        print()
        print("  1) Kataloge anzeigen")
        print("  2) Programme in einem Katalog anzeigen")
        print("  3) Programm schnell bearbeiten")
        print("  4) Programm aus einem Katalog entfernen")
        print("  5) Neuen Katalog erstellen")
        print("  6) Standardkatalog festlegen")
        print("  7) Software zwischen Katalogen kopieren")
        print("  8) Parameter-Backups verwalten")
        print("  9) Alten Scan-Müll aus Katalog entfernen")
        print(" 10) Mehrfachmodus: Programme markieren / Installationsmodus ändern")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()

        if choice == "1":
            cmd_catalog_list(
                argparse.Namespace(
                    project=project,
                )
            )

        elif choice == "2":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            cmd_software_list(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                )
            )

        elif choice == "3":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            catalog = get_catalog(
                project,
                catalog_name,
            )

            if not catalog.get("software_catalog"):
                print(f"Katalog '{catalog_name}' ist leer.")
                continue

            software_key, multi_mode = choose_software_single_with_multi_shortcut(
                project,
                catalog_name,
                title=f"Programm aus '{catalog_name}' schnell bearbeiten",
            )

            if multi_mode:
                bulk_install_context_menu(project, catalog_name)
                continue

            if software_key is None:
                continue

            cmd_software_edit(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    key=software_key,
                )
            )

        elif choice == "4":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog auswählen",
            )

            catalog = get_catalog(
                project,
                catalog_name,
            )

            if not catalog.get("software_catalog"):
                print(f"Katalog '{catalog_name}' ist leer.")
                continue

            software_key = choose_software_interactive(
                project,
                catalog_name,
            )

            cmd_software_remove(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    key=software_key,
                    yes=False,
                )
            )

        elif choice == "5":
            name = prompt("Neuer Katalogname")
            copy_from = None

            if yes_no(
                "Bestehenden Katalog als Vorlage kopieren?",
                False,
            ):
                copy_from = choose_catalog_by_number(
                    project,
                    default_name=default_name,
                    title="Vorlage auswählen",
                )

            set_default = yes_no(
                "Diesen Katalog als Standard setzen?",
                False,
            )

            cmd_catalog_create(
                argparse.Namespace(
                    project=project,
                    name=name,
                    copy_from=copy_from,
                    set_default=set_default,
                )
            )

        elif choice == "6":
            name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Neuen Standardkatalog auswählen",
            )

            cmd_catalog_set_default(
                argparse.Namespace(
                    project=project,
                    name=name,
                )
            )

        elif choice == "7":
            source = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Quellkatalog auswählen",
            )

            destination = choose_catalog_by_number(
                project,
                default_name=None,
                title="Zielkatalog auswählen",
            )

            source_data = get_catalog(
                project,
                source,
            )["software_catalog"]

            if not source_data:
                print(f"Katalog '{source}' ist leer.")
                continue

            print()
            print("Was soll kopiert werden?")
            print("  1) ALLE Programme (Standard)")
            print("  2) Ein einzelnes Programm")
            mode = input("> [1] ").strip() or "1"

            if mode == "1":
                all_ = True
                software = []

            elif mode == "2":
                all_ = False
                software = [
                    choose_software_interactive(
                        project,
                        source,
                    )
                ]

            else:
                print("Ungültige Auswahl.")
                continue

            cmd_catalog_copy(
                argparse.Namespace(
                    project=project,
                    source=source,
                    destination=destination,
                    software=software,
                    all=all_,
                    overwrite=False,
                    create_destination=False,
                )
            )

        elif choice == "8":
            parameter_backup_menu(project)

        elif choice == "9":
            catalog_name = choose_catalog_by_number(
                project,
                default_name=default_name,
                title="Katalog reparieren",
            )

            cmd_catalog_repair(
                argparse.Namespace(
                    project=project,
                    catalog=catalog_name,
                    all=False,
                )
            )

        elif choice == "10":
            bulk_install_context_menu(project)

        elif choice == "0":
            return

        else:
            print("Ungültige Auswahl.")




def cmd_init(args: argparse.Namespace) -> None:
    from .environment import ensure_initialized

    ensure_initialized(args.project)



OFFICE_PRODUCTS: dict[str, dict[str, Any]] = {
    # Planner / Project subscription
    "project_plan3": {
        "name": "Planner and Project Plan 3",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },
    "project_plan5": {
        "name": "Planner and Project Plan 5",
        "product_id": "ProjectProRetail",
        "family": "project",
        "channel": None,
    },

    # Microsoft 365 / Office 365
    "m365_apps_enterprise": {
        "name": "Microsoft 365 Apps for enterprise (EEA / ohne Teams)",
        "product_id": "O365ProPlusEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_apps_business": {
        "name": "Microsoft 365 Apps for business (EEA / ohne Teams)",
        "product_id": "O365BusinessEEANoTeamsRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_standard": {
        "name": "Microsoft 365 Business Standard",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_business_premium": {
        "name": "Microsoft 365 Business Premium",
        "product_id": "O365BusinessRetail",
        "family": "office",
        "channel": None,
    },
    "m365_e3_e5": {
        "name": "Microsoft 365 E3/E5 oder Office 365 E3/E5",
        "product_id": "O365ProPlusRetail",
        "family": "office",
        "channel": None,
    },

    # Office 2024 Retail / Volume
    "office_home_business_2024": {
        "name": "Office Home & Business 2024 Retail",
        "product_id": "HomeBusiness2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_professional_2024": {
        "name": "Office Professional 2024 Retail",
        "product_id": "Professional2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_proplus_2024_retail": {
        "name": "Office Professional Plus 2024 Retail",
        "product_id": "ProPlus2024Retail",
        "family": "office",
        "channel": None,
    },
    "office_ltsc_proplus_2024": {
        "name": "Office LTSC Professional Plus 2024 Volume",
        "product_id": "ProPlus2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },
    "office_ltsc_standard_2024": {
        "name": "Office LTSC Standard 2024 Volume",
        "product_id": "Standard2024Volume",
        "family": "office",
        "channel": "PerpetualVL2024",
    },

    # Project 2024
    "project_pro_2024_retail": {
        "name": "Project Professional 2024 Retail",
        "product_id": "ProjectPro2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_std_2024_retail": {
        "name": "Project Standard 2024 Retail",
        "product_id": "ProjectStd2024Retail",
        "family": "project",
        "channel": None,
    },
    "project_pro_2024_volume": {
        "name": "Project Professional LTSC 2024 Volume",
        "product_id": "ProjectPro2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },
    "project_std_2024_volume": {
        "name": "Project Standard LTSC 2024 Volume",
        "product_id": "ProjectStd2024Volume",
        "family": "project",
        "channel": "PerpetualVL2024",
    },

    # Visio
    "visio_subscription": {
        "name": "Visio Professional Subscription / Visio Plan 2",
        "product_id": "VisioProRetail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_retail": {
        "name": "Visio Professional 2024 Retail",
        "product_id": "VisioPro2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_std_2024_retail": {
        "name": "Visio Standard 2024 Retail",
        "product_id": "VisioStd2024Retail",
        "family": "visio",
        "channel": None,
    },
    "visio_pro_2024_volume": {
        "name": "Visio Professional LTSC 2024 Volume",
        "product_id": "VisioPro2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
    "visio_std_2024_volume": {
        "name": "Visio Standard LTSC 2024 Volume",
        "product_id": "VisioStd2024Volume",
        "family": "visio",
        "channel": "PerpetualVL2024",
    },
}

__all__ = (
    "slugify",
    "prompt",
    "prompt_choice",
    "select_from_list",
    "choose_host_interactive",
    "choose_software_interactive",
    "CTRL2_SENTINEL",
    "_input_with_ctrl2",
    "_software_selection_rows",
    "choose_software_single_with_multi_shortcut",
    "choose_software_multi_interactive",
    "choose_catalog_by_number",
    "yes_no",
    "CATALOG_NAME_RE",
    "SOFTWARE_KEY_RE",
    "validate_catalog_name",
    "validate_software_key",
    "validate_host_address",
    "_validate_catalog_for_persistence",
    "catalog_path",
    "list_catalog_names",
    "get_default_catalog_name",
    "resolve_catalog_name",
    "choose_catalog_interactive",
    "get_catalog",
    "save_catalog",
    "cmd_catalog_list",
    "cmd_catalog_create",
    "cmd_catalog_set_default",
    "cmd_catalog_copy",
    "PARAMETER_PROFILE_FIELDS",
    "load_parameter_backups",
    "_scrub_parameter_backup_secrets",
    "save_parameter_backups",
    "parameter_profile_from_app",
    "backup_parameter_profile",
    "cmd_params_backup",
    "cmd_params_list",
    "_restore_parameter_profile",
    "cmd_params_restore",
    "parameter_backup_menu",
    "EDITABLE_CONTEXTS",
    "_context_label",
    "DEFAULT_VISIBLE_INSTALL_CONTEXTS",
    "_normalize_context_value",
    "get_visible_install_contexts",
    "_visible_context_choices",
    "prompt_install_context",
    "install_context_options_menu",
    "options_menu",
    "_save_quick_edit",
    "cmd_software_edit",
    "_parse_multi_program_selection",
    "_bulk_context_compatibility",
    "_apply_bulk_install_context",
    "bulk_install_context_menu",
    "catalog_menu",
    "cmd_init",
    "OFFICE_PRODUCTS",
)
