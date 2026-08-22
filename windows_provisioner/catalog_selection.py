# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktive Auswahlhilfen.

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
    from .catalogs import (
        select_from_list,
    )

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
    from .catalogs import (
        get_catalog,
        select_from_list,
    )

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
    from .catalogs import (
        CTRL2_SENTINEL,
    )

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
    from .catalogs import (
        CTRL2_SENTINEL,
        _input_with_ctrl2,
        _software_selection_rows,
        get_catalog,
    )

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
    from .catalogs import (
        _parse_multi_program_selection,
        _software_selection_rows,
        get_catalog,
    )

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
    from .catalogs import (
        get_default_catalog_name,
        list_catalog_names,
        select_from_list,
    )

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
