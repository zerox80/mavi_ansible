# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Druckerkatalogverwaltung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    csv,
    ipaddress,
    json,
    re,
    sys,
    yaml,
)



def get_printer_catalog(project: Path) -> dict[str, Any]:
    from .environment import (
        die,
        ensure_initialized,
        load_yaml,
        project_paths,
    )
    from .settings import PRINTER_CATALOG_TEMPLATE

    ensure_initialized(project, quiet=True)
    path = project_paths(project)["printer_catalog"]
    data = load_yaml(path, PRINTER_CATALOG_TEMPLATE) or {}
    if not isinstance(data, dict):
        die(f"Druckerkatalog ist kein gültiges YAML-Dictionary: {path}")
    if "printers" not in data:
        data = {"printers": data}
    if not isinstance(data.get("printers"), dict):
        die(f"'printers' im Druckerkatalog ist kein Dictionary: {path}")
    return data


def save_printer_catalog(project: Path, data: dict[str, Any]) -> None:
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )

    atomic_write_yaml(project_paths(project)["printer_catalog"], data)


def choose_printer_interactive(project: Path) -> str:
    from .printers import (
        get_printer_catalog,
    )

    from .catalogs import select_from_list
    from .environment import die

    printers = get_printer_catalog(project)["printers"]
    if not printers:
        die("Keine Drucker im Druckerkatalog vorhanden.")
    items: list[tuple[str, str]] = []
    for key, cfg in printers.items():
        cfg = cfg or {}
        label = f"{cfg.get('name', key)}  [{cfg.get('ip', '?')}]"
        items.append((key, label))
    return select_from_list("Drucker auswählen", items, allow_name=True)


def cmd_printer_add(args: argparse.Namespace) -> None:
    from .printers import (
        _choose_driver_name_from_inf,
        choose_driver_package_root,
        get_printer_catalog,
        resolve_printer_driver_source,
        save_printer_catalog,
    )

    from .catalogs import (
        prompt,
        slugify,
        yes_no,
    )
    from .environment import (
        die,
        ensure_initialized,
        get_config,
    )

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)
    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]

    name = getattr(args, "name", None) or prompt("Druckername auf Windows")
    key_default = slugify(name)
    if key_default == "software":
        key_default = "drucker"
    key = getattr(args, "key", None) or prompt("Drucker-Schlüssel", key_default)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
        die("Drucker-Schlüssel enthält ungültige Zeichen.")

    ip_raw = getattr(args, "ip", None) or prompt("Drucker IPv4-Adresse")
    try:
        parsed_ip = ipaddress.ip_address(ip_raw)
    except ValueError:
        die(f"Ungültige IP-Adresse: {ip_raw}")
    if parsed_ip.version != 4:
        die("Aktuell werden nur IPv4-TCP/IP-Drucker unterstützt.")
    printer_ip = str(parsed_ip)

    inf_path, selected_driver_dir = resolve_printer_driver_source(args, config)
    print()
    print(f"Gewählte Treiber-INF: {inf_path}")

    (
        package_root,
        missing_package_files,
        packed_package_files,
        referenced_package_files,
    ) = choose_driver_package_root(inf_path, config)

    if referenced_package_files:
        resolved_count = len(referenced_package_files) - len(missing_package_files)
        print()
        print(
            f"Treiberpaket-Prüfung: {resolved_count} von "
            f"{len(referenced_package_files)} referenzierten Datei(en) auflösbar."
        )
        if packed_package_files:
            print(
                f"  ✓ {len(packed_package_files)} Payload-Datei(en) liegen laut INF "
                "in vorhandenen CAB-Archiven."
            )
        print(f"Ermittelter Paketordner: {package_root}")

    if missing_package_files:
        print()
        print("! Das Treiberpaket wirkt UNVOLLSTÄNDIG.")
        print("  Die INF referenziert Dateien, die im Paketordner nicht gefunden wurden:")
        for missing_name in missing_package_files[:20]:
            print(f"    - {missing_name}")
        if len(missing_package_files) > 20:
            print(f"    ... und {len(missing_package_files) - 20} weitere")
        print()
        print(
            "  Bitte den VOLLSTÄNDIG entpackten Hersteller-Treiber verwenden, "
            "nicht nur die einzelne INF-Datei."
        )
        force_incomplete = bool(getattr(args, "yes", False))
        if not force_incomplete:
            if not sys.stdin.isatty() or not yes_no(
                "Unvollständiges Paket trotzdem in den Katalog übernehmen?",
                False,
            ):
                die("Drucker wurde wegen unvollständigem Treiberpaket nicht gespeichert.")

    driver_name = getattr(args, "driver_name", None)
    if not driver_name:
        driver_name = _choose_driver_name_from_inf(inf_path)
    driver_name = str(driver_name).strip()
    if not driver_name:
        die("Windows-Treibername darf nicht leer sein.")

    port_number = int(getattr(args, "port_number", 9100) or 9100)
    if not 1 <= port_number <= 65535:
        die("Portnummer muss zwischen 1 und 65535 liegen.")

    port_name = getattr(args, "port_name", None) or f"IP_{printer_ip}"

    if key in printers and not bool(getattr(args, "yes", False)):
        if not sys.stdin.isatty():
            die(f"Drucker '{key}' existiert bereits. Mit --yes überschreiben.")
        if not yes_no(f"Drucker '{key}' existiert bereits. Überschreiben?", False):
            print("Abgebrochen.")
            return

    try:
        inf_relative = inf_path.resolve().relative_to(package_root.resolve()).as_posix()
    except ValueError:
        inf_relative = inf_path.name

    printers[key] = {
        "name": name,
        "ip": printer_ip,
        "port_name": port_name,
        "port_number": port_number,
        "driver_name": driver_name,
        "driver_inf": str(inf_path),
        "driver_source_dir": str(selected_driver_dir or inf_path.parent),
        "driver_package_dir": str(package_root),
        "driver_inf_relative": inf_relative,
    }
    save_printer_catalog(args.project, catalog)

    print()
    print(f"✓ Drucker '{key}' gespeichert.")
    print(f"  Name:       {name}")
    print(f"  IP/Port:    {printer_ip}:{port_number}")
    print(f"  TCP-Port:   {port_name}")
    print(f"  Treiber:    {driver_name}")
    print(f"  INF:        {inf_path}")
    print(f"  Paketordner:{package_root}")
    print(f"  INF relativ:{inf_relative}")


def cmd_printer_list(args: argparse.Namespace) -> None:
    from .printers import (
        get_printer_catalog,
    )

    printers = get_printer_catalog(args.project)["printers"]
    if not printers:
        print("Keine Drucker im Druckerkatalog.")
        return

    print(f"{'KEY':<24} {'NAME':<30} {'IP':<16} TREIBER")
    print("-" * 105)
    for key, cfg in printers.items():
        cfg = cfg or {}
        print(
            f"{key:<24} "
            f"{str(cfg.get('name', key)):<30} "
            f"{str(cfg.get('ip', '')):<16} "
            f"{cfg.get('driver_name', '')}"
        )


def cmd_printer_show(args: argparse.Namespace) -> None:
    from .printers import (
        get_printer_catalog,
    )

    from .environment import die

    printers = get_printer_catalog(args.project)["printers"]
    if args.key not in printers:
        die(f"Drucker '{args.key}' ist nicht im Druckerkatalog.")
    print(
        yaml.safe_dump(
            {args.key: printers[args.key]},
            allow_unicode=True,
            sort_keys=False,
        )
    )


def cmd_printer_remove(args: argparse.Namespace) -> None:
    from .printers import (
        get_printer_catalog,
        save_printer_catalog,
    )

    from .catalogs import yes_no
    from .environment import die

    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]
    if args.key not in printers:
        die(f"Drucker '{args.key}' ist nicht im Druckerkatalog.")

    if not bool(getattr(args, "yes", False)) and not yes_no(
        f"Drucker '{args.key}' wirklich nur aus dem Katalog entfernen?",
        False,
    ):
        print("Abgebrochen.")
        return

    del printers[args.key]
    save_printer_catalog(args.project, catalog)
    print(f"✓ Drucker '{args.key}' aus dem Katalog entfernt.")
    print("  Auf bereits eingerichteten PCs wurde nichts entfernt.")
