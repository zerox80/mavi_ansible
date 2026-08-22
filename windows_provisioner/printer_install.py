# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Druckerinstallation und Menü.

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



def cmd_printer_install(args: argparse.Namespace) -> None:
    from .printers import (
        choose_driver_package_root,
        find_inf_driver_name_candidates,
        get_printer_catalog,
        save_printer_catalog,
    )

    from .environment import (
        die,
        ensure_initialized,
        get_config,
        project_paths,
    )
    from .execution import (
        ensure_windows_tree,
        load_inventory,
        run_subprocess,
    )

    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)
    catalog = get_printer_catalog(args.project)
    printers = catalog["printers"]

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}
    if args.host not in hosts:
        die(f"Host '{args.host}' ist nicht im Windows-Inventory vorhanden.")

    requested = list(getattr(args, "printers", []) or [])
    install_all = bool(getattr(args, "all", False))
    if install_all:
        if not printers:
            die("Druckerkatalog ist leer.")
        requested = []
    elif not requested:
        die("Drucker-Schlüssel angeben oder --all verwenden.")
    else:
        missing = [key for key in requested if key not in printers]
        if missing:
            die("Nicht im Druckerkatalog: " + ", ".join(missing))

    extra = {
        "printer_catalog_file": str(p["printer_catalog"]),
        "install_all_printers": install_all,
        "printer_names": requested,
        # Unbekannten Publisher niemals in einem unbeaufsichtigten Lauf blind vertrauen.
        # Interaktiv darf das Ansible-Playbook Subject/Issuer/Thumbprint anzeigen
        # und explizit nach einer Freigabe fragen.
        "printer_prompt_publisher_trust": bool(sys.stdin.isatty()),
    }

    selected = list(printers.keys()) if install_all else requested

    # Lokaler Treiber-Preflight, bevor wir hunderte MB auf den Ziel-PC kopieren.
    # Gleichzeitig migriert v0.8.17-Einträge auf Paket-Root + relativen INF-Pfad.
    config = get_config(args.project)
    catalog_changed = False
    print()
    print("Mavi DRUCKER-PREFLIGHT")
    print("=====================")
    for key in selected:
        cfg = printers[key] or {}
        inf_raw = str(cfg.get("driver_inf") or "").strip()
        if not inf_raw:
            die(f"Drucker '{key}' hat keine driver_inf im Katalog.")
        inf_path = Path(inf_raw)
        if not inf_path.exists() or not inf_path.is_file():
            die(f"Drucker '{key}': Treiber-INF fehlt lokal: {inf_path}")

        package_root, missing_files, packed_files, referenced_files = choose_driver_package_root(
            inf_path, config
        )
        if missing_files:
            print(f"\n! {key}: Treiberpaket ist unvollständig.")
            print(
                f"  {len(referenced_files) - len(missing_files)} von "
                f"{len(referenced_files)} referenzierten Datei(en) auflösbar."
            )
            for missing_name in missing_files[:20]:
                print(f"    FEHLT: {missing_name}")
            if len(missing_files) > 20:
                print(f"    ... und {len(missing_files) - 20} weitere")
            die(
                "Druckerinstallation abgebrochen. Vollständig entpackten "
                f"Treiberordner für '{key}' bereitstellen und Drucker neu hinzufügen."
            )

        try:
            inf_relative = inf_path.resolve().relative_to(
                package_root.resolve()
            ).as_posix()
        except ValueError:
            inf_relative = inf_path.name

        if str(cfg.get("driver_package_dir") or "") != str(package_root):
            cfg["driver_package_dir"] = str(package_root)
            catalog_changed = True
        if str(cfg.get("driver_inf_relative") or "") != inf_relative:
            cfg["driver_inf_relative"] = inf_relative
            catalog_changed = True

        driver_name = str(cfg.get("driver_name") or "").strip()
        candidates = find_inf_driver_name_candidates(inf_path, driver_name)
        exact = [x for x in candidates if x.casefold() == driver_name.casefold()]
        if not exact and driver_name:
            contained = [
                x for x in candidates
                if driver_name.casefold() in x.casefold()
            ]
            if len(contained) == 1:
                old_name = driver_name
                driver_name = contained[0]
                cfg["driver_name"] = driver_name
                catalog_changed = True
                print(
                    f"  {key}: Treibername präzisiert: "
                    f"'{old_name}' -> '{driver_name}'"
                )

        if referenced_files:
            found_text = f"{len(referenced_files)} Referenz(en) geprüft"
            if packed_files:
                found_text += f", davon {len(packed_files)} in CAB"
        else:
            found_text = "keine SourceDisksFiles-Liste in INF"
        print(
            f"  ✓ {key}: {found_text} | Paket: {package_root.name} | "
            f"Treiber: {cfg.get('driver_name')}"
        )

    if catalog_changed:
        save_printer_catalog(args.project, catalog)
        print("  ✓ Druckerkatalog automatisch auf aktuelle Drucker-Metadaten aktualisiert.")

    print()
    print("Mavi DRUCKERPLAN")
    print("================")
    for index, key in enumerate(selected, 1):
        cfg = printers[key]
        print(
            f"  {index:02d}. {key}: {cfg.get('name', key)} | "
            f"{cfg.get('ip')}:{cfg.get('port_number', 9100)} | "
            f"{cfg.get('driver_name')}"
        )

    cmd = [
        "ansible-playbook",
        "-i",
        str(p["inventory"]),
        str(p["printer_playbook"]),
        "--limit",
        args.host,
        "--ask-vault-pass",
        "-e",
        json.dumps(extra, ensure_ascii=False),
    ]
    raise SystemExit(run_subprocess(cmd, args.project))


def printer_menu(project: Path) -> None:
    from .printers import (
        choose_printer_interactive,
        cmd_printer_add,
        cmd_printer_install,
        cmd_printer_list,
        cmd_printer_remove,
    )

    from .catalogs import choose_host_interactive

    while True:
        print()
        print("DRUCKER")
        print("=======")
        print("  1) TCP/IP-Drucker + Treiberordner zum Katalog hinzufügen")
        print("  2) Druckerkatalog anzeigen")
        print("  3) Einen Drucker auf PC installieren")
        print("  4) ALLE Drucker auf PC installieren")
        print("  5) Drucker aus Katalog entfernen")
        print("  0) Zurück")
        print()

        choice = input("> ").strip()
        if choice == "1":
            cmd_printer_add(
                argparse.Namespace(
                    project=project,
                    name=None,
                    key=None,
                    ip=None,
                    driver_dir=None,
                    driver_inf=None,
                    driver_name=None,
                    port_name=None,
                    port_number=9100,
                    yes=False,
                )
            )
        elif choice == "2":
            cmd_printer_list(argparse.Namespace(project=project))
        elif choice in {"3", "4"}:
            host = choose_host_interactive(project)
            if choice == "3":
                key = choose_printer_interactive(project)
                selected = [key]
                all_ = False
            else:
                selected = []
                all_ = True
            try:
                cmd_printer_install(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        printers=selected,
                        all=all_,
                    )
                )
            except SystemExit as exc:
                if exc.code not in (0, None):
                    print(f"\nDruckerinstallation beendet mit Code {exc.code}.")
        elif choice == "5":
            key = choose_printer_interactive(project)
            cmd_printer_remove(
                argparse.Namespace(project=project, key=key, yes=False)
            )
        elif choice == "0":
            return
        else:
            print("Ungültige Auswahl.")
