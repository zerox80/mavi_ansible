# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktives Katalogmenü.

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



def catalog_menu(project: Path) -> None:
    from .catalogs import (
        bulk_install_context_menu,
        choose_catalog_by_number,
        choose_software_interactive,
        choose_software_single_with_multi_shortcut,
        cmd_catalog_copy,
        cmd_catalog_create,
        cmd_catalog_list,
        cmd_catalog_set_default,
        cmd_software_edit,
        get_catalog,
        get_default_catalog_name,
        parameter_backup_menu,
        prompt,
        yes_no,
    )

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
