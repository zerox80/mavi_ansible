# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktives Hauptmenü.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations


from ._dependencies import (
    re,
)
from ._dependencies import (
    Path,
    argparse,
)


def menu(project: Path) -> None:
    """
    Die öffentliche, TUI-first Startansicht. Die historische Vollansicht
    bleibt als Untermenü erhalten, damit kein vorhandenes Feature verloren geht.
    """

    from .environment import (
        _mavi_profile_ready,
        ensure_initialized,
        get_config,
    )
    from .printers import printer_menu

    ensure_initialized(project, quiet=True)

    while True:
        config = get_config(project)
        profile = config.get("profile", {}) or {}
        profile_name = str(profile.get("name", "") or "").strip()
        setup_state = "bereit" if _mavi_profile_ready(config) else "Einrichtung offen"

        print(
            "\n"
            "╔══════════════════════════════════════╗\n"
            "║           MAVI PROVISIONER            ║\n"
            "╚══════════════════════════════════════╝\n"
            f" Umgebung: {profile_name or '(noch nicht benannt)'}  |  {setup_state}\n"
            "\n"
            "  1) Grundprofil & Softwarequelle\n"
            "  2) Zugangsdaten & Vault\n"
            "  3) Doctor & Bereitschaft\n"
            "  4) PCs & Verbindung\n"
            "  5) Software, Kataloge und Microsoft-Produkte\n"
            "  6) Drucker\n"
            "  7) Vollständige Funktionsoberfläche\n"
            "  0) Beenden\n"
        )

        choice = input("> ").strip()
        try:
            if choice == "1":
                mavi_setup_menu(project)
            elif choice == "2":
                mavi_credentials_menu(project)
            elif choice == "3":
                mavi_doctor_menu(project)
            elif choice == "4":
                mavi_pc_menu(project)
            elif choice == "5":
                print("\nDie vollständige Software- und Katalogverwaltung öffnet sich jetzt.")
                legacy_menu(project)
            elif choice == "6":
                printer_menu(project)
            elif choice == "7":
                legacy_menu(project)
            elif choice == "0":
                print("Tschüss.")
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


_LEGACY_MENU_ITEMS = (
    ("1", "Normale Software hinzufügen"),
    ("2", "Microsoft-Produkt hinzufügen"),
    ("3", "Software-Katalog anzeigen"),
    ("4", "Software installieren"),
    ("5", "Kataloge verwalten"),
    ("6", "Neuen PC hinzufügen"),
    ("7", "PCs anzeigen"),
    ("8", "Verbindung testen (win_ping)"),
    ("9", "Dateien initialisieren / prüfen"),
    ("10", "Drucker verwalten / installieren"),
    ("11", "OpenSSH / Windows-Verbindung verwalten"),
    ("12", "Optionen / TUI anpassen"),
    ("13", "WinGet-Software suchen / hinzufügen"),
    ("14", "Microsoft Store-App suchen / hinzufügen"),
    ("15", "Windows-Client optimieren / Programme bereinigen"),
    ("16", "PC aus der Liste entfernen"),
)


_LEGACY_MENU_COMPACT_KEYS = frozenset({"1", "3", "4", "6", "7", "8"})


_LEGACY_MENU_TOGGLE_CHOICES = frozenset({"m", "mehr", "+"})


def _render_legacy_menu(default_catalog: str, expanded: bool) -> str:
    """Rendert die vollständige Funktionsoberfläche kurz oder aufgeklappt."""
    visible_items = (
        _LEGACY_MENU_ITEMS
        if expanded
        else tuple(
            item
            for item in _LEGACY_MENU_ITEMS
            if item[0] in _LEGACY_MENU_COMPACT_KEYS
        )
    )
    item_lines = "\n".join(
        f" {number:>2}) {label}" for number, label in visible_items
    )
    toggle_label = "Weniger anzeigen" if expanded else "Mehr anzeigen"

    return (
        "\n"
        "╔══════════════════════════════════════╗\n"
        "║   MAVI PROVISIONER — VOLLVERSION      ║\n"
        "╚══════════════════════════════════════╝\n"
        f" Standardkatalog: {default_catalog}\n"
        "\n"
        f"{item_lines}\n"
        f"  M) {toggle_label}\n"
        "  0) Beenden\n"
    )


def legacy_menu(project: Path) -> None:
    from .catalogs import (
        catalog_menu,
        choose_catalog_interactive,
        choose_host_interactive,
        choose_software_multi_interactive,
        choose_software_single_with_multi_shortcut,
        cmd_init,
        get_default_catalog_name,
        options_menu,
        prompt,
    )
    from .clients import client_menu
    from .environment import ensure_initialized
    from .execution import (
        cmd_host_add,
        cmd_host_list,
        cmd_host_remove,
        cmd_install,
        cmd_ping,
        selected_apps_need_user,
    )
    from .openssh import ssh_menu
    from .printers import printer_menu
    from .reports import cmd_software_list
    from .software import (
        cmd_microsoft_add,
        cmd_software_add,
        cmd_store_add,
        cmd_winget_add,
    )

    ensure_initialized(project, quiet=True)
    expanded = False

    while True:
        default_catalog = get_default_catalog_name(project)

        print(_render_legacy_menu(default_catalog, expanded))

        choice = input("> ").strip()

        if choice.casefold() in _LEGACY_MENU_TOGGLE_CHOICES:
            expanded = not expanded
            continue

        try:
            if choice == "1":
                cmd_software_add(
                    argparse.Namespace(
                        project=project,
                        path=None,
                        name=None,
                        key=None,
                        catalog=None,
                        odt=None,
                    )
                )

            elif choice == "2":
                cmd_microsoft_add(
                    argparse.Namespace(
                        project=project,
                        catalog=None,
                        name=None,
                        key=None,
                        odt=None,
                    )
                )

            elif choice == "3":
                catalog_name = choose_catalog_interactive(
                    project,
                    None,
                    purpose="anzeigen",
                    ask_other=True,
                )
                cmd_software_list(
                    argparse.Namespace(
                        project=project,
                        catalog=catalog_name,
                    )
                )

            elif choice == "4":
                host = choose_host_interactive(project)

                catalog_name = choose_catalog_interactive(
                    project,
                    None,
                    purpose="für die Installation verwenden",
                    ask_other=True,
                )

                print()
                print("Was soll installiert werden?")
                print("  1) ALLE Programme aus diesem Katalog (Standard)")
                print("  2) Ein einzelnes Programm")
                print("  3) Mehrere Programme markieren")
                print("     Tipp: In 'Ein einzelnes Programm' wechselt Strg+2 sofort in den Markiermodus.")
                print()

                install_mode = input("> [1] ").strip() or "1"

                if install_mode == "1":
                    names = []
                    install_all = True

                elif install_mode == "2":
                    install_all = False
                    software_key, multi_mode = choose_software_single_with_multi_shortcut(
                        project,
                        catalog_name,
                        title=f"Einzelnes Programm aus '{catalog_name}' auswählen",
                    )
                    if multi_mode:
                        names = choose_software_multi_interactive(
                            project,
                            catalog_name,
                            title="PROGRAMME FÜR INSTALLATION MARKIEREN",
                        )
                        if not names:
                            print("Installation abgebrochen. Keine Programme markiert.")
                            continue
                    else:
                        if software_key is None:
                            continue
                        names = [software_key]

                elif install_mode == "3":
                    install_all = False
                    names = choose_software_multi_interactive(
                        project,
                        catalog_name,
                        title="PROGRAMME FÜR INSTALLATION MARKIEREN",
                    )
                    if not names:
                        print("Installation abgebrochen. Keine Programme markiert.")
                        continue

                else:
                    print("Ungültige Auswahl.")
                    continue

                target = ""
                if selected_apps_need_user(
                    project,
                    names,
                    install_all,
                    catalog_name,
                ):
                    target = prompt(
                        "Zielbenutzer für INTERAKTIVE Pakete "
                        "(Enter = aktuell angemeldet)",
                        "",
                    )

                ns = argparse.Namespace(
                    project=project,
                    host=host,
                    software=names,
                    all=install_all,
                    target_user=target,
                    check=False,
                    catalog=catalog_name,
                    status_interval=10.0,
                    live_probe=True,
                )

                try:
                    cmd_install(ns)
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(
                            f"\nInstallation beendet mit Code {exc.code}."
                        )

            elif choice == "5":
                catalog_menu(project)

            elif choice == "6":
                cmd_host_add(
                    argparse.Namespace(
                        project=project,
                        name=None,
                        ip=None,
                        ansible_user=None,
                        local_admin=None,
                        connection=None,
                        ssh_key=None,
                        ssh_port=None,
                    )
                )

            elif choice == "7":
                cmd_host_list(argparse.Namespace(project=project))

            elif choice == "8":
                host = choose_host_interactive(project)
                try:
                    cmd_ping(
                        argparse.Namespace(
                            project=project,
                            host=host,
                        )
                    )
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"\nPing beendet mit Code {exc.code}.")

            elif choice == "9":
                cmd_init(argparse.Namespace(project=project))

            elif choice == "10":
                printer_menu(project)

            elif choice == "11":
                ssh_menu(project)

            elif choice == "12":
                options_menu(project)

            elif choice == "13":
                cmd_winget_add(
                    argparse.Namespace(
                        project=project,
                        host=None,
                        query=None,
                        package_id=None,
                        source="winget",
                        catalog=None,
                        name=None,
                        key=None,
                        scope=None,
                        version=None,
                    )
                )

            elif choice == "14":
                cmd_store_add(
                    argparse.Namespace(
                        project=project,
                        host=None,
                        query=None,
                        package_id=None,
                        source="msstore",
                        catalog=None,
                        name=None,
                        key=None,
                        scope="user",
                        version=None,
                    )
                )

            elif choice == "15":
                client_menu(project)

            elif choice == "16":
                host = choose_host_interactive(project)
                cmd_host_remove(
                    argparse.Namespace(
                        project=project,
                        name=host,
                        yes=False,
                    )
                )

            elif choice == "0":
                print("Tschüss.")
                return

            else:
                print("Ungültige Auswahl.")

        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return


def mavi_software_source_setup(project: Path) -> None:
    """Softwarequelle und Windows-Pfadabbildungen vollständig in der TUI pflegen."""
    from .catalogs import (
        prompt,
        prompt_choice,
        slugify,
        yes_no,
    )
    from .environment import (
        _mavi_drive_label,
        _mavi_mount_smb_source,
        _mavi_profile_validation_issues,
        _mavi_prompt_source_root,
        _mavi_unc_mount_parts,
        _mavi_write_config,
        ensure_initialized,
        get_config,
    )

    ensure_initialized(project, quiet=True)
    config = get_config(project)
    source = dict(config.get("software_source", {}) or {})
    old_source = dict(source)

    print()
    print("SOFTWAREQUELLE EINRICHTEN")
    print("=========================")

    source["label"] = prompt(
        "Bezeichnung",
        str(source.get("label", "") or "").strip() or "Softwarequelle",
    ).strip() or "Softwarequelle"

    source_kind = prompt_choice(
        "Wo liegt die Software?",
        [
            ("1", "Lokaler Ordner auf dem Controller"),
            ("2", "Windows-Freigabe / UNC"),
        ],
        "2" if str(source.get("kind", "") or "").lower() == "smb" else "1",
    )
    source["kind"] = "smb" if source_kind == "2" else "local"

    if source["kind"] == "smb":
        while True:
            unc_root = prompt(
                "UNC-Wurzel (z. B. \\\\server\\freigabe)",
                str(source.get("unc_root", "") or "").strip(),
            ).strip().rstrip("\\/")
            try:
                share, _prefix_path = _mavi_unc_mount_parts(unc_root)
            except ValueError as exc:
                print(f"! {exc}")
                continue
            break

        share_parts = [part for part in share[2:].split("/") if part]
        mount_path = (
            project
            / "software-sources"
            / slugify(share_parts[0])
            / slugify(share_parts[1])
        )
        source_root = str(mount_path)
        source["local_root"] = source_root
        source["unc_root"] = unc_root

        identity = config.get("identity", {}) or {}
        default_mount_user = (
            str(source.get("mount_user", "") or "").strip()
            or str(identity.get("ansible_user", "") or "").strip()
        )
        mount_user_label = (
            "SMB-Benutzer (DOMAIN\\Benutzer; 'gast' = Gast)"
            if default_mount_user
            else "SMB-Benutzer (DOMAIN\\Benutzer; Enter = Gast)"
        )
        mount_user = prompt(
            mount_user_label,
            default_mount_user,
        ).strip()
        source["mount_user"] = "" if mount_user.lower() == "gast" else mount_user

        mount_host = str(source.get("mount_host", "") or "").strip()
        domain_suffix = str(
            (config.get("winrm_https", {}) or {}).get("domain_suffix", "") or ""
        ).strip()
        if not mount_host and "." not in share_parts[0] and domain_suffix:
            mount_host = f"{share_parts[0]}.{domain_suffix}"

        while True:
            mounted, mount_host = _mavi_mount_smb_source(
                unc_root,
                mount_path,
                str(source.get("mount_user", "") or ""),
                mount_host,
            )
            source["mount_host"] = (
                "" if mount_host.lower() == share_parts[0].lower() else mount_host
            )
            if mounted:
                break
            if not yes_no("SMB-Verbindung erneut versuchen?", True):
                print("Softwarequelle wurde nicht geändert.")
                return
    else:
        source_root = _mavi_prompt_source_root(
            str(source.get("local_root", "") or "").strip()
            or str(project / "software-source")
        )
        source["local_root"] = source_root
        source["unc_root"] = ""
        source["mount_user"] = ""
        source["mount_host"] = ""
        if source_root:
            try:
                Path(source_root).expanduser().mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                print(f"! Software-Ordner konnte nicht automatisch angelegt werden: {exc}")

    if yes_no(
        "Windows-Laufwerksbuchstabe für diese Quelle hinterlegen?",
        bool(_mavi_drive_label(source.get("drive"))),
    ):
        while True:
            drive = _mavi_drive_label(prompt(
                "Laufwerk (z. B. S:)",
                _mavi_drive_label(source.get("drive")) or "S:\\",
            ))
            if re.fullmatch(r"[A-Z]:\\", drive):
                source["drive"] = drive
                break
            print("! Bitte nur einen Laufwerksbuchstaben wie S: eingeben.")
    else:
        source["drive"] = ""

    mappings = dict(config.get("path_mappings", {}) or {})
    for old_key in (
        _mavi_drive_label(old_source.get("drive")),
        _mavi_drive_label(old_source.get("drive"))[:2],
        str(old_source.get("unc_root", "") or "").strip().rstrip("\\/"),
    ):
        if old_key:
            mappings.pop(old_key, None)

    drive = _mavi_drive_label(source.get("drive"))
    if drive and source_root:
        mappings[drive] = source_root
        mappings[drive[:2]] = source_root
    unc_root = str(source.get("unc_root", "") or "").strip().rstrip("\\/")
    if unc_root and source_root:
        mappings[unc_root] = source_root

    config["software_source"] = source
    config["path_mappings"] = mappings
    config["profile"]["setup_completed"] = not _mavi_profile_validation_issues(config)
    _mavi_write_config(project, config)

    print()
    print("✓ Softwarequelle gespeichert.")
    print(f"  UNC:            {unc_root or '(keine)'}")
    if source["kind"] == "local":
        print(f"  Lokaler Ordner: {source_root}")


def mavi_setup_menu(project: Path) -> None:
    """TUI-Einstieg für Grundprofil und erweiterte Softwarequellen."""
    from .environment import (
        _mavi_drive_label,
        cmd_setup,
        get_config,
    )

    while True:
        config = get_config(project)
        source = config.get("software_source", {}) or {}
        local_root = str(source.get("local_root", "") or "").strip()
        unc_root = str(source.get("unc_root", "") or "").strip()
        drive = _mavi_drive_label(source.get("drive"))
        source_kind = str(source.get("kind", "local") or "local").lower()

        print()
        print("GRUNDPROFIL & SOFTWAREQUELLE")
        print("============================")
        if source_kind == "smb":
            print(f"  Windows-Freigabe: {unc_root or '(noch nicht gesetzt)'}")
        else:
            print(f"  Lokaler Ordner:   {local_root or '(noch nicht gesetzt)'}")
        print(f"  Windows-Laufwerk: {drive or '(keins)'}")
        print()
        print("  1) Grundprofil bearbeiten")
        print("  2) Softwarequelle, UNC und Laufwerk einrichten")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_setup(argparse.Namespace(project=project, advanced=False))
            elif choice == "2":
                mavi_software_source_setup(project)
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_doctor_menu(project: Path) -> None:
    """TUI-Frontend für den read-only Doctor."""
    from .catalogs import (
        choose_host_interactive,
        prompt,
        yes_no,
    )
    from .environment import (
        _mavi_write_windows_collector,
        cmd_doctor,
    )
    from .remote import (
        _effective_host_var,
        _host_inventory_entry,
    )

    while True:
        print()
        print("DOCTOR & BEREITSCHAFT")
        print("=====================")
        print("  1) Controller, Profil und alle Voraussetzungen prüfen")
        print("  2) Einen bereits erreichbaren Windows-PC remote prüfen")
        print("  3) Offline-Collector für einen Windows-PC erzeugen")
        print("  4) Windows-Faktenbericht (JSON) importieren und auswerten")
        print("  5) Nur OpenSSH-Bereitschaft prüfen")
        print("  6) Nur WinRM/Kerberos-Bereitschaft prüfen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="all",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "2":
                host = choose_host_interactive(project)
                inv, windows, host_data = _host_inventory_entry(project, host)
                del inv
                connection = str(
                    _effective_host_var(
                        windows,
                        host_data,
                        "ansible_connection",
                        "ssh",
                    ) or "ssh"
                ).lower()
                ask_vault = yes_no(
                    "Benötigt dieses Inventory ein Ansible-Vault-Passwort?",
                    connection in {"psrp", "winrm"},
                )
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=host,
                    feature="all",
                    remote=True,
                    ask_vault=ask_vault,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "3":
                host = ""
                try:
                    host = choose_host_interactive(project)
                except SystemExit:
                    print("Kein Inventory-PC gewählt; Collector wird allgemein erzeugt.")
                path = _mavi_write_windows_collector(project, host or None)
                print()
                print("✓ Read-only Windows-Collector erstellt:")
                print(f"  {path}")
                print("  Datei auf das Ziel kopieren, als Administrator ausführen und die ausgegebene JSON-Datei zurück auf den Controller holen.")
            elif choice == "4":
                raw = prompt("Pfad zur Mavi-Doctor-Facts.json")
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="all",
                    remote=False,
                    ask_vault=True,
                    facts=Path(raw).expanduser(),
                    collector_out=None,
                ))
            elif choice == "5":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="ssh",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "6":
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=None,
                    feature="winrm",
                    remote=False,
                    ask_vault=True,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_credentials_menu(project: Path) -> None:
    """Geführter Vault-Einstieg ohne Geheimnisse an der Kommandozeile."""
    from .catalogs import prompt
    from .environment import get_config
    from .execution import (
        cmd_credentials_set,
        cmd_credentials_setup,
    )

    while True:
        config = get_config(project)
        identity = config.get("identity", {}) or {}
        configured_user = str(identity.get("ansible_user", "") or "").strip()
        configured_vault = str(identity.get("vault_path", "") or "").strip()

        print()
        print("ZUGANGSDATEN & VAULT")
        print("====================")
        print(f"  Windows-Benutzer: {configured_user or '(noch nicht gesetzt)'}")
        print(f"  Vault-Datei:      {configured_vault or '(noch nicht gesetzt)'}")
        print()
        print("  1) Windows-/Domänen-Benutzer und Kennwort verschlüsselt einrichten")
        print("  2) Installer-Geheimnis verschlüsselt anlegen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_credentials_setup(argparse.Namespace(
                    project=project,
                    ansible_user=None,
                    force=False,
                ))
            elif choice == "2":
                name = prompt(
                    "Name (muss mit vault_ oder mavi_vault_ beginnen, z. B. vault_installer_token)"
                ).strip()
                cmd_credentials_set(argparse.Namespace(
                    project=project,
                    name=name,
                    force=False,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")


def mavi_pc_menu(project: Path) -> None:
    """TUI-Flow für Inventory, Verbindung, Doctor und Client-Wartung."""
    from .catalogs import (
        choose_host_interactive,
        yes_no,
    )
    from .clients import client_menu
    from .environment import cmd_doctor
    from .execution import (
        cmd_host_add,
        cmd_host_list,
        cmd_host_remove,
        cmd_ping,
    )
    from .openssh import ssh_menu
    from .remote import (
        _effective_host_var,
        _host_inventory_entry,
    )

    while True:
        print()
        print("PCS & VERBINDUNG")
        print("================")
        print("  1) Neuen PC ins Inventory aufnehmen")
        print("  2) PCs anzeigen")
        print("  3) OpenSSH / Windows-Verbindung einrichten")
        print("  4) Verbindung testen (win_ping)")
        print("  5) Doctor für einen PC ausführen")
        print("  6) Windows-Client optimieren / Programme bereinigen")
        print("  7) PC aus der Liste entfernen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_host_add(argparse.Namespace(
                    project=project,
                    name=None,
                    ip=None,
                    ansible_user=None,
                    local_admin=None,
                    connection=None,
                    ssh_key=None,
                    ssh_port=None,
                ))
            elif choice == "2":
                cmd_host_list(argparse.Namespace(project=project))
            elif choice == "3":
                ssh_menu(project)
            elif choice == "4":
                host = choose_host_interactive(project)
                cmd_ping(argparse.Namespace(project=project, host=host))
            elif choice == "5":
                host = choose_host_interactive(project)
                inv, windows, host_data = _host_inventory_entry(project, host)
                del inv
                connection = str(
                    _effective_host_var(
                        windows,
                        host_data,
                        "ansible_connection",
                        "ssh",
                    ) or "ssh"
                ).lower()
                remote = yes_no(
                    "Read-only Fakten direkt per Ansible vom PC abrufen?",
                    True,
                )
                ask_vault = False
                if remote:
                    ask_vault = yes_no(
                        "Benötigt dieses Inventory ein Ansible-Vault-Passwort?",
                        connection in {"psrp", "winrm"},
                    )
                cmd_doctor(argparse.Namespace(
                    project=project,
                    host=host,
                    feature="all",
                    remote=remote,
                    ask_vault=ask_vault,
                    facts=None,
                    collector_out=None,
                ))
            elif choice == "6":
                client_menu(project)
            elif choice == "7":
                host = choose_host_interactive(project)
                cmd_host_remove(argparse.Namespace(
                    project=project,
                    name=host,
                    yes=False,
                ))
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except KeyboardInterrupt:
            print("\nAbgebrochen.")
        except EOFError:
            print()
            return
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")
