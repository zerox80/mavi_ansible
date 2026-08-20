# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""Interaktive Menüs, Argumentparser und Programmeinstieg."""

from __future__ import annotations

from ._dependencies import (
    Path,
    argparse,
    re,
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

    while True:
        default_catalog = get_default_catalog_name(project)

        print(
            "\n"
            "╔══════════════════════════════════════╗\n"
            "║   MAVI PROVISIONER — VOLLVERSION      ║\n"
            "╚══════════════════════════════════════╝\n"
            f" Standardkatalog: {default_catalog}\n"
            "\n"
            "  1) Normale Software hinzufügen\n"
            "  2) Microsoft-Produkt hinzufügen\n"
            "  3) Software-Katalog anzeigen\n"
            "  4) Software installieren\n"
            "  5) Kataloge verwalten\n"
            "  6) Neuen PC hinzufügen\n"
            "  7) PCs anzeigen\n"
            "  8) Verbindung testen (win_ping)\n"
            "  9) Dateien initialisieren / prüfen\n"
            " 10) Drucker verwalten / installieren\n"
            " 11) OpenSSH / Windows-Verbindung verwalten\n"
            " 12) Optionen / TUI anpassen\n"
            " 13) WinGet-Software suchen / hinzufügen\n"
            " 14) Microsoft Store-App suchen / hinzufügen\n"
            " 15) Windows-Client optimieren / Programme bereinigen\n"
            "  0) Beenden\n"
        )

        choice = input("> ").strip()

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


def build_parser() -> argparse.ArgumentParser:
    from .catalogs import (
        cmd_catalog_copy,
        cmd_catalog_create,
        cmd_catalog_list,
        cmd_catalog_set_default,
        cmd_init,
        cmd_params_backup,
        cmd_params_list,
        cmd_params_restore,
        cmd_software_edit,
    )
    from .clients import (
        _client_uninstall_timeout_minutes,
        _monitor_timeout_minutes,
        cmd_client_optimize,
        cmd_client_uninstall,
    )
    from .environment import (
        cmd_doctor,
        cmd_doctor_collector,
        cmd_setup,
    )
    from .execution import (
        cmd_credentials_set,
        cmd_credentials_setup,
        cmd_host_add,
        cmd_host_list,
        cmd_install,
        cmd_ping,
    )
    from .openssh import (
        cmd_ssh_guide,
        cmd_ssh_keygen,
        cmd_ssh_remove_keys,
        cmd_ssh_server_setup,
        cmd_ssh_setup_check,
        cmd_ssh_status,
        cmd_ssh_use,
        cmd_ssh_use_psrp,
        cmd_ssh_winrm_https,
        cmd_ssh_winrm_reset,
    )
    from .printers import (
        cmd_printer_add,
        cmd_printer_install,
        cmd_printer_list,
        cmd_printer_remove,
        cmd_printer_show,
    )
    from .reports import (
        REPORT_HTTP_DEFAULT_TTL,
        REPORT_HTTP_PORT,
        cmd_internal_report_serve,
        cmd_software_list,
        cmd_software_remove,
        cmd_software_show,
    )
    from .settings import (
        DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
        DEFAULT_PROJECT,
        VERSION,
    )
    from .software import (
        cmd_catalog_repair,
        cmd_microsoft_add,
        cmd_software_add,
        cmd_store_add,
        cmd_winget_add,
    )

    parser = argparse.ArgumentParser(
        prog="mavi-provisioner",
        description=(
            "Interaktives Mavi-Frontend für Ansible-Windows-Provisioning "
            "mit mehreren Software-Katalogen. "
            "Ohne Unterbefehl startet das Menü."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Beispiele:
  mavi-provisioner
  mavi-provisioner setup
  mavi-provisioner doctor
  mavi-provisioner doctor --format json
  mavi-provisioner doctor PC-001 --remote
  mavi-provisioner doctor-collector --out ./Mavi-Doctor-Collector.ps1

  # Kataloge
  mavi-provisioner catalog list
  mavi-provisioner catalog create buero
  mavi-provisioner catalog create technik --copy-from default
  mavi-provisioner catalog set-default buero
  mavi-provisioner catalog copy default buero chrome pascom
  mavi-provisioner catalog copy default test --all --create-destination
  mavi-provisioner catalog repair --catalog default
  mavi-provisioner catalog repair --all

  # Software
  mavi-provisioner software add "S:\Tools\example-installer.exe"
  mavi-provisioner software add "S:\Tools\remote-support.msi" --catalog technik
  mavi-provisioner software list --serve-report
  mavi-provisioner winget add --query vlc
  mavi-provisioner store add --query "Microsoft To Do"
  mavi-provisioner software list
  mavi-provisioner software list --catalog buero
  mavi-provisioner software show pascom --catalog buero
  mavi-provisioner software edit pascom --catalog buero
  mavi-provisioner software remove pascom --catalog buero

  # WinGet
  mavi-provisioner winget add --query vlc
  mavi-provisioner winget add --id VideoLAN.VLC --scope machine

  # Parameter-Backups, unabhängig von der Installer-Version
  mavi-provisioner params backup --catalog default --all
  mavi-provisioner params backup --catalog default pascom citrixworkspaceapp_x64
  mavi-provisioner params list
  mavi-provisioner params restore pascom --catalog default
  mavi-provisioner params restore --catalog default --all

  # Microsoft Office / Project / Visio
  # Empfohlener Weg: expliziter Microsoft-Assistent.
  mavi-provisioner microsoft add
  mavi-provisioner microsoft add --catalog buero
  mavi-provisioner microsoft add --catalog buero --odt "S:\Microsoft\ODT\setup.exe"

  # Falls man versehentlich OfficeSetup.exe über "software add" auswählt,
  # bietet das Tool den Wechsel zum Microsoft-Assistenten an.

  # Installation
  mavi-provisioner install PC-001 --all
  mavi-provisioner install PC-001 --all --catalog buero
  mavi-provisioner install PC-001 remote_support --status-interval 5
  # Bootstrapper unbeaufsichtigt: context: machine_detached
  # Sichtbare Admin-GUI: context: machine_interactive
  # USER zuerst; sichtbarer UAC-Fallback nur bei benötigter Elevation: context: user_uac
  # Sichtbare Benutzer-GUI: context: user_interactive
  mavi-provisioner install PC-001 remote_support --no-live-probe
  mavi-provisioner install PC-001 browser remote_support --catalog default

  # TCP/IP-Drucker
  mavi-provisioner printer add --name "Büro 1. OG" --ip 10.10.20.50 --driver-dir "S:\Drucker\Treiber"
  mavi-provisioner printer list
  mavi-provisioner printer install PC-001 buero_1og
  mavi-provisioner printer install PC-001 --all

  # PCs
  mavi-provisioner host add PC-001 10.10.20.101
  mavi-provisioner host list
  mavi-provisioner ping PC-001

  # Windows-Client optimieren / klassische Programme bereinigen
  mavi-provisioner client optimize PC-001 --disable-fast-startup
  mavi-provisioner client optimize PC-001 --monitor-timeout-ac 15 --monitor-timeout-dc 5
  mavi-provisioner client uninstall PC-001
  mavi-provisioner client uninstall PC-001 --m365 --timeout-minutes 60

  # OpenSSH-Vollautomatik: nginx, CA, HTTPS und Windows-Starter
  mavi-provisioner ssh server-setup
  mavi-provisioner ssh auto PC-001
  mavi-provisioner ssh use PC-001
  mavi-provisioner ssh status PC-001
  mavi-provisioner ssh psrp PC-001
  mavi-provisioner ssh winrm-reset PC-001
  mavi-provisioner ssh winrm-reset PC-001 --disable-openssh

Ohne --catalog wird immer der aktuell gesetzte Standardkatalog verwendet. Im interaktiven Menü können PCs, Kataloge und Programme bequem per Nummer gewählt werden. Unter 'Kataloge verwalten' lassen sich bestehende Programme schnell bearbeiten, anzeigen, kopieren und entfernen. Strg+2 wechselt in unterstützten Programmauswahlen direkt in den Mehrfachmodus.
""",
    )

    parser.add_argument(
        "--project",
        type=Path,
        default=DEFAULT_PROJECT,
        help="Ansible-Laufzeitprojekt (Standard: ~/.local/share/mavi-provisioner)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    sub = parser.add_subparsers(dest="command")

    # Nur für den von ``software list --serve-report`` gestarteten,
    # kurzlebigen Kindprozess. Kein Verzeichnis wird freigegeben.
    p_report_serve = sub.add_parser(
        "_report-serve",
        help=argparse.SUPPRESS,
    )
    p_report_serve.add_argument("--file", type=Path, required=True)
    p_report_serve.add_argument("--bind", required=True)
    p_report_serve.add_argument("--port", type=int, required=True)
    p_report_serve.add_argument("--ttl", type=int, required=True)
    p_report_serve.set_defaults(func=cmd_internal_report_serve)

    p_init = sub.add_parser(
        "init",
        help="Kataloge und generische Playbooks anlegen/aktualisieren",
    )
    p_init.set_defaults(func=cmd_init)

    p_setup = sub.add_parser(
        "setup",
        help="Interaktives, nicht geheimes Umgebungsprofil einrichten",
    )
    p_setup.add_argument(
        "--advanced",
        action="store_true",
        help="Zusätzlich SMB-/Laufwerks- und Bootstrap-Details abfragen",
    )
    p_setup.set_defaults(func=cmd_setup)

    p_credentials = sub.add_parser(
        "credentials",
        help="Credentials ausschließlich verschlüsselt in Ansible Vault verwalten",
    )
    credentials_sub = p_credentials.add_subparsers(
        dest="credentials_command",
        required=True,
    )
    p_credentials_setup = credentials_sub.add_parser(
        "setup",
        help="Zentralen Windows-Ansible-Benutzer und verschlüsseltes Kennwort einrichten",
    )
    p_credentials_setup.add_argument(
        "--ansible-user",
        help=r"Nicht geheimer Benutzer, z. B. EXAMPLE\Provisioning-Admin",
    )
    p_credentials_setup.add_argument(
        "--force",
        action="store_true",
        help="Vorhandenen verschlüsselten ansible_password-Wert ersetzen",
    )
    p_credentials_setup.set_defaults(func=cmd_credentials_setup)

    p_credentials_set = credentials_sub.add_parser(
        "set",
        help="Verschlüsseltes Installer-Geheimnis als vault_*-Variable speichern",
    )
    p_credentials_set.add_argument("name", help="Variablenname mit vault_ oder mavi_vault_ Präfix")
    p_credentials_set.add_argument(
        "--force",
        action="store_true",
        help="Vorhandenen verschlüsselten Wert ersetzen",
    )
    p_credentials_set.set_defaults(func=cmd_credentials_set)

    p_doctor = sub.add_parser(
        "doctor",
        help="Read-only Voraussetzungen und optional Windows-Fakten prüfen",
    )
    p_doctor.add_argument(
        "host",
        nargs="?",
        help="Optionaler Inventory-Hostname für Ziel-PC-Prüfungen",
    )
    p_doctor.add_argument(
        "--feature",
        choices=("all", "ssh", "winrm", "software"),
        default="all",
        help="Prüfbereich (Standard: all)",
    )
    p_doctor.add_argument(
        "--remote",
        action="store_true",
        help="Read-only Fakten temporär per Ansible vom Ziel-PC abrufen",
    )
    p_doctor.add_argument(
        "--no-ask-vault",
        dest="ask_vault",
        action="store_false",
        help="Beim Remote-Doctor kein Vault-Passwort abfragen",
    )
    p_doctor.add_argument(
        "--facts",
        type=Path,
        help="Lokale Mavi-Doctor-Facts.json importieren",
    )
    p_doctor.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "json"),
        default="text",
        help="Ausgabeformat; JSON eignet sich für Automatisierung",
    )
    p_doctor.set_defaults(func=cmd_doctor, ask_vault=True)

    p_doctor_collector = sub.add_parser(
        "doctor-collector",
        help="Offline-Collector explizit als PowerShell-Datei erzeugen",
    )
    p_doctor_collector.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Zielpfad der zu erzeugenden PowerShell-Datei",
    )
    p_doctor_collector.set_defaults(func=cmd_doctor_collector)

    # --------------------------
    # Catalog
    # --------------------------
    p_catalog = sub.add_parser(
        "catalog",
        help="Software-Kataloge erstellen, auswählen und kopieren",
    )
    cat_sub = p_catalog.add_subparsers(
        dest="catalog_command",
        required=True,
    )

    p_cl = cat_sub.add_parser(
        "list",
        help="Alle Kataloge und den Standardkatalog anzeigen",
    )
    p_cl.set_defaults(func=cmd_catalog_list)

    p_cc = cat_sub.add_parser(
        "create",
        help="Neuen Katalog erstellen",
    )
    p_cc.add_argument("name", help="Name des neuen Katalogs")
    p_cc.add_argument(
        "--copy-from",
        help="Neuen Katalog direkt als Kopie eines bestehenden Katalogs anlegen",
    )
    p_cc.add_argument(
        "--set-default",
        action="store_true",
        help="Den neuen Katalog direkt zum Standard machen",
    )
    p_cc.set_defaults(func=cmd_catalog_create)

    p_csd = cat_sub.add_parser(
        "set-default",
        help="Standardkatalog festlegen",
    )
    p_csd.add_argument("name", help="Vorhandener Katalog")
    p_csd.set_defaults(func=cmd_catalog_set_default)

    p_cp = cat_sub.add_parser(
        "copy",
        help="Software von einem Katalog in einen anderen kopieren",
    )
    p_cp.add_argument("source", help="Quellkatalog")
    p_cp.add_argument("destination", help="Zielkatalog")
    p_cp.add_argument(
        "software",
        nargs="*",
        help="Software-Schlüssel; ohne Angabe wird interaktiv gefragt",
    )
    p_cp.add_argument(
        "--all",
        action="store_true",
        help="Alle Softwareeinträge kopieren",
    )
    p_cp.add_argument(
        "--overwrite",
        action="store_true",
        help="Abweichende vorhandene Einträge im Ziel überschreiben",
    )
    p_cp.add_argument(
        "--create-destination",
        action="store_true",
        help="Zielkatalog automatisch anlegen, falls er fehlt",
    )
    p_cp.set_defaults(func=cmd_catalog_copy)

    p_cr = cat_sub.add_parser(
        "repair",
        help="Rohe Scan-/Jinja-Daten aus Katalogeinträgen entfernen",
    )
    p_cr.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_cr.add_argument(
        "--all",
        action="store_true",
        help="Alle Kataloge reparieren",
    )
    p_cr.set_defaults(func=cmd_catalog_repair)

    # --------------------------
    # Microsoft Office / Project / Visio
    # --------------------------
    p_ms = sub.add_parser(
        "microsoft",
        help="Microsoft Office, Project oder Visio über ODT/XML verwalten",
    )
    ms_sub = p_ms.add_subparsers(
        dest="microsoft_command",
        required=True,
    )

    p_ms_add = ms_sub.add_parser(
        "add",
        help="Microsoft-Produkt interaktiv zu einem Katalog hinzufügen",
    )
    p_ms_add.add_argument(
        "--catalog",
        help="Zielkatalog; ohne Angabe wird der Standard vorgeschlagen",
    )
    p_ms_add.add_argument(
        "--name",
        help="Anzeigename im Katalog",
    )
    p_ms_add.add_argument(
        "--key",
        help="Katalog-Schlüssel",
    )
    p_ms_add.add_argument(
        "--odt",
        help="Optionaler Pfad zur ODT setup.exe; sonst wird interaktiv gefragt",
    )
    p_ms_add.set_defaults(func=cmd_microsoft_add)

    # --------------------------
    # Software
    # --------------------------
    p_sw = sub.add_parser(
        "software",
        help="Software in Katalogen verwalten",
    )
    sw_sub = p_sw.add_subparsers(
        dest="software_command",
        required=True,
    )


    p_add = sw_sub.add_parser(
        "add",
        help="MSI/EXE mit festen oder manuell gesetzten Parametern hinzufügen",
    )
    p_add.add_argument("path", nargs="?", help="Installer-Pfad")
    p_add.add_argument("--name", help="Anzeigename")
    p_add.add_argument("--key", help="Katalog-Schlüssel")
    p_add.add_argument(
        "--catalog",
        help="Zielkatalog; ohne Angabe wird der Standard vorgeschlagen",
    )
    p_add.add_argument(
        "--allow-unsafe-missing-sha256",
        action="store_true",
        help=(
            "Explizite Legacy-Ausnahme: lokalen Installer ohne SHA-256 binden "
            "(unsicher; Standard ist fail-closed)"
        ),
    )
    p_add.set_defaults(func=cmd_software_add)

    p_list = sw_sub.add_parser(
        "list",
        help="Software eines Katalogs anzeigen",
    )
    p_list.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_list.add_argument(
        "--serve-report",
        action="store_true",
        help=(
            "HTML-Bericht kurzzeitig per tokenisiertem HTTP bereitstellen "
            "(Standard: nur lokale Datei)"
        ),
    )
    p_list.add_argument(
        "--report-bind",
        default="loopback",
        metavar="LOOPBACK|LAN|IP",
        help=(
            "Bind für --serve-report; Standard: loopback. LAN/private IP "
            "ist ein bewusstes, unverschlüsseltes Opt-in"
        ),
    )
    p_list.add_argument(
        "--report-port",
        type=int,
        default=REPORT_HTTP_PORT,
        help=f"TCP-Port des kurzzeitigen Reportservers (Standard: {REPORT_HTTP_PORT})",
    )
    p_list.add_argument(
        "--report-ttl",
        type=int,
        default=REPORT_HTTP_DEFAULT_TTL,
        help=(
            "Lebensdauer in Sekunden, begrenzt auf 30–3600 "
            f"(Standard: {REPORT_HTTP_DEFAULT_TTL})"
        ),
    )
    p_list.set_defaults(func=cmd_software_list)

    p_edit = sw_sub.add_parser(
        "edit",
        help="Bestehendes Paket interaktiv schnell bearbeiten",
    )
    p_edit.add_argument(
        "key",
        nargs="?",
        help="Software-Schlüssel; ohne Angabe interaktive Auswahl",
    )
    p_edit.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_edit.set_defaults(func=cmd_software_edit)

    p_show = sw_sub.add_parser(
        "show",
        help="Ein Paket vollständig anzeigen",
    )
    p_show.add_argument("key")
    p_show.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_show.set_defaults(func=cmd_software_show)

    p_rm = sw_sub.add_parser(
        "remove",
        help="Paket aus einem Katalog entfernen",
    )
    p_rm.add_argument("key")
    p_rm.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_rm.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Ohne Rückfrage löschen",
    )
    p_rm.set_defaults(func=cmd_software_remove)

    # --------------------------
    # WinGet
    # --------------------------
    p_winget = sub.add_parser(
        "winget",
        help="WinGet-Pakete suchen und zum Software-Katalog hinzufügen",
    )
    winget_sub = p_winget.add_subparsers(
        dest="winget_command",
        required=True,
    )

    p_wa = winget_sub.add_parser(
        "add",
        help="WinGet-Paket suchen/prüfen und zum Katalog hinzufügen",
    )
    p_wa.add_argument("--host", help="Referenz-PC für die WinGet-Suche")
    p_wa.add_argument("--query", help="Suchbegriff, z. B. vlc")
    p_wa.add_argument("--id", dest="package_id", help="Exakte WinGet-Paket-ID, z. B. VideoLAN.VLC")
    p_wa.add_argument("--source", default="winget", help="WinGet-Quelle (Standard: winget)")
    p_wa.add_argument("--scope", choices=["machine", "user"], help="Installationsbereich")
    p_wa.add_argument("--version", help="Optional feste Paketversion; Standard: aktuellste")
    p_wa.add_argument("--catalog", help="Zielkatalog")
    p_wa.add_argument("--name", help="Anzeigename")
    p_wa.add_argument("--key", help="Katalog-Schlüssel")
    p_wa.set_defaults(func=cmd_winget_add)

    # --------------------------
    # Microsoft Store (über WinGet msstore)
    # --------------------------
    p_store = sub.add_parser(
        "store",
        help="Microsoft-Store-Apps über die WinGet-Quelle msstore verwalten",
    )
    store_sub = p_store.add_subparsers(
        dest="store_command",
        required=True,
    )

    p_sa = store_sub.add_parser(
        "add",
        help="Microsoft-Store-App suchen und als USER-Paket zum Katalog hinzufügen",
    )
    p_sa.add_argument("--host", help="Referenz-PC für die Microsoft-Store-Suche")
    p_sa.add_argument("--query", help="Suchbegriff, z. B. Microsoft To Do")
    p_sa.add_argument("--id", dest="package_id", help="Exakte Microsoft-Store-ID")
    p_sa.add_argument("--catalog", help="Zielkatalog")
    p_sa.add_argument("--name", help="Anzeigename")
    p_sa.add_argument("--key", help="Katalog-Schlüssel")
    p_sa.set_defaults(func=cmd_store_add, source="msstore", scope="user", version=None)


    # --------------------------
    # Parameter-Backups
    # --------------------------
    p_params = sub.add_parser(
        "params",
        help="Installer-Parameter unabhängig vom Installer sichern/wiederherstellen",
    )
    params_sub = p_params.add_subparsers(
        dest="params_command",
        required=True,
    )

    p_pb = params_sub.add_parser(
        "backup",
        help="Flags/Kontext/Erkennungspfad aus einem Katalog sichern",
    )
    p_pb.add_argument(
        "software",
        nargs="*",
        help="Software-Schlüssel; ohne Angabe werden alle gesichert",
    )
    p_pb.add_argument(
        "--catalog",
        help="Quellkatalog; Standard: Default-Katalog",
    )
    p_pb.add_argument(
        "--all",
        action="store_true",
        help="Alle Programme im Katalog sichern",
    )
    p_pb.set_defaults(func=cmd_params_backup)

    p_pl = params_sub.add_parser(
        "list",
        help="Gesicherte Parameter-Profile anzeigen",
    )
    p_pl.set_defaults(func=cmd_params_list)

    p_pr = params_sub.add_parser(
        "restore",
        help="Gesicherte Parameter auf aktuellen Installer-Eintrag anwenden",
    )
    p_pr.add_argument(
        "profile",
        nargs="?",
        help="Profil/Software-Schlüssel; ohne Angabe interaktive Auswahl",
    )
    p_pr.add_argument(
        "--catalog",
        help="Zielkatalog; Standard: Default-Katalog",
    )
    p_pr.add_argument(
        "--target-key",
        help="Auf abweichenden Software-Schlüssel anwenden",
    )
    p_pr.add_argument(
        "--all",
        action="store_true",
        help="Alle passenden Profile auf den Katalog anwenden",
    )
    p_pr.add_argument(
        "--force",
        action="store_true",
        help="Auch bei geändertem Installer-Typ wiederherstellen",
    )
    p_pr.set_defaults(func=cmd_params_restore)

    # --------------------------
    # Printer
    # --------------------------
    p_printer = sub.add_parser(
        "printer",
        help="TCP/IP-Drucker und Treiberordner verwalten/installieren",
    )
    printer_sub = p_printer.add_subparsers(
        dest="printer_command",
        required=True,
    )

    p_pa = printer_sub.add_parser(
        "add",
        help="TCP/IP-Drucker samt Treiberordner zum Druckerkatalog hinzufügen",
    )
    p_pa.add_argument("--name", help="Windows-Druckername")
    p_pa.add_argument("--key", help="Drucker-Schlüssel im Katalog")
    p_pa.add_argument("--ip", help="IPv4-Adresse des Druckers")
    p_pa.add_argument(
        "--driver-dir",
        help=(
            "Vollständig entpackter Druckertreiber-Ordner; Mavi sucht "
            "die passende INF automatisch"
        ),
    )
    p_pa.add_argument(
        "--driver-inf",
        help="Direkter INF-Pfad (Legacy/Expertenmodus)",
    )
    p_pa.add_argument(
        "--driver-name",
        help="Exakter Windows-Druckertreibername; sonst INF-Auswahl",
    )
    p_pa.add_argument(
        "--port-name",
        help="TCP/IP-Portname; Standard: IP_<Adresse>",
    )
    p_pa.add_argument(
        "--port-number",
        type=int,
        default=9100,
        help="RAW-TCP-Port (Standard: 9100)",
    )
    p_pa.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Vorhandenen Katalogeintrag ohne Rückfrage überschreiben",
    )
    p_pa.set_defaults(func=cmd_printer_add)

    p_plist = printer_sub.add_parser(
        "list",
        help="Druckerkatalog anzeigen",
    )
    p_plist.set_defaults(func=cmd_printer_list)

    p_pshow = printer_sub.add_parser(
        "show",
        help="Druckereintrag vollständig anzeigen",
    )
    p_pshow.add_argument("key")
    p_pshow.set_defaults(func=cmd_printer_show)

    p_premove = printer_sub.add_parser(
        "remove",
        help="Drucker nur aus dem Katalog entfernen",
    )
    p_premove.add_argument("key")
    p_premove.add_argument("-y", "--yes", action="store_true")
    p_premove.set_defaults(func=cmd_printer_remove)

    p_pinstall = printer_sub.add_parser(
        "install",
        help="Einen oder mehrere TCP/IP-Drucker systemweit installieren",
    )
    p_pinstall.add_argument("host", help="Inventory-Hostname")
    p_pinstall.add_argument(
        "printers",
        nargs="*",
        help="Drucker-Schlüssel",
    )
    p_pinstall.add_argument(
        "--all",
        action="store_true",
        help="Alle Drucker aus dem Druckerkatalog installieren",
    )
    p_pinstall.set_defaults(func=cmd_printer_install)

    # --------------------------
    # Host
    # --------------------------
    p_host = sub.add_parser(
        "host",
        help="Windows-PCs im Inventory verwalten",
    )
    host_sub = p_host.add_subparsers(
        dest="host_command",
        required=True,
    )

    p_ha = host_sub.add_parser(
        "add",
        help="Neuen Windows-PC hinzufügen",
    )
    p_ha.add_argument("name", nargs="?")
    p_ha.add_argument("ip", nargs="?")
    p_ha.add_argument(
        "--ansible-user",
        help=(
            r"Optionaler host-spezifischer Benutzer, z. B. EXAMPLE\Admin. "
            "Ohne Angabe wird der zentrale Domänen-/Ansible-User geerbt."
        ),
    )
    p_ha.add_argument(
        "--local-admin",
        help=(
            "Veraltet: lokaler Admin-Name. Nur für Rückwärtskompatibilität; "
            "Standard ist jetzt der zentrale Domänen-User."
        ),
    )
    p_ha.add_argument(
        "--connection",
        choices=["inherit", "psrp", "ssh"],
        default="inherit",
        help="Verbindung für diesen Host; Standard: zentrale Inventory-Einstellung erben",
    )
    p_ha.add_argument(
        "--ssh-key",
        help="Privater SSH-Key für --connection ssh; Standard: Projekt/.ssh/mavi_windows_ed25519",
    )
    p_ha.add_argument(
        "--ssh-port",
        type=int,
        help="SSH-Port für --connection ssh; Standard: 22",
    )
    p_ha.set_defaults(func=cmd_host_add)

    p_hl = host_sub.add_parser(
        "list",
        help="Windows-PCs anzeigen",
    )
    p_hl.set_defaults(func=cmd_host_list)

    # --------------------------
    # OpenSSH / Windows
    # --------------------------
    p_ssh = sub.add_parser(
        "ssh",
        help="OpenSSH für Windows-Hosts einrichten und verwalten",
    )
    ssh_sub = p_ssh.add_subparsers(
        dest="ssh_command",
        required=True,
    )

    p_sk = ssh_sub.add_parser(
        "keygen",
        help="Dedizierten Mavi-Ed25519-Key auf dem Ansible-Server anlegen",
    )
    p_sk.add_argument("--key", help="Alternativer privater Key-Pfad")
    p_sk.add_argument("-y", "--yes", action="store_true", help="Key ohne Rückfrage erzeugen")
    p_sk.set_defaults(func=cmd_ssh_keygen)

    p_server_setup = ssh_sub.add_parser(
        "server-setup",
        help="nginx, private Mavi-CA, SAN-Zertifikat, Webroot und Firewall automatisch einrichten",
    )
    p_server_setup.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="für den internen sudo-Neustart; die Einrichtung bleibt vollautomatisch",
    )
    p_server_setup.set_defaults(func=cmd_ssh_server_setup)

    p_sg = ssh_sub.add_parser(
        "guide",
        aliases=["auto"],
        help="komplette OpenSSH-Vollautomatik vorbereiten und den Laptop-Starter ablegen",
    )
    p_sg.add_argument("host", nargs="?", help="Optionaler Inventory-Host für IP/User-Hinweise")
    p_sg.add_argument("--key", help="Alternativer privater Key-Pfad; .pub wird daneben erwartet")
    p_sg.add_argument("--msi", help="Optionaler Windows-/UNC-Pfad zur OpenSSH-Win64-MSI; sonst Windows Capability/FoD")
    p_sg.set_defaults(func=cmd_ssh_guide)

    p_sc = ssh_sub.add_parser(
        "setup-check",
        help="nginx/HTTPS/Zertifikat automatisch einrichten und anschließend diagnostizieren",
    )
    p_sc.add_argument(
        "--msi",
        help="Optionale OpenSSH-MSI für SHA-256- und Authenticode-Diagnose",
    )
    p_sc.set_defaults(func=cmd_ssh_setup_check)

    p_su = ssh_sub.add_parser(
        "use",
        help="Inventory-Host auf OpenSSH + PowerShell + SSH-Key umstellen",
    )
    p_su.add_argument("host", help="Inventory-Hostname")
    p_su.add_argument("--key", help="Alternativer privater SSH-Key")
    p_su.add_argument("--port", type=int, help="SSH-Port; Standard: 22")
    p_su.add_argument("-y", "--yes", action="store_true", help="gescannten SSH-Host-Key ohne Rückfrage übernehmen")
    p_su.set_defaults(func=cmd_ssh_use)

    p_sp = ssh_sub.add_parser(
        "psrp",
        help="Inventory-Host auf zuvor geprüftes PSRP/WinRM HTTPS + Kerberos umstellen",
    )
    p_sp.add_argument("host", help="Inventory-Hostname")
    p_sp.set_defaults(func=cmd_ssh_use_psrp)

    p_swh = ssh_sub.add_parser(
        "winrm-https",
        aliases=["winrm-kerberos"],
        help="WinRM über bestehendes OpenSSH auf HTTPS + Kerberos-only härten und HTTP/5985 entfernen",
    )
    p_swh.add_argument("host", help="Inventory-Hostname mit eingerichteter OpenSSH-Key-Verbindung")
    p_swh.set_defaults(func=cmd_ssh_winrm_https)

    p_swr = ssh_sub.add_parser(
        "winrm-reset",
        aliases=["winrm-disable"],
        help="WinRM/Kerberos über OpenSSH vollständig auf Stand 0 zurücksetzen",
    )
    p_swr.add_argument("host", help="Inventory-Hostname; OpenSSH muss auf Windows erreichbar sein")
    p_swr.add_argument("--key", help="Alternativer privater SSH-Key für den Rückbau")
    p_swr.add_argument("--port", type=int, help="SSH-Port für den Rückbau; Standard aus der Konfiguration")
    p_swr.add_argument(
        "--disable-openssh",
        action="store_true",
        help="nach dem WinRM-Rückbau auch Mavi-SSH-Key/Firewall entfernen und sshd deaktivieren",
    )
    p_swr.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Stand-0-Rückbau ohne Bestätigungsfrage starten",
    )
    p_swr.set_defaults(func=cmd_ssh_winrm_reset)

    p_ss = ssh_sub.add_parser(
        "status",
        help="Lokalen SSH-/Ansible-Status und optional einen Host anzeigen",
    )
    p_ss.add_argument("host", nargs="?", help="Optionaler Inventory-Hostname")
    p_ss.add_argument("--key", help="Alternativer privater SSH-Key")
    p_ss.set_defaults(func=cmd_ssh_status)

    p_sr = ssh_sub.add_parser(
        "remove-keys",
        help="Mavi-Public-Key(s) von einem Windows-PC entfernen",
    )
    p_sr.add_argument("host", help="Inventory-Hostname")
    p_sr.add_argument("-y", "--yes", action="store_true", help="ohne Rückfrage entfernen")
    p_sr.set_defaults(func=cmd_ssh_remove_keys)

    # --------------------------
    # Windows-Client-Optimierung
    # --------------------------
    p_client = sub.add_parser(
        "client",
        help="Windows-Clients optimieren und klassische Programme bereinigen",
    )
    client_sub = p_client.add_subparsers(
        dest="client_command",
        required=True,
    )

    p_client_optimize = client_sub.add_parser(
        "optimize",
        help="Schnellstart und Bildschirmtimeout verwalten",
    )
    p_client_optimize.add_argument("host", help="Inventory-Hostname")
    p_client_optimize.add_argument(
        "--disable-fast-startup",
        action="store_true",
        help="Windows-Schnellstart deaktivieren; Ruhezustand beibehalten",
    )
    p_client_optimize.add_argument(
        "--monitor-timeout-ac",
        type=_monitor_timeout_minutes,
        metavar="MIN",
        default=None,
        help="Bildschirmtimeout im Netzbetrieb; 0 = Nie",
    )
    p_client_optimize.add_argument(
        "--monitor-timeout-dc",
        type=_monitor_timeout_minutes,
        metavar="MIN",
        default=None,
        help="Bildschirmtimeout im Akkubetrieb; 0 = Nie",
    )
    p_client_optimize.set_defaults(func=cmd_client_optimize)

    p_client_uninstall = client_sub.add_parser(
        "uninstall",
        help="Klassische Programme suchen, mehrfach auswählen und seriell deinstallieren",
    )
    p_client_uninstall.add_argument("host", help="Inventory-Hostname")
    p_client_uninstall.add_argument(
        "--m365",
        action="store_true",
        help="Erkannte Microsoft-365-Einträge in der Auswahl vorab markieren",
    )
    p_client_uninstall.add_argument(
        "--timeout-minutes",
        type=_client_uninstall_timeout_minutes,
        default=DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES,
        metavar="MIN",
        help=(
            "Zeitlimit pro Programm; Standard: "
            f"{DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES} Minuten"
        ),
    )
    p_client_uninstall.set_defaults(func=cmd_client_uninstall)

    p_ping = sub.add_parser(
        "ping",
        help="Ansible win_ping über die konfigurierte Verbindung ausführen",
    )
    p_ping.add_argument("host")
    p_ping.set_defaults(func=cmd_ping)

    # --------------------------
    # Install
    # --------------------------
    p_install = sub.add_parser(
        "install",
        help="Software aus einem Katalog installieren",
    )
    p_install.add_argument(
        "host",
        help="Inventory-Hostname",
    )
    p_install.add_argument(
        "software",
        nargs="*",
        help="Ein oder mehrere Software-Schlüssel",
    )
    p_install.add_argument(
        "--all",
        action="store_true",
        help="Alle Pakete aus dem gewählten Katalog installieren",
    )
    p_install.add_argument(
        "--catalog",
        help="Katalog; Standard: gesetzter Default-Katalog",
    )
    p_install.add_argument(
        "--target-user",
        help=r"Benutzer für interaktive Kontexte, z. B. EXAMPLE\Max.Mustermann",
    )
    p_install.add_argument(
        "--check",
        action="store_true",
        help="Ansible Check Mode",
    )
    p_install.add_argument(
        "--status-interval",
        type=float,
        default=10.0,
        help=(
            "Sekunden zwischen Mavi-Live-Meldungen während ein Installer "
            "läuft (Standard: 10; 0 = aus)"
        ),
    )
    p_install.add_argument(
        "--no-live-probe",
        dest="live_probe",
        action="store_false",
        help=(
            "Remote-Prozess-/Log-Probe während laufender Installer "
            "deaktivieren"
        ),
    )
    p_install.set_defaults(
        func=cmd_install,
        live_probe=True,
    )

    return parser



def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        menu(args.project.resolve())
        return

    args.project = args.project.resolve()
    args.func(args)

__all__ = (
    "legacy_menu",
    "mavi_software_source_setup",
    "mavi_setup_menu",
    "mavi_doctor_menu",
    "mavi_credentials_menu",
    "mavi_pc_menu",
    "menu",
    "build_parser",
    "main",
)
