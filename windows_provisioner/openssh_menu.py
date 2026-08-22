# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Interaktives OpenSSH-Menü.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    ThreadPoolExecutor,
    argparse,
    as_completed,
    base64,
    datetime,
    getpass,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    socket,
    ssl,
    subprocess,
    sys,
    tempfile,
    time,
    timezone,
    urllib,
    yaml,
)



def ssh_menu(project: Path) -> None:
    from .openssh import (
        cmd_ssh_guide,
        cmd_ssh_keygen,
        cmd_ssh_setup_check,
        cmd_ssh_status,
        cmd_ssh_use,
        cmd_ssh_use_psrp,
        cmd_ssh_winrm_https,
        cmd_ssh_winrm_reset,
        ssh_remove_keys_menu,
    )

    from .catalogs import choose_host_interactive, prompt_choice, yes_no
    from .execution import cmd_ping

    while True:
        print()
        print("OPENSSH / WINDOWS")
        print("=================")
        print("  1) Mavi SSH-Key anlegen / anzeigen")
        print("  2) OpenSSH für neuen PC vollautomatisch vorbereiten")
        print("  3) PC auf OpenSSH umstellen")
        print("  4) PC auf geprüftes PSRP/WinRM HTTPS + Kerberos umstellen")
        print("  5) Remote-Verwaltungsstatus / Doctor")
        print("  6) Verbindung testen (win_ping)")
        print("  7) Mavi SSH-Key(s) von Windows-PC(s) entfernen")
        print("  8) nginx/HTTPS/Zertifikat automatisch einrichten oder prüfen")
        print("  9) WinRM über OpenSSH auf HTTPS + Kerberos-only härten")
        print(" 10) WinRM/Kerberos auf Stand 0 setzen (OpenSSH bleibt aktiv)")
        print(" 11) Mavi-Remote-Verwaltung vollständig deaktivieren")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        try:
            if choice == "1":
                cmd_ssh_keygen(argparse.Namespace(project=project, key=None, yes=False))
            elif choice == "2":
                host = choose_host_interactive(project)
                cmd_ssh_guide(argparse.Namespace(project=project, host=host, key=None, msi=None, prompt_msi=True))
            elif choice == "3":
                host = choose_host_interactive(project)
                cmd_ssh_use(argparse.Namespace(project=project, host=host, key=None, port=None, yes=False))
            elif choice == "4":
                host = choose_host_interactive(project)
                cmd_ssh_use_psrp(argparse.Namespace(project=project, host=host))
            elif choice == "5":
                scope = prompt_choice(
                    "Statusumfang:",
                    [
                        ("1", "Einzelnen PC prüfen"),
                        ("2", "Alle Inventory-PCs prüfen"),
                    ],
                    "1",
                )
                host = choose_host_interactive(project) if scope == "1" else None
                live = yes_no(
                    "Live-Check über den aktuellen Verwaltungsweg ausführen?",
                    default=False,
                )
                cmd_ssh_status(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        all_hosts=(scope == "2"),
                        live=live,
                    )
                )
            elif choice == "6":
                host = choose_host_interactive(project)
                try:
                    cmd_ping(argparse.Namespace(project=project, host=host))
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        print(f"\nPing beendet mit Code {exc.code}.")
            elif choice == "7":
                ssh_remove_keys_menu(project)
            elif choice == "8":
                cmd_ssh_setup_check(argparse.Namespace(project=project, msi=None))
            elif choice == "9":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_https(argparse.Namespace(project=project, host=host))
            elif choice == "10":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=False,
                    )
                )
            elif choice == "11":
                host = choose_host_interactive(project)
                cmd_ssh_winrm_reset(
                    argparse.Namespace(
                        project=project,
                        host=host,
                        key=None,
                        port=None,
                        yes=False,
                        disable_openssh=True,
                    )
                )
            elif choice == "0":
                return
            else:
                print("Ungültige Auswahl.")
        except SystemExit as exc:
            if exc.code not in (0, None):
                print(f"\nAktion beendet mit Code {exc.code}.")
