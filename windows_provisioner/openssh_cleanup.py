# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""SSH-Key-Bereinigung.

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



def _public_key_prefix_from_path(pub_path: Path) -> str:
    """Key-Typ und Base64-Payload einer Public-Key-Datei lesen."""
    from .openssh import (
        _public_key_prefix_from_text,
    )

    if not pub_path.exists():
        return ""
    try:
        text = pub_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return _public_key_prefix_from_text(text)


def _public_key_prefix_from_text(public_key: str) -> str:
    """Key-Typ und Base64-Payload einer OpenSSH-Public-Key-Zeile lesen."""
    parts = str(public_key or "").strip().split()
    if len(parts) < 2:
        return ""
    return f"{parts[0]} {parts[1]}"


def _public_key_prefix_for_private_key(private_key_path: Path) -> str:
    """Public-Key-Präfix aus Companion-Datei oder dem privaten Key bestimmen."""
    from .openssh import (
        _public_key_prefix_from_path,
        _public_key_prefix_from_text,
    )

    resolved = private_key_path.expanduser().resolve()
    companion_prefix = _public_key_prefix_from_path(Path(str(resolved) + ".pub"))
    if companion_prefix:
        return companion_prefix
    if not resolved.is_file():
        return ""
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh_keygen:
        return ""
    try:
        result = subprocess.run(
            [ssh_keygen, "-y", "-P", "", "-f", str(resolved)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return _public_key_prefix_from_text(result.stdout)


def _ssh_private_key_path_for_host(
    project: Path,
    windows: dict[str, Any],
    host_data: dict[str, Any],
    *,
    requested_key: Path | str | None = None,
) -> Path:
    """Expliziten, aktiven oder gemerkten SSH-Key eines Hosts auflösen."""
    from .remote import _connection_label, _effective_host_var, get_ssh_settings

    raw_key = str(requested_key or "").strip()
    if not raw_key and _connection_label(windows, host_data) == "SSH":
        raw_key = str(
            _effective_host_var(
                windows,
                host_data,
                "ansible_ssh_private_key_file",
                "",
            )
            or ""
        ).strip()
    if not raw_key:
        raw_key = str(host_data.get("mavi_ssh_private_key_file", "") or "").strip()
    if not raw_key:
        raw_key = str(get_ssh_settings(project)["private_key"])
    return Path(raw_key).expanduser().resolve()


def cmd_ssh_remove_keys(args: argparse.Namespace) -> None:
    """Mavi-Keys nach ausdrücklicher Bestätigung vom Windows-PC entfernen."""

    from .openssh import (
        _remove_mavi_ssh_keys_from_host,
    )

    from .catalogs import yes_no
    from .environment import (
        atomic_write_yaml,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _connection_label,
        _host_inventory_entry,
        _saved_winrm_https_transport,
        _ssh_environment_marker,
    )

    ensure_initialized(args.project, quiet=True)
    inv, windows, host_data = _host_inventory_entry(args.project, args.host)
    del inv
    connection_before = _connection_label(windows, host_data)
    saved_winrm_available = False
    if connection_before == "SSH":
        try:
            _saved_winrm_https_transport(args.project, host_data)
        except ValueError:
            pass
        else:
            saved_winrm_available = True

    if not bool(getattr(args, "yes", False)):
        print("\nMavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print(f"PC:          {args.host}")
        print(f"Verbindung:  {connection_before}")
        print(f"Entfernt werden NUR Mavi-Keys dieses Projekts mit Marker '{_ssh_environment_marker(args.project)}'")
        print("und der aktuell auf dem Ansible-Server konfigurierte Mavi-Public-Key.")
        print("Andere Einträge in administrators_authorized_keys bleiben erhalten.")
        if connection_before == "SSH":
            if saved_winrm_available:
                print("Danach wird dieser Host auf das gespeicherte PSRP/WinRM HTTPS + Kerberos umgestellt.")
            else:
                print("! Für diesen PC ist kein geprüfter PSRP/WinRM-Ersatzweg gespeichert.")
                print("! Der Mavi-Key wird bei Bestätigung trotzdem entfernt; das Inventory bleibt auf SSH.")
        question = (
            "Mavi SSH-Key(s) trotz fehlendem Ersatzweg wirklich entfernen?"
            if connection_before == "SSH" and not saved_winrm_available
            else "Mavi SSH-Key(s) auf diesem PC wirklich entfernen?"
        )
        if not yes_no(question, default=False):
            print("Abgebrochen.")
            return

    rc = _remove_mavi_ssh_keys_from_host(args.project, args.host)
    if rc != 0:
        print(f"\n! Key-Entfernung auf {args.host} fehlgeschlagen, Code {rc}.")
        return

    if connection_before == "SSH" and saved_winrm_available:
        inv, windows, host_data = _host_inventory_entry(args.project, args.host)
        del windows
        _apply_saved_winrm_https_transport(args.project, host_data)
        atomic_write_yaml(project_paths(args.project)["inventory"], inv)
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt und Inventory auf PSRP HTTPS/Kerberos umgestellt.")
    else:
        print(f"✓ {args.host}: Mavi SSH-Key(s) entfernt. Verbindung bleibt {connection_before}.")
        if connection_before == "SSH":
            print("  Für neue Mavi-SSH-Verbindungen muss wieder ein Key eingerichtet oder die Verbindung umgestellt werden.")

    print("  OpenSSH/sshd bleibt auf Windows installiert und aktiv.")
    print("  Fremde SSH-Keys und Mavi-known_hosts auf dem Ansible-Server bleiben unangetastet.")


def ssh_remove_keys_menu(project: Path) -> None:

    from .openssh import (
        _remove_mavi_ssh_keys_from_host,
        cmd_ssh_remove_keys,
    )

    from .catalogs import (
        choose_host_interactive,
        yes_no,
    )
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )
    from .remote import (
        _apply_saved_winrm_https_transport,
        _connection_label,
        _host_inventory_entry,
        _saved_winrm_https_transport,
    )

    while True:
        print()
        print("Mavi SSH-KEYS ENTFERNEN")
        print("=======================")
        print("  1) Von EINEM Windows-PC entfernen")
        print("  2) Von ALLEN Windows-PCs entfernen")
        print("  0) Zurück")
        print()
        choice = input("> ").strip()

        if choice == "1":
            host = choose_host_interactive(project)
            cmd_ssh_remove_keys(
                argparse.Namespace(project=project, host=host, yes=False)
            )
            return

        if choice == "2":
            inv = load_inventory(project)
            windows = ensure_windows_tree(inv)
            hosts = list((windows.get("hosts", {}) or {}).keys())
            if not hosts:
                print("Keine Windows-PCs im Inventory vorhanden.")
                return

            print()
            print(f"! Mavi SSH-Key(s) werden auf {len(hosts)} PC(s) entfernt.")
            switch_to_winrm: set[str] = set()
            ssh_without_replacement: list[str] = []
            for host in hosts:
                _, host_windows, host_data = _host_inventory_entry(project, host)
                if _connection_label(host_windows, host_data) != "SSH":
                    continue
                try:
                    _saved_winrm_https_transport(project, host_data)
                except ValueError:
                    ssh_without_replacement.append(host)
                else:
                    switch_to_winrm.add(host)

            if ssh_without_replacement:
                print(
                    f"! Für {len(ssh_without_replacement)} SSH-PC(s) ist kein geprüfter "
                    "PSRP/WinRM-Ersatzweg gespeichert: " + ", ".join(ssh_without_replacement)
                )
                print("! Bei Bestätigung werden die Mavi-Keys dort trotzdem entfernt; das Inventory bleibt auf SSH.")
                question = "Mavi SSH-Key(s) trotzdem auf ALLEN Inventory-PCs entfernen?"
            else:
                question = "Mavi SSH-Key(s) wirklich auf ALLEN Inventory-PCs entfernen?"
            if not yes_no(question, default=False):
                print("Abgebrochen.")
                return

            succeeded: list[str] = []
            failed: list[str] = []
            for index, host in enumerate(hosts, start=1):
                print()
                print(f"[{index}/{len(hosts)}] {host}")
                before_inv, before_windows, before_data = _host_inventory_entry(project, host)
                del before_inv
                connection_before = _connection_label(before_windows, before_data)
                rc = _remove_mavi_ssh_keys_from_host(project, host)
                if rc != 0:
                    failed.append(host)
                    print(f"! {host}: fehlgeschlagen, Verbindung bleibt {connection_before}.")
                    continue

                if host in switch_to_winrm:
                    after_inv, after_windows, after_data = _host_inventory_entry(project, host)
                    del after_windows
                    _apply_saved_winrm_https_transport(project, after_data)
                    atomic_write_yaml(project_paths(project)["inventory"], after_inv)
                succeeded.append(host)
                if host in switch_to_winrm:
                    print(f"✓ {host}: Key(s) entfernt → PSRP HTTPS/Kerberos")
                else:
                    print(f"✓ {host}: Key(s) entfernt, Verbindung bleibt {connection_before}")

            print()
            print("Mavi SSH-KEY-ENTFERNUNG FERTIG")
            print("==============================")
            print(f"Erfolgreich: {len(succeeded)}/{len(hosts)}")
            if failed:
                print("Fehlgeschlagen: " + ", ".join(failed))
            return

        if choice == "0":
            return

        print("Ungültige Auswahl.")
