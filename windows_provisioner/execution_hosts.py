# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Hostverwaltung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    json,
    os,
    queue,
    re,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    yaml,
)



def cmd_host_add(args: argparse.Namespace) -> None:
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    from .catalogs import (
        prompt,
        prompt_choice,
        validate_host_address,
    )
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _apply_ssh_transport,
        _connection_label,
        _validate_inventory_host_alias,
        _validate_new_host_alias,
    )

    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)

    name = args.name or prompt("PC-Name (muss dem Windows-Computernamen entsprechen)")
    ip = validate_host_address(
        args.ip or prompt("IPv4-Adresse oder FQDN")
    )

    # Standard: KEIN host-spezifischer Benutzer. Dadurch erbt der neue PC
    # den zentralen Ansible-/Domänen-Benutzer aus windows.vars bzw. group_vars.
    # Ein Override ist nur noch bewusst per --ansible-user möglich.
    ansible_user = getattr(args, "ansible_user", None)
    legacy_local_admin = getattr(args, "local_admin", None)
    requested_connection = getattr(args, "connection", None)
    ssh_key_arg = getattr(args, "ssh_key", None)
    ssh_port_arg = getattr(args, "ssh_port", None)

    if ansible_user and legacy_local_admin:
        die("--ansible-user und --local-admin nicht gleichzeitig verwenden.")

    interactive_add = args.name is None or args.ip is None
    if requested_connection is None and interactive_add:
        print()
        selected_transport = prompt_choice(
            "Verbindung für diesen PC:",
            [
                ("1", "OpenSSH / SSH-Key (Mavi-Standard)"),
            ],
            "1",
        )
        requested_connection = "ssh"

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows["hosts"]
    name = str(name or "")
    existing_host = name in hosts
    try:
        if existing_host:
            name = _validate_inventory_host_alias(name)
        else:
            name = _validate_new_host_alias(name)
    except ValueError as exc:
        die(str(exc))

    host_data = hosts.setdefault(name, {})
    if not isinstance(host_data, dict):
        host_data = {}
        hosts[name] = host_data

    disabled_state = host_data.get("mavi_remote_management_disabled")
    if (
        existing_host
        and requested_connection == "ssh"
        and isinstance(disabled_state, dict)
        and disabled_state.get("openssh") is True
    ):
        die(
            f"{name} ist als vollständig remote deaktiviert gespeichert. "
            f"Nach dem lokalen OpenSSH-Starter ausschließlich mit "
            f"'mavi-provisioner ssh use {name}' reaktivieren."
        )

    host_data["ansible_host"] = ip

    if ansible_user:
        host_data["ansible_user"] = ansible_user
    elif legacy_local_admin:
        # Rückwärtskompatibilität für alte CLI-Aufrufe.
        host_data["ansible_user"] = f"{name}\\{legacy_local_admin}"
    else:
        # Wichtig: einen eventuell alten lokalen Override entfernen, damit
        # der zentrale Domänen-Admin wieder geerbt wird.
        host_data.pop("ansible_user", None)

    if requested_connection == "ssh":
        key_path = Path(ssh_key_arg).expanduser() if ssh_key_arg else None
        resolved_key, resolved_port = _apply_ssh_transport(
            args.project,
            host_data,
            key_path=key_path,
            port=ssh_port_arg,
        )
    elif requested_connection == "psrp":
        die(
            "Neue Hosts werden nicht mehr mit PSRP HTTP/NTLM angelegt. "
            "Zuerst den OpenSSH-Starter ausführen, dann 'ssh winrm-https' verwenden."
        )
    elif requested_connection not in (None, "inherit"):
        die("Unbekannte Verbindung. Erlaubt: inherit, psrp, ssh.")

    atomic_write_yaml(p["inventory"], inv)
    print(f"✓ {name} ({ip}) eingetragen.")

    if "ansible_user" in host_data:
        print(f"  Ansible-User: {host_data['ansible_user']} (Host-Override)")
    else:
        group_user = (windows.get("vars", {}) or {}).get("ansible_user")
        if group_user:
            print(f"  Ansible-User: {group_user} (zentral geerbt)")
        else:
            print("  Ansible-User: zentral geerbt (windows.vars / group_vars)")

    print(f"  Verbindung: {_connection_label(windows, host_data)}")
    if requested_connection == "ssh":
        print(f"  SSH-Port:    {resolved_port}")
        print(f"  SSH-Key:     {resolved_key}")
        if not resolved_key.exists():
            print("  ! SSH-Key fehlt noch. Nächster Schritt: mavi-provisioner ssh keygen")
        print(f"  Anleitung:   mavi-provisioner ssh guide {name}")


def cmd_host_list(args: argparse.Namespace) -> None:
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    from .remote import _connection_label

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {})
    if not hosts:
        print("Keine Windows-Hosts eingetragen.")
        return

    group_user = (windows.get("vars", {}) or {}).get("ansible_user")

    print(f"{'HOST':<25} {'IP':<18} {'VERB.':<8} {'ANSIBLE-USER'}")
    print("-" * 105)
    for name, data in hosts.items():
        data = data or {}
        host_user = data.get("ansible_user")
        if host_user:
            shown_user = f"{host_user} (Host-Override)"
        elif group_user:
            shown_user = f"{group_user} (geerbt)"
        else:
            shown_user = "(geerbt aus group_vars/windows.vars)"

        connection = _connection_label(windows, data)
        print(
            f"{name:<25} "
            f"{str(data.get('ansible_host', '')):<18} "
            f"{connection:<8} "
            f"{shown_user}"
        )


def cmd_host_remove(args: argparse.Namespace) -> None:
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    from .catalogs import (
        choose_host_interactive,
        yes_no,
    )
    from .environment import (
        atomic_write_yaml,
        die,
        ensure_initialized,
        project_paths,
    )

    ensure_initialized(args.project, quiet=True)

    name = getattr(args, "name", None)
    if not name:
        name = choose_host_interactive(args.project)

    inv = load_inventory(args.project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {})
    if not isinstance(hosts, dict):
        die("Windows-Inventory enthält keine gültige Host-Zuordnung.")
    if name not in hosts:
        die(f"PC '{name}' ist nicht im Windows-Inventory vorhanden.")

    selected_host_entry = hosts[name]
    host_data = selected_host_entry if isinstance(selected_host_entry, dict) else {}
    ip = str(host_data.get("ansible_host", "") or "")
    pc_label = f"PC '{name}'" + (f" ({ip})" if ip else "")
    if not bool(getattr(args, "yes", False)) and not yes_no(
        f"{pc_label} wirklich aus dem Inventory entfernen?",
        default=False,
    ):
        print("Abgebrochen.")
        return

    # Die Bestätigung kann beliebig lange offen bleiben. Deshalb den aktuellen
    # Inventory-Stand danach erneut laden, damit parallele Änderungen an anderen
    # Hosts nicht mit dem vor der Rückfrage gelesenen Snapshot überschrieben werden.
    current_inv = load_inventory(args.project)
    current_windows = ensure_windows_tree(current_inv)
    current_hosts = current_windows.get("hosts", {})
    if not isinstance(current_hosts, dict):
        die("Windows-Inventory enthält keine gültige Host-Zuordnung.")
    if name not in current_hosts:
        die(f"PC '{name}' wurde zwischenzeitlich aus dem Inventory entfernt.")
    if current_hosts[name] != selected_host_entry:
        die(
            f"Der Inventory-Eintrag von PC '{name}' wurde zwischenzeitlich geändert. "
            "Bitte Entfernung erneut starten und den aktuellen Eintrag bestätigen."
        )

    del current_hosts[name]
    atomic_write_yaml(project_paths(args.project)["inventory"], current_inv)
    print(f"✓ {pc_label} aus dem Inventory entfernt.")
    print("  Der Windows-PC selbst und seine Remote-Konfiguration wurden nicht verändert.")
