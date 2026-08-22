# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Inventory-Grundlagen.

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


def load_inventory(project: Path) -> dict[str, Any]:
    from .environment import (
        die,
        load_yaml,
        project_paths,
    )

    path = project_paths(project)["inventory"]
    if not path.exists():
        return {
            "all": {
                "children": {
                    "windows": {
                        "vars": {
                            "ansible_connection": "ssh",
                            "ansible_port": 22,
                            "ansible_shell_type": "powershell",
                        },
                        "hosts": {},
                    }
                }
            }
        }
    data = load_yaml(path, {})
    if not isinstance(data, dict):
        die(f"Inventory ist kein gültiges YAML-Dictionary: {path}")
    # Alte Projekte dürfen bei keinem neuen Mavi-Aufruf versehentlich erneut
    # HTTP/5985 + NTLM verwenden. Sichere, explizit gesetzte PSRP-HTTPS/
    # Kerberos-Hosts bleiben erhalten; sonst wird nur in-memory auf SSH
    # zurückgestellt und beim nächsten Inventory-Schreiben persistiert.
    windows = (
        data.get("all", {}) if isinstance(data.get("all"), dict) else {}
    )
    children = windows.get("children", {}) if isinstance(windows.get("children"), dict) else {}
    group = children.get("windows", {}) if isinstance(children.get("windows"), dict) else {}
    group_vars = group.get("vars", {}) if isinstance(group.get("vars"), dict) else {}
    group_connection = str(group_vars.get("ansible_connection", "") or "").lower()
    group_protocol = str(group_vars.get("ansible_psrp_protocol", "") or "").lower()
    group_auth = str(group_vars.get("ansible_psrp_auth", "") or "").lower()
    group_legacy = group_connection == "psrp" and (
        group_protocol != "https" or group_auth != "kerberos"
    )
    if group_legacy:
        group_vars["ansible_connection"] = "ssh"
        group_vars["ansible_port"] = 22
        group_vars["ansible_shell_type"] = "powershell"
        for key in ("ansible_psrp_protocol", "ansible_psrp_auth", "ansible_psrp_cert_validation", "ansible_psrp_ca_cert", "ansible_psrp_message_encryption"):
            group_vars.pop(key, None)
    hosts = group.get("hosts", {}) if isinstance(group.get("hosts"), dict) else {}
    for host_vars in hosts.values():
        if not isinstance(host_vars, dict):
            continue
        connection = str(host_vars.get("ansible_connection", "") or "").lower()
        protocol = str(host_vars.get("ansible_psrp_protocol", "") or "").lower()
        auth = str(host_vars.get("ansible_psrp_auth", "") or "").lower()
        legacy = connection == "psrp" and (
            protocol != "https" or auth != "kerberos"
        )
        if legacy:
            host_vars["ansible_connection"] = "ssh"
            host_vars["ansible_port"] = 22
            host_vars["ansible_shell_type"] = "powershell"
            for key in ("ansible_psrp_protocol", "ansible_psrp_auth", "ansible_psrp_cert_validation", "ansible_psrp_ca_cert", "ansible_psrp_message_encryption"):
                host_vars.pop(key, None)
    return data


def ensure_windows_tree(inv: dict[str, Any]) -> dict[str, Any]:
    all_ = inv.setdefault("all", {})
    children = all_.setdefault("children", {})
    windows = children.setdefault("windows", {})
    vars_ = windows.setdefault("vars", {})
    vars_.setdefault("ansible_connection", "ssh")
    vars_.setdefault("ansible_port", 22)
    vars_.setdefault("ansible_shell_type", "powershell")
    windows.setdefault("hosts", {})
    return windows
