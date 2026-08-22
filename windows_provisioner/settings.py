# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Produktprofil, Standardwerte und persistierte Datenvorlagen."""

from __future__ import annotations

from ._dependencies import (
    Path,
    os,
)

VERSION = "0.9.10"
DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES = 45
# Ein neues Projekt wird bewusst außerhalb des Quell-Repositorys angelegt.
# So bleiben Umgebungswerte, Inventories, Zertifikate und Secrets getrennt
# vom veröffentlichbaren Programmcode.
DEFAULT_PROJECT = Path(
    os.environ.get(
        "XDG_DATA_HOME",
        str(Path.home() / ".local" / "share"),
    )
) / "mavi-provisioner"

CONFIG_TEMPLATE = {
    # Dieses Profil enthält ausschließlich nicht geheime Umgebungsfakten.
    # Passwörter gehören in Ansible Vault oder einen externen Secret Store.
    "profile": {
        "schema_version": 2,
        "name": "",
        "setup_completed": False,
    },
    "local_admin_user": "",
    "identity": {
        # Nicht geheim; der Setup-Assistent übernimmt den Wert zusätzlich in
        # windows.vars. Das Kennwort liegt ausschließlich im Ansible Vault.
        "ansible_user": "",
        "vault_path": "inventory/group_vars/windows/vault.yml",
    },
    "default_catalog": "default",
    # Der Setup-Assistent setzt den HTTPS-Endpunkt. Mavi deaktiviert die
    # Zertifikatsprüfung an keiner Stelle.
    "bootstrap_base_url": "",
    "bootstrap_local_dir": "",
    "ansible_server_ip": "",
    # Leer = das passende private RFC1918-/ULA-Netz automatisch verwenden.
    # Das hält den bewährten Ein-Klick-OpenSSH-Weg ohne zusätzliche Netzfrage
    # im Erststart nutzbar.
    "bootstrap_allowed_cidrs": [],
    # Kurze, umgebungseigene Zertifikatslaufzeiten. Eine CA-Rotation ist immer
    # ein expliziter administrativer Vorgang und geschieht nie still.
    "bootstrap_ca_validity_days": 825,
    "bootstrap_server_cert_validity_days": 90,
    # Leer = automatisch <software_source.local_root>/Mavi-Bootstrap und
    # <software_source.drive>\\Mavi-Bootstrap verwenden.
    "bootstrap_launcher_local_dir": "",
    "bootstrap_launcher_windows_dir": "",
    # Optional: exakter Zertifikat-Subject ODER exakter SimpleName der
    # vorhandenen Hersteller-Signatur der OpenSSH-MSI.
    "openssh_msi_expected_signer": "",
    "software_source": {
        "kind": "local",
        "label": "",
        "drive": "",
        "unc_root": "",
        "local_root": "",
        "mount_user": "",
        "mount_host": "",
    },
    "path_mappings": {},
    "ssh": {
        "port": 22,
        "private_key": "",
    },
    # PSRP/WinRM-Endstufe für eine optionale AD-Domäne. Mavi akzeptiert hier
    # absichtlich ausschließlich Kerberos: Kein Negotiate-/NTLM-Fallback.
    "winrm_https": {
        "domain_suffix": "",
        "port": 5986,
        "auth": "kerberos",
        # Leer = aus dem vorhandenen ansible_user als UPN ableiten.
        # Nur setzen, falls der UPN absichtlich davon abweicht.
        "kerberos_principal": "",
        # Leer = den echten AD-DNS-Server automatisch aus resolvectl bzw.
        # /etc/resolv.conf ermitteln. Optional eine einzelne DNS-Server-IP
        # setzen, wenn der Controller mehrere getrennte Resolver verwendet.
        "kerberos_dns_server": "",
        "message_encryption": "always",
        "disable_http_after_verified": True,
    },
    "ui": {
        # Welche Installationskontexte in der TUI angeboten werden.
        # Interne Werte bleiben stabil, damit bestehende Kataloge kompatibel sind.
        "visible_install_contexts": [
            "machine",
            "system",
            "user_interactive",
            "machine_detached",
            "machine_interactive",
            "user_uac",
        ],
        "install_contexts_schema": 2,
    },
}

CATALOG_TEMPLATE = {"software_catalog": {}}

INSTALLER_RULES_TEMPLATE = {"installer_rules": {}}
PARAMETER_BACKUP_TEMPLATE = {"parameter_profiles": {}}
PRINTER_CATALOG_TEMPLATE = {"printers": {}}

__all__ = (
    "VERSION",
    "DEFAULT_CLIENT_UNINSTALL_TIMEOUT_MINUTES",
    "DEFAULT_PROJECT",
    "CONFIG_TEMPLATE",
    "CATALOG_TEMPLATE",
    "INSTALLER_RULES_TEMPLATE",
    "PARAMETER_BACKUP_TEMPLATE",
    "PRINTER_CATALOG_TEMPLATE",
)
