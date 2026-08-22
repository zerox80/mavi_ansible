# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Projektdateien und Initialisierung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    hashlib,
    os,
    re,
    shutil,
    subprocess,
    sys,
    tempfile,
    time,
    yaml,
)


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def die(message: str, code: int = 1) -> None:
    from .environment import (
        eprint,
    )

    from .reports import redact_sensitive_text

    eprint(f"\nFEHLER: {redact_sensitive_text(message)}\n")
    raise SystemExit(code)


def project_paths(project: Path) -> dict[str, Path]:
    return {
        "project": project,
        "inventory": project / "inventory" / "hosts.yml",
        "credentials_vault": project / "inventory" / "group_vars" / "windows" / "vault.yml",
        "software_dir": project / "software",
        "legacy_catalog": project / "software" / "catalog.yml",
        "catalogs_dir": project / "software" / "catalogs",
        "office_configs_dir": project / "software" / "office_configs",
        "installer_rules": project / "software" / "installer_rules.yml",
        "parameter_backups": project / "software" / "parameter_backups.yml",
        "config": project / "software" / "mavi_config.yml",
        "playbooks": project / "playbooks",
        "playbook": project / "playbooks" / "install_catalog.yml",
        "tasks_dir": project / "playbooks" / "tasks",
        "task": project / "playbooks" / "tasks" / "install_one.yml",
        "diagnostic_task": project / "playbooks" / "tasks" / "diagnose_install_failure.yml",
        "live_probe_playbook": project / "playbooks" / "live_install_probe.yml",
        "client_optimize_playbook": project / "playbooks" / "client_optimize.yml",
        "client_uninstall_playbook": project / "playbooks" / "client_uninstall.yml",
        "printers_dir": project / "printers",
        "printer_catalog": project / "printers" / "catalog.yml",
        "printer_playbook": project / "playbooks" / "install_printers.yml",
        "printer_task": project / "playbooks" / "tasks" / "install_printer_one.yml",
        "ssh_dir": project / ".ssh",
        "ssh_key": project / ".ssh" / "mavi_windows_ed25519",
        "ssh_known_hosts": project / ".ssh" / "known_hosts",
        "ssh_bootstrap_dir": project / ".ssh" / "bootstrap",
        # Von der HTTPS-Bootstrap-CA bewusst getrennte CA ausschließlich für
        # WinRM-Serverzertifikate. Sie wird nie über nginx veröffentlicht.
        "winrm_pki_dir": project / ".mavi-winrm-pki",
        # Projektlokale Kerberos-Laufzeitkonfiguration. Mavi verändert nie
        # systemweit /etc/krb5.conf und nutzt ausschließlich diese Datei für
        # seine eigenen Ansible-Unterprozesse.
        "kerberos_runtime_dir": project / ".mavi-kerberos",
        "reports_dir": project / "reports",
    }


def load_yaml(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        value = yaml.safe_load(f)
    return default if value is None else value


def atomic_write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                data,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                width=120,
            )
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def write_if_missing(path: Path, content: str) -> bool:
    if path.exists():
        return False
    atomic_write_text(path, content)
    return True


def write_managed_file(path: Path, content: str) -> str:
    """
    Vom Mavi-Tool verwaltete Dateien werden bei einem Versionsupdate aktualisiert.
    Wenn bereits anderer Inhalt existiert, bleibt eine eindeutige, nicht erneut
    überschriebene Sicherung erhalten.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        current = path.read_text(encoding="utf-8")
        if current == content:
            return "unchanged"

        backup = path.with_name(f"{path.name}.bak.{time.time_ns()}")
        atomic_write_text(backup, current)
        atomic_write_text(path, content)
        return "updated"

    atomic_write_text(path, content)
    return "created"


def ensure_initialized(project: Path, quiet: bool = False) -> None:
    from .environment import (
        atomic_write_yaml,
        load_yaml,
        project_paths,
        write_managed_file,
    )

    from .catalogs import DEFAULT_VISIBLE_INSTALL_CONTEXTS
    from .remote import _activate_existing_kerberos_runtime_config
    from .settings import (
        CATALOG_TEMPLATE,
        CONFIG_TEMPLATE,
        INSTALLER_RULES_TEMPLATE,
        PARAMETER_BACKUP_TEMPLATE,
        PRINTER_CATALOG_TEMPLATE,
    )
    from .templates import (
        CLIENT_OPTIMIZE_PLAYBOOK_TEMPLATE,
        CLIENT_UNINSTALL_PLAYBOOK_TEMPLATE,
        DIAGNOSTIC_TASK_TEMPLATE,
        LIVE_PROBE_PLAYBOOK_TEMPLATE,
        PLAYBOOK_TEMPLATE,
        PRINTER_PLAYBOOK_TEMPLATE,
        PRINTER_TASK_TEMPLATE,
        TASK_TEMPLATE,
    )

    p = project_paths(project)
    # Falls dieses Projekt bereits einen gehärteten WinRM-/Kerberos-Transport
    # eingerichtet hat, muss auch ein später neu gestartetes Mavi dieselbe
    # projektlokale KDC-DNS-Konfiguration an seine Ansible-Prozesse vererben.
    # Fehlt sie noch, wird sie ausschließlich beim WinRM-Setup erzeugt.
    _activate_existing_kerberos_runtime_config(project)
    p["software_dir"].mkdir(parents=True, exist_ok=True)
    p["catalogs_dir"].mkdir(parents=True, exist_ok=True)
    p["office_configs_dir"].mkdir(parents=True, exist_ok=True)
    p["printers_dir"].mkdir(parents=True, exist_ok=True)

    # Legacy-Datei bleibt kompatibel, wird in v0.8 aber nicht mehr
    # automatisch für Silent-Erkennung verwendet.
    if not p["installer_rules"].exists():
        atomic_write_yaml(p["installer_rules"], INSTALLER_RULES_TEMPLATE)

    if not p["parameter_backups"].exists():
        atomic_write_yaml(
            p["parameter_backups"],
            PARAMETER_BACKUP_TEMPLATE,
        )
        if not quiet:
            print(
                f"✓ Parameter-Backupdatei angelegt: "
                f"{p['parameter_backups']}"
            )

    if not p["printer_catalog"].exists():
        atomic_write_yaml(p["printer_catalog"], PRINTER_CATALOG_TEMPLATE)
        if not quiet:
            print(f"✓ Druckerkatalog angelegt: {p['printer_catalog']}")

    p["playbooks"].mkdir(parents=True, exist_ok=True)
    p["tasks_dir"].mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    updated: list[Path] = []
    migrated: list[tuple[Path, Path]] = []

    # Konfiguration anlegen bzw. neue Standardwerte ergänzen.
    if not p["config"].exists():
        atomic_write_yaml(p["config"], CONFIG_TEMPLATE)
        created.append(p["config"])
        config_data = dict(CONFIG_TEMPLATE)
    else:
        config_data = load_yaml(p["config"], {}) or {}
        changed = False

        for key, value in CONFIG_TEMPLATE.items():
            if key not in config_data:
                config_data[key] = value
                changed = True

        # Verschachtelte Bereiche ebenfalls ergänzen.
        for nested_key in (
            "profile",
            "identity",
            "software_source",
            "path_mappings",
            "ssh",
            "winrm_https",
            "ui",
        ):
            defaults = CONFIG_TEMPLATE.get(nested_key, {}) or {}
            current = config_data.get(nested_key, {}) or {}

            # v0.8.33-Migration muss passieren, bevor die neuen UI-Defaults
            # gemerged werden. Sonst würde das Default-Schema die alte
            # Konfiguration bereits wie eine neue aussehen lassen.
            if nested_key == "ui" and "install_contexts_schema" not in current:
                current = dict(current)
                visible = current.get("visible_install_contexts")
                if not isinstance(visible, list):
                    visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
                else:
                    visible = list(visible)
                    if "user_uac" not in visible:
                        visible.append("user_uac")
                current["visible_install_contexts"] = visible
                current["install_contexts_schema"] = 2
                changed = True

            merged = dict(defaults)
            merged.update(current)
            if merged != config_data.get(nested_key, {}):
                config_data[nested_key] = merged
                changed = True

        # v0.8.33: Der neue UAC-Kontext existierte vorher noch nicht und kann
        # deshalb in alten Sichtbarkeitslisten nicht bewusst deaktiviert worden sein.
        # Einmalig sichtbar ergänzen; danach respektiert das Optionen-Menü die Auswahl.
        ui_current = dict(config_data.get("ui", {}) or {})
        try:
            ui_schema = int(ui_current.get("install_contexts_schema", 1) or 1)
        except (TypeError, ValueError):
            ui_schema = 1
        if ui_schema < 2:
            visible = ui_current.get("visible_install_contexts")
            if not isinstance(visible, list):
                visible = list(DEFAULT_VISIBLE_INSTALL_CONTEXTS)
            else:
                visible = list(visible)
                if "user_uac" not in visible:
                    visible.append("user_uac")
            ui_current["visible_install_contexts"] = visible
            ui_current["install_contexts_schema"] = 2
            config_data["ui"] = ui_current
            changed = True

        if changed:
            atomic_write_yaml(p["config"], config_data)
            updated.append(p["config"])

    default_name = str(config_data.get("default_catalog", "default")).strip() or "default"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", default_name):
        default_name = "default"
        config_data["default_catalog"] = default_name
        atomic_write_yaml(p["config"], config_data)
        if p["config"] not in updated:
            updated.append(p["config"])

    default_catalog_path = p["catalogs_dir"] / f"{default_name}.yml"

    # Migration aus v0.2.x:
    # software/catalog.yml bleibt als Legacy-Backup liegen.
    if not default_catalog_path.exists():
        if p["legacy_catalog"].exists():
            legacy_data = load_yaml(p["legacy_catalog"], CATALOG_TEMPLATE)
            if "software_catalog" not in (legacy_data or {}):
                legacy_data = {"software_catalog": legacy_data or {}}
            atomic_write_yaml(default_catalog_path, legacy_data)
            migrated.append((p["legacy_catalog"], default_catalog_path))
        else:
            atomic_write_yaml(default_catalog_path, CATALOG_TEMPLATE)
            created.append(default_catalog_path)

    playbook_status = write_managed_file(p["playbook"], PLAYBOOK_TEMPLATE)
    if playbook_status == "created":
        created.append(p["playbook"])
    elif playbook_status == "updated":
        updated.append(p["playbook"])

    task_status = write_managed_file(p["task"], TASK_TEMPLATE)
    if task_status == "created":
        created.append(p["task"])
    elif task_status == "updated":
        updated.append(p["task"])

    diagnostic_status = write_managed_file(
        p["diagnostic_task"],
        DIAGNOSTIC_TASK_TEMPLATE,
    )
    if diagnostic_status == "created":
        created.append(p["diagnostic_task"])
    elif diagnostic_status == "updated":
        updated.append(p["diagnostic_task"])

    live_probe_status = write_managed_file(
        p["live_probe_playbook"],
        LIVE_PROBE_PLAYBOOK_TEMPLATE,
    )
    if live_probe_status == "created":
        created.append(p["live_probe_playbook"])
    elif live_probe_status == "updated":
        updated.append(p["live_probe_playbook"])

    client_optimize_status = write_managed_file(
        p["client_optimize_playbook"],
        CLIENT_OPTIMIZE_PLAYBOOK_TEMPLATE,
    )
    if client_optimize_status == "created":
        created.append(p["client_optimize_playbook"])
    elif client_optimize_status == "updated":
        updated.append(p["client_optimize_playbook"])

    client_uninstall_status = write_managed_file(
        p["client_uninstall_playbook"],
        CLIENT_UNINSTALL_PLAYBOOK_TEMPLATE,
    )
    if client_uninstall_status == "created":
        created.append(p["client_uninstall_playbook"])
    elif client_uninstall_status == "updated":
        updated.append(p["client_uninstall_playbook"])

    printer_playbook_status = write_managed_file(
        p["printer_playbook"],
        PRINTER_PLAYBOOK_TEMPLATE,
    )
    if printer_playbook_status == "created":
        created.append(p["printer_playbook"])
    elif printer_playbook_status == "updated":
        updated.append(p["printer_playbook"])

    printer_task_status = write_managed_file(
        p["printer_task"],
        PRINTER_TASK_TEMPLATE,
    )
    if printer_task_status == "created":
        created.append(p["printer_task"])
    elif printer_task_status == "updated":
        updated.append(p["printer_task"])

    if not quiet:
        if migrated:
            print("Katalog migriert:")
            for old_path, new_path in migrated:
                print(f"  ✓ {old_path}")
                print(f"    → {new_path}")
                print("    Alte Datei bleibt als Legacy-Backup erhalten.")

        if created:
            print("Erstellt:")
            for path in created:
                print(f"  ✓ {path}")

        if updated:
            print("Aktualisiert:")
            for path in updated:
                print(f"  ✓ {path}")

        if not created and not updated and not migrated:
            print("✓ Mavi-Provisioner-Dateien sind bereits aktuell.")

        if not p["inventory"].exists():
            print(f"\n! Inventory fehlt noch: {p['inventory']}")


def atomic_write_text(path: Path, content: str, *, mode: int | None = None) -> None:
    """Text vollständig schreiben, bevor der bisherige Pfad ersetzt wird."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        if mode is not None:
            os.chmod(tmp_name, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
