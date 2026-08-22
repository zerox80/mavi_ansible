# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Inventory-, Ansible- und Installationsausführung."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    getpass,
    json,
    os,
    queue,
    re,
    secrets,
    shutil,
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


def cmd_host_add(args: argparse.Namespace) -> None:
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


def shlex_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=,@+-]+", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_subprocess(
    cmd: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
) -> int:
    from .environment import die
    from .reports import redact_sensitive_text

    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()
    try:
        return subprocess.call(cmd, cwd=str(cwd), env=env)
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
    return 1



ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value)


def format_elapsed(seconds: float) -> str:
    seconds_i = max(0, int(seconds))
    minutes, seconds_i = divmod(seconds_i, 60)
    hours, minutes = divmod(minutes, 60)

    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds_i:02d}"

    return f"{minutes:02d}:{seconds_i:02d}"


def is_live_install_task(task_name: str) -> bool:
    """
    Nur Aufgaben markieren, bei denen der eigentliche Installer läuft.
    Kopieren, Prüfen, Diagnose usw. erzeugen keinen Heartbeat.
    """
    markers = (
        " | Systemweit installieren",
        " | Als SYSTEM installieren",
        " | Detached systemweit installieren",
        " | Interaktiv über Task Scheduler installieren",
        " | Microsoft Office / Project / Visio per ODT installieren",
        " | ODT-Task auf Abschluss warten",
        " | WinGet MACHINE installieren",
        " | WinGet USER über angemeldeten Benutzer installieren",
    )
    return any(marker in task_name for marker in markers)


def task_software_key(task_name: str) -> str:
    if " | " not in task_name:
        return ""
    return task_name.split(" | ", 1)[0].strip()


def print_live_install_status(
    *,
    host: str,
    task_name: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    from .reports import redact_sensitive_text

    key = task_software_key(task_name)
    app = apps.get(key, {}) if key else {}

    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )

    arguments = app.get("arguments")
    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Installer läuft noch, "
        "Ansible wartet auf Rückmeldung."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Task:       {task_name}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(
        f"  Letzte Ansible-Ausgabe: vor {silent_for}s"
    )
    print(
        "  Hinweis: Der Prozess wurde NICHT abgebrochen. "
        "Das ist nur die Live-Statusanzeige."
    )
    print(flush=True)



def print_general_wait_status(
    *,
    host: str,
    current_task: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    """
    Heartbeat auch dann, wenn Ansible noch keine neue TASK-Zeile geliefert
    hat. Das ist wichtig, wenn die Ausgabe selbst puffert oder ein Modul
    zwischen zwei sichtbaren Tasks hängt.
    """
    from .reports import redact_sensitive_text

    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    key = task_software_key(current_task)
    app = apps.get(key, {}) if key else {}

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )
    arguments = app.get("arguments")

    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Ansible läuft noch, "
        "aber liefert gerade keine neue Ausgabe."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Letzter sichtbarer Task: {current_task or '(noch keiner)'}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(f"  Keine neue Ansible-Ausgabe seit: {silent_for}s")
    print(
        "  Der Provisioner läuft weiter. Das ist KEIN Fehler und "
        "es wurde nichts abgebrochen."
    )
    print(flush=True)


def _stdout_reader(
    stream: Any,
    output_queue: "queue.Queue[str | None]",
) -> None:
    """
    Eigener Reader-Thread statt selectors + TextIOWrapper.

    Grund: TextIOWrapper kann mehrere Zeilen intern puffern. selectors sieht
    dann am OS-Handle keine neuen Bytes mehr, obwohl Python noch komplette
    Zeilen im eigenen Buffer hat. Genau dadurch konnte v0.8.4 nach einem
    'skipping:' scheinbar einfrieren.
    """
    try:
        for line in iter(stream.readline, ""):
            output_queue.put(line)
    finally:
        output_queue.put(None)



def create_temporary_vault_password_file(password: str) -> Path:
    """
    Einmal eingegebenes Vault-Passwort für Hauptlauf und parallele
    Live-Probes verwenden. Datei ist 0600 und wird nach dem Lauf gelöscht.
    """
    fd, raw_path = tempfile.mkstemp(
        prefix=".mavi-vault-",
        suffix=".txt",
    )

    path = Path(raw_path)

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password)
            handle.write("\n")

    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass

        path.unlink(missing_ok=True)
        raise

    return path


VAULT_SECRET_VARIABLE_RE = re.compile(
    r"^(?:vault|mavi_vault)_[A-Za-z][A-Za-z0-9_]{0,127}$"
)


def _credentials_vault_path(project: Path, config: dict[str, Any]) -> tuple[Path, str]:
    from .environment import die

    project_root = project.expanduser().resolve()
    identity = config.get("identity", {})
    if not isinstance(identity, dict):
        die("identity in mavi_config.yml muss ein YAML-Objekt sein.")
    raw_path = str(
        identity.get("vault_path", "inventory/group_vars/windows/vault.yml")
        or "inventory/group_vars/windows/vault.yml"
    ).strip()
    relative = Path(raw_path)
    if relative.is_absolute():
        die("identity.vault_path muss relativ zum Laufzeitprojekt sein.")
    resolved = (project_root / relative).resolve()
    try:
        resolved.relative_to(project_root)
    except ValueError:
        die("identity.vault_path darf das Laufzeitprojekt nicht über '..' verlassen.")
    if resolved.suffix.lower() not in {".yml", ".yaml"}:
        die("identity.vault_path muss auf eine .yml- oder .yaml-Datei zeigen.")
    normalized = resolved.relative_to(project_root).as_posix()
    return resolved, normalized


def _atomic_write_private_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    tmp_path = Path(raw_tmp)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content.rstrip() + "\n")
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        tmp_path.unlink(missing_ok=True)


def _encrypted_vault_variable_block(
    *,
    variable_name: str,
    secret_value: str,
    vault_password_file: Path,
) -> str:
    from .environment import die
    from .reports import redact_sensitive_text

    executable = shutil.which("ansible-vault")
    if not executable:
        die(
            "ansible-vault wurde nicht gefunden. Credentials werden nicht "
            "ersatzweise im Klartext gespeichert."
        )
    result = subprocess.run(
        [
            executable,
            "encrypt_string",
            "--stdin-name",
            variable_name,
            "--vault-password-file",
            str(vault_password_file),
        ],
        input=secret_value + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = redact_sensitive_text(result.stderr or result.stdout or "")
        die(f"ansible-vault konnte den Geheimwert nicht verschlüsseln: {detail.strip()}")

    block_pattern = re.compile(
        rf"(?m)^{re.escape(variable_name)}:\s*!vault\s*\|\s*$"
        rf"(?:\r?\n[ \t]+[^\r\n]*)+"
    )
    match = block_pattern.search(result.stdout or "")
    if not match:
        die("ansible-vault lieferte keinen erwarteten verschlüsselten YAML-Block.")
    block = match.group(0).rstrip()
    if secret_value and secret_value in block:
        die("SICHERHEITSABBRUCH: ansible-vault-Ausgabe enthielt den Klartextwert.")
    return block


def _upsert_encrypted_vault_variable(
    path: Path,
    *,
    variable_name: str,
    encrypted_block: str,
    force: bool,
) -> None:
    from .catalogs import yes_no
    from .environment import die

    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    for line in existing.splitlines():
        if not line or line.isspace() or line.lstrip().startswith("#") or line.strip() == "---":
            continue
        if line[:1].isspace():
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*:\s*!vault\s*\|\s*", line):
            die(
                f"Vault-Datei {path} enthält nicht verschlüsselte oder unbekannte "
                "Top-Level-Daten. Mavi verändert sie nicht automatisch."
            )

    current_pattern = re.compile(
        rf"(?m)^{re.escape(variable_name)}:\s*!vault\s*\|\s*$"
        rf"(?:\r?\n[ \t]+[^\r\n]*)+"
    )
    current = current_pattern.search(existing)
    if current and not force:
        if not sys.stdin.isatty() or not yes_no(
            f"Verschlüsselten Wert '{variable_name}' ersetzen?",
            False,
        ):
            die(f"Vault-Wert '{variable_name}' wurde nicht überschrieben.")

    if current:
        updated = existing[:current.start()] + encrypted_block + existing[current.end():]
    else:
        separator = "\n\n" if existing.strip() else "---\n"
        updated = existing.rstrip() + separator + encrypted_block
    _atomic_write_private_text(path, updated)


def _prompt_secret_twice(label: str) -> str:
    from .environment import die

    value = getpass.getpass(label + ": ")
    if not value:
        die("Leere Geheimwerte werden nicht gespeichert.")
    confirmation = getpass.getpass(label + " wiederholen: ")
    if not secrets.compare_digest(value, confirmation):
        die("Die beiden Eingaben stimmen nicht überein.")
    return value


def _store_vault_secret(
    project: Path,
    *,
    variable_name: str,
    secret_label: str,
    force: bool,
) -> tuple[Path, str]:
    from .environment import (
        die,
        get_config,
    )

    config = get_config(project)
    vault_path, normalized_path = _credentials_vault_path(project, config)
    secret_value = _prompt_secret_twice(secret_label)
    vault_password = getpass.getpass("Ansible-Vault-Passwort: ")
    if not vault_password:
        die("Leeres Ansible-Vault-Passwort ist nicht erlaubt.")
    vault_password_file: Path | None = None
    try:
        vault_password_file = create_temporary_vault_password_file(vault_password)
        encrypted_block = _encrypted_vault_variable_block(
            variable_name=variable_name,
            secret_value=secret_value,
            vault_password_file=vault_password_file,
        )
        _upsert_encrypted_vault_variable(
            vault_path,
            variable_name=variable_name,
            encrypted_block=encrypted_block,
            force=force,
        )
    finally:
        secret_value = ""
        vault_password = ""
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)
    return vault_path, normalized_path


def cmd_credentials_setup(args: argparse.Namespace) -> None:
    """Create the Windows credential as an encrypted group variable only."""
    from .catalogs import prompt
    from .environment import (
        _mavi_normalize_ansible_user,
        atomic_write_yaml,
        die,
        ensure_initialized,
        get_config,
        project_paths,
    )

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)
    identity = dict(config.get("identity", {}) or {})
    ansible_user = str(
        getattr(args, "ansible_user", None)
        or identity.get("ansible_user", "")
        or ""
    ).strip()
    if not ansible_user and sys.stdin.isatty():
        ansible_user = prompt(r"Ansible-Benutzer, z. B. EXAMPLE\Provisioning-Admin")
    try:
        ansible_user = _mavi_normalize_ansible_user(ansible_user)
    except ValueError as exc:
        die(str(exc))
    if not ansible_user:
        die("Ansible-Benutzer fehlt.")

    vault_path, normalized_path = _store_vault_secret(
        args.project,
        variable_name="ansible_password",
        secret_label=f"Kennwort für {ansible_user}",
        force=bool(getattr(args, "force", False)),
    )

    identity["ansible_user"] = ansible_user
    identity["vault_path"] = normalized_path
    config["identity"] = identity
    atomic_write_yaml(project_paths(args.project)["config"], config)

    inventory = load_inventory(args.project)
    windows = ensure_windows_tree(inventory)
    windows.setdefault("vars", {})["ansible_user"] = ansible_user
    atomic_write_yaml(project_paths(args.project)["inventory"], inventory)

    print("✓ Windows-Credential ausschließlich verschlüsselt gespeichert.")
    print(f"  Benutzer: {ansible_user}")
    print(f"  Vault:    {vault_path}")
    print("  Kennwort: nicht angezeigt und nie als CLI-Argument/Klartextdatei gespeichert")


def cmd_credentials_set(args: argparse.Namespace) -> None:
    """Add a Vault variable usable by strict installer argument references."""
    from .environment import (
        die,
        ensure_initialized,
    )

    ensure_initialized(args.project, quiet=True)
    variable_name = str(args.name or "").strip()
    if not VAULT_SECRET_VARIABLE_RE.fullmatch(variable_name):
        die(
            "Installer-Geheimnis muss vault_ oder mavi_vault_ als Präfix haben "
            "und danach nur Buchstaben, Zahlen oder Unterstriche enthalten."
        )
    vault_path, _normalized_path = _store_vault_secret(
        args.project,
        variable_name=variable_name,
        secret_label=f"Geheimwert für {variable_name}",
        force=bool(getattr(args, "force", False)),
    )
    print(f"✓ '{variable_name}' verschlüsselt gespeichert: {vault_path}")
    print(f'  Katalogreferenz: "{{{{ {variable_name} }}}}"')


def redact_live_text(value: Any) -> str:
    """Kompatibilitätsname für die zentrale Secret-Schwärzung."""
    from .reports import redact_sensitive_text

    return redact_sensitive_text(value)


def _probe_process_map(
    probe: dict[str, Any] | None,
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}

    for item in (probe or {}).get("Processes", []) or []:
        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        result[pid] = item

    return result


def print_remote_live_probe(
    probe: dict[str, Any],
    previous_probe: dict[str, Any] | None = None,
) -> None:
    """
    Kompakte Remote-Sicht auf den tatsächlich laufenden Installer.
    """
    from .reports import redact_sensitive_text

    processes = probe.get("Processes", []) or []
    current_map = _probe_process_map(probe)
    previous_map = _probe_process_map(previous_probe)

    current_pids = set(current_map)
    previous_pids = set(previous_map)

    new_pids = sorted(current_pids - previous_pids)
    gone_pids = sorted(previous_pids - current_pids)

    current_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in current_map.values()
    )
    previous_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in previous_map.values()
    )

    cpu_delta = (
        current_cpu - previous_cpu
        if previous_probe is not None
        else None
    )

    print()
    print("[Mavi REMOTE LIVE] Zustand auf dem Windows-PC")
    print(
        "  Ziel-Installer läuft: "
        + ("JA" if probe.get("TargetRunning") else "NEIN")
    )
    print(
        "  Pending Reboot:       "
        + ("JA" if probe.get("PendingReboot") else "NEIN")
    )
    print(f"  Relevante Prozesse:    {len(processes)}")

    if previous_probe is not None:
        activity: list[str] = []

        if cpu_delta is not None and cpu_delta > 0.05:
            activity.append(f"CPU +{cpu_delta:.2f}s")

        if new_pids:
            activity.append(
                "neue PID(s) " + ",".join(map(str, new_pids))
            )

        if gone_pids:
            activity.append(
                "beendete PID(s) " + ",".join(map(str, gone_pids))
            )

        if activity:
            print("  Aktivität seit Probe:  " + " | ".join(activity))
        else:
            print(
                "  Aktivität seit Probe:  "
                "keine sichtbare CPU-/Prozessänderung "
                "(nicht automatisch ein Fehler)"
            )

    if processes:
        print()
        print("  PROZESSE:")

        for item in processes[:12]:
            role = str(item.get("Role") or "RELATED")
            pid = item.get("Pid", "?")
            ppid = item.get("ParentPid", "?")
            name = str(item.get("Name") or "?")
            cpu = item.get("CpuSeconds")
            ram = item.get("WorkingSetMB")
            uptime = item.get("UptimeSeconds")

            cpu_text = "?" if cpu is None else f"{float(cpu):.2f}s"
            ram_text = "?" if ram is None else f"{float(ram):.1f} MB"

            if uptime is None:
                uptime_text = "?"
            else:
                uptime_text = format_elapsed(float(uptime))

            print(
                f"    [{role:<7}] PID={pid} PPID={ppid} "
                f"{name} | Laufzeit={uptime_text} "
                f"| CPU={cpu_text} | RAM={ram_text}"
            )

            command_line = redact_live_text(
                item.get("CommandLine")
            ).strip()

            if command_line:
                if len(command_line) > 220:
                    command_line = command_line[:220] + "..."

                print(f"              CMD: {command_line}")

    logs = probe.get("Logs", []) or []

    if logs:
        print()
        print("  AKTUELLE INSTALLER-LOGS:")

        for item in logs[:8]:
            print(
                f"    {item.get('LastWriteTime', '?')} | "
                f"{item.get('SizeKB', '?')} KB | "
                f"{item.get('Path', '?')}"
            )

    events = probe.get("MsiEvents", []) or []

    if events:
        print()
        print("  LETZTE MSI-EVENTS:")

        for item in events[:5]:
            message = redact_sensitive_text(item.get("Message"))
            if len(message) > 260:
                message = message[:260] + "..."

            print(
                f"    {item.get('Time', '?')} | "
                f"ID={item.get('Id', '?')} | {message}"
            )

    print()


def _bound_ansible_session_context(
    *,
    host: str,
    ansible_session: dict[str, Any],
) -> tuple[Path, Path, Path, dict[str, str], dict[str, Any]]:
    """Prozesskontext einer bereits geöffneten Ansible-Sitzung validieren."""
    if str(ansible_session.get("host") or "") != host:
        raise RuntimeError("Die Ansible-Sitzung gehört zu einem anderen PC.")

    ansible_executable = ansible_session.get("ansible_executable")
    ansible_python = ansible_session.get("ansible_python")
    inventory_path = ansible_session.get("inventory_path")
    if not all(isinstance(value, Path) for value in (
        ansible_executable,
        ansible_python,
        inventory_path,
    )):
        raise RuntimeError("Die Ansible-Sitzung ist unvollständig.")

    raw_environment = ansible_session.get("environment")
    raw_extra_vars = ansible_session.get("extra_vars")
    if not isinstance(raw_environment, dict) or not isinstance(raw_extra_vars, dict):
        raise RuntimeError("Der Prozesskontext der Ansible-Sitzung ist ungültig.")

    environment = {
        str(key): str(value)
        for key, value in raw_environment.items()
    }
    return (
        ansible_executable,
        ansible_python,
        inventory_path,
        environment,
        dict(raw_extra_vars),
    )


def run_remote_live_probe(
    *,
    project: Path,
    host: str,
    app: dict[str, Any],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    timeout: float = 12.0,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Zweite kurze Ansible-Verbindung während der Hauptinstallation.
    Keine Änderung auf dem Ziel-PC, nur Prozess-/Log-/Reboot-Abfrage.
    """
    from .environment import project_paths
    from .reports import redact_sensitive_text

    probe_playbook = project_paths(project)["live_probe_playbook"]

    if not probe_playbook.exists():
        return None, f"Probe-Playbook fehlt: {probe_playbook}"

    if str(app.get("type") or "").lower() == "winget":
        installer_name = "winget.exe"
        remote_installer = ""
    else:
        installer_name = Path(
            str(app.get("installer") or "")
        ).name
        remote_installer = (
            "C:\\Mavi-Provisioner\\Installers\\"
            + installer_name
        )

    fd, raw_output = tempfile.mkstemp(
        prefix=".mavi-live-probe-",
        suffix=".json",
    )
    os.close(fd)

    output_path = Path(raw_output)

    try:
        output_path.unlink(missing_ok=True)

        (
            ansible_executable,
            ansible_python,
            inventory_path,
            runtime_environment,
            transport_vars,
        ) = _bound_ansible_session_context(
            host=host,
            ansible_session=ansible_session,
        )

        extra = {
            "mavi_probe_installer_path": remote_installer,
            "mavi_probe_installer_name": installer_name,
            "mavi_probe_software_name": str(
                app.get("name") or ""
            ),
            "mavi_probe_output_file": str(output_path),
        }
        extra.update(transport_vars)

        cmd = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i",
            str(inventory_path),
            str(probe_playbook),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
            "-e",
            json.dumps(extra, ensure_ascii=False),
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired:
            return (
                None,
                f"Remote-Probe nach {timeout:g}s ohne Antwort "
                "abgebrochen. Hauptinstallation läuft weiter.",
            )

        if result.returncode != 0:
            combined = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            ).strip()

            lines = [
                line.strip()
                for line in combined.splitlines()
                if line.strip()
            ]

            detail = redact_sensitive_text(" | ".join(lines[-4:]))

            if len(detail) > 700:
                detail = detail[-700:]

            return (
                None,
                "Remote-Probe fehlgeschlagen"
                + (f": {detail}" if detail else "."),
            )

        if not output_path.exists():
            return None, "Remote-Probe lieferte keine Ergebnisdatei."

        payload = output_path.read_text(
            encoding="utf-8"
        ).strip()

        if not payload:
            return None, "Remote-Probe lieferte ein leeres Ergebnis."

        parsed = json.loads(payload)

        if not isinstance(parsed, dict):
            return None, "Remote-Probe lieferte unerwartete Daten."

        return parsed, None

    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Remote-Probe konnte nicht ausgewertet werden: {exc}"

    finally:
        output_path.unlink(missing_ok=True)


def run_install_subprocess(
    cmd: list[str],
    cwd: Path,
    *,
    host: str,
    apps: dict[str, dict[str, Any]],
    ansible_session: dict[str, Any],
    status_interval: float = 10.0,
    vault_password_file: Path | None = None,
    live_probe: bool = True,
) -> int:
    """
    Ansible-Ausgabe live durchreichen.

    v0.8.5 benutzt einen Reader-Thread + Queue, damit keine bereits von
    Python gepufferten Ansible-Zeilen verloren/unsichtbar bleiben.

    Zusätzlich:
    - bei echtem Installer-Task: detaillierter Installer-Heartbeat
    - bei sonstiger Ansible-Stille: allgemeiner Heartbeat
    - KEIN automatischer Abbruch
    - KEINE manuellen Befehle auf dem Ziel-PC
    """
    from .environment import die
    from .reports import redact_sensitive_text

    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()

    _, _, _, env, _ = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    # Hilft Python-basierten Child-Prozessen, Ausgaben zeitnah zu flushen.
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=None,  # Terminal geerbt, --ask-vault-pass bleibt nutzbar.
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
        return 1

    assert proc.stdout is not None

    output_queue: "queue.Queue[str | None]" = queue.Queue()

    reader = threading.Thread(
        target=_stdout_reader,
        args=(proc.stdout, output_queue),
        name="mavi-ansible-output-reader",
        daemon=True,
    )
    reader.start()

    current_task = ""
    task_started = time.monotonic()
    last_output = time.monotonic()
    last_status = time.monotonic()
    stream_closed = False
    previous_probe: dict[str, Any] | None = None
    previous_probe_task = ""

    try:
        while True:
            try:
                item = output_queue.get(timeout=0.25)
            except queue.Empty:
                item = "__Mavi_NO_LINE__"

            if item is None:
                stream_closed = True

            elif item != "__Mavi_NO_LINE__":
                line = item
                print(redact_sensitive_text(line), end="", flush=True)

                now = time.monotonic()
                last_output = now

                clean = strip_ansi(line).strip()
                match = re.match(r"^TASK \[(.+)\]", clean)

                if match:
                    new_task = match.group(1).strip()

                    if new_task != current_task:
                        previous_probe = None
                        previous_probe_task = ""

                    current_task = new_task
                    task_started = now
                    last_status = now

            return_code = proc.poll()

            if return_code is not None and stream_closed and output_queue.empty():
                return return_code

            now = time.monotonic()

            if (
                status_interval > 0
                and now - last_status >= status_interval
                and proc.poll() is None
            ):
                if is_live_install_task(current_task):
                    print_live_install_status(
                        host=host,
                        task_name=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                    key = task_software_key(current_task)
                    app = apps.get(key, {}) if key else {}

                    if (
                        live_probe
                        and vault_password_file is not None
                        and app
                    ):
                        probe, probe_error = run_remote_live_probe(
                            project=cwd,
                            host=host,
                            app=app,
                            vault_password_file=vault_password_file,
                            ansible_session=ansible_session,
                        )

                        if probe is not None:
                            print_remote_live_probe(
                                probe,
                                previous_probe=(
                                    previous_probe
                                    if previous_probe_task == current_task
                                    else None
                                ),
                            )
                            previous_probe = probe
                            previous_probe_task = current_task

                        elif probe_error:
                            print()
                            print("[Mavi REMOTE LIVE] Detailprobe nicht verfügbar:")
                            print(f"  {probe_error}")
                            print(
                                "  Hauptinstallation läuft unverändert weiter."
                            )
                            print()
                else:
                    print_general_wait_status(
                        host=host,
                        current_task=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                last_status = time.monotonic()

    except KeyboardInterrupt:
        print()
        print(
            "Abbruch angefordert. Ansible-Prozess wird beendet. "
            "Ein bereits gestarteter Windows-Installer kann auf dem "
            "Ziel-PC noch weiterlaufen."
        )
        proc.terminate()

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return 130

    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass



def cmd_ping(args: argparse.Namespace) -> None:
    from .clients import _create_prompted_client_vault_file
    from .environment import die
    from .remote import (
        _close_client_ansible_session,
        _open_client_ansible_session,
        _temporary_single_host_inventory,
    )

    vault_password_file = _create_prompted_client_vault_file()
    ansible_session: dict[str, Any] | None = None
    temporary_inventory_path: Path | None = None
    return_code = 2
    try:
        try:
            ansible_session = _open_client_ansible_session(
                project=args.project,
                host=str(args.host),
                vault_password_file=vault_password_file,
            )
            (
                ansible_executable,
                ansible_python,
                inventory_path,
                runtime_environment,
                transport_vars,
            ) = _bound_ansible_session_context(
                host=str(args.host),
                ansible_session=ansible_session,
            )
            temporary_inventory_path = _temporary_single_host_inventory(
                args.project,
                str(args.host),
            )
            inventory_path = temporary_inventory_path
            ansible_ad_hoc = ansible_executable.with_name("ansible")
            if not ansible_ad_hoc.is_file():
                raise RuntimeError(
                    "Das ansible-Kommando fehlt in der erkannten Ansible-Umgebung."
                )

            command = [
                str(ansible_python),
                "-I",
                str(ansible_ad_hoc),
                "-i",
                str(inventory_path),
                str(args.host),
                "-m",
                "ansible.windows.win_ping",
                "--vault-password-file",
                str(vault_password_file),
            ]
            if transport_vars:
                command.extend([
                    "--extra-vars",
                    json.dumps(
                        transport_vars,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ),
                ])

            return_code = run_subprocess(
                command,
                args.project,
                env=runtime_environment,
            )
        except RuntimeError as exc:
            die(str(exc), code=2)
    finally:
        try:
            if temporary_inventory_path is not None:
                temporary_inventory_path.unlink(missing_ok=True)
        finally:
            try:
                _close_client_ansible_session(ansible_session)
            finally:
                vault_password_file.unlink(missing_ok=True)

    raise SystemExit(return_code)


def selected_apps_need_user(
    project: Path,
    names: list[str],
    all_: bool,
    catalog_name: str | None = None,
) -> bool:
    from .catalogs import get_catalog

    catalog = get_catalog(project, catalog_name)["software_catalog"]
    selected = list(catalog.values()) if all_ else [
        catalog[x] for x in names if x in catalog
    ]
    interactive_contexts = {
        "user_non_elevated",
        "user_interactive",
        "machine_interactive",
        "user_uac",
    }
    return any(
        x.get("context") in interactive_contexts
        for x in selected
    )




def _existing_target_installer_processes(
    probe: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    # Nur TARGET zählt. CHILD/RELATED allein führen bewusst nicht zum Skip.
    targets: list[dict[str, Any]] = []

    for item in (probe or {}).get("Processes", []) or []:
        if str(item.get("Role") or "").upper() != "TARGET":
            continue

        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        if pid <= 0:
            continue

        targets.append(item)

    return targets


def _probe_pid_set(probe: dict[str, Any] | None) -> set[int]:
    pids: set[int] = set()
    for item in (probe or {}).get("Processes", []) or []:
        try:
            pids.add(int(item.get("Pid")))
        except (TypeError, ValueError):
            pass
    return pids


def _new_busy_installer_processes(
    probe: dict[str, Any] | None,
    baseline_pids: set[int],
) -> list[dict[str, Any]]:
    """
    Nachlauf-Schutz für Bootstrapper:
    Nur Prozesse berücksichtigen, die beim Start dieses Pakets noch nicht
    existierten. Alte Zombies blockieren dadurch nicht den ganzen Katalog.
    """
    busy: list[dict[str, Any]] = []

    for item in (probe or {}).get("Processes", []) or []:
        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        if pid in baseline_pids:
            continue

        role = str(item.get("Role") or "").upper()
        name = str(item.get("Name") or "").lower()
        command = str(item.get("CommandLine") or "").lower()

        obvious_installer = (
            role in {"TARGET", "CHILD"}
            or name in {
                "msiexec.exe",
                "cwainstaller.exe",
                "bootstrapperhelper.exe",
            }
            or re.match(
                r"^(setup|install|installer|update|updater|bootstrap).*\\.exe$",
                name,
            )
            is not None
            or "\\ctx-" in command
        )

        if obvious_installer:
            busy.append(item)

    return busy


def wait_for_post_install_settle(
    *,
    project: Path,
    host: str,
    app: dict[str, Any],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    baseline_pids: set[int],
    max_wait_seconds: float = 90.0,
    poll_seconds: float = 5.0,
) -> tuple[bool, str]:
    """
    Verhindert, dass bei einer Katalogserie das nächste Paket startet,
    während ein vom Bootstrapper abgekoppelter Kindprozess noch arbeitet.
    """
    deadline = time.monotonic() + max(0.0, max_wait_seconds)
    announced = False
    last_busy: list[dict[str, Any]] = []

    while True:
        probe, error = run_remote_live_probe(
            project=project,
            host=host,
            app=app,
            vault_password_file=vault_password_file,
            ansible_session=ansible_session,
            timeout=12.0,
        )

        if probe is None:
            return True, (
                "Nachlauf-Probe nicht verfügbar; fahre kontrolliert fort: "
                + str(error or "unbekannter Probe-Fehler")
            )

        busy = _new_busy_installer_processes(probe, baseline_pids)
        last_busy = busy

        if not busy:
            if announced:
                print("  Nachlauf beendet. Keine neuen Installer-Prozesse mehr aktiv.")
            return True, "Installer-Nachlauf ist ruhig."

        if time.monotonic() >= deadline:
            names = ", ".join(
                f"{item.get('Name', '?')} PID={item.get('Pid', '?')}"
                for item in last_busy[:6]
            )
            return False, (
                f"Nach {max_wait_seconds:g}s laufen noch neue Installer-Prozesse: "
                + (names or "unbekannt")
            )

        if not announced:
            print()
            print("[Mavi SMART] Installer hat noch Nachlaufprozesse.")
            print("  Das nächste Programm startet erst, wenn diese fertig sind")
            print(f"  oder nach maximal {max_wait_seconds:g}s Nachlauf-Wartezeit.")
            announced = True

        names = ", ".join(
            f"{item.get('Name', '?')} PID={item.get('Pid', '?')}"
            for item in busy[:6]
        )
        print(f"  Noch aktiv: {names}")
        time.sleep(max(1.0, poll_seconds))


def wait_for_host_ready(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    max_wait_seconds: float = 180.0,
) -> bool:
    """
    Vor dem nächsten Paket kurz win_ping prüfen. Wenn ein vorheriger Installer
    Windows neu gestartet hat, wartet die Serie auf die Rückkehr des PCs.
    """
    (
        ansible_executable,
        ansible_python,
        inventory_path,
        runtime_environment,
        transport_vars,
    ) = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    ansible_ad_hoc = ansible_executable.with_name("ansible")
    if not ansible_ad_hoc.is_file():
        raise RuntimeError(
            "Das ansible-Kommando fehlt in der erkannten Ansible-Umgebung."
        )

    cmd = [
        str(ansible_python),
        "-I",
        str(ansible_ad_hoc),
        "-i",
        str(inventory_path),
        host,
        "-m",
        "ansible.windows.win_ping",
        "--vault-password-file",
        str(vault_password_file),
    ]
    if transport_vars:
        cmd.extend([
            "--extra-vars",
            json.dumps(transport_vars, ensure_ascii=True, separators=(",", ":")),
        ])

    deadline = time.monotonic() + max(1.0, max_wait_seconds)
    first_failure = True

    while True:

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=20.0,
                env=runtime_environment,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            result = None

        if result is not None and result.returncode == 0:
            if not first_failure:
                print("[Mavi SMART] Windows-PC ist wieder per Ansible erreichbar.")
            return True

        if time.monotonic() >= deadline:
            return False

        if first_failure:
            print()
            print("[Mavi SMART] Ziel-PC antwortet gerade nicht auf win_ping.")
            print("  Falls ein Installer neu gestartet hat, wartet Mavi automatisch")
            print(f"  bis zu {max_wait_seconds:g}s auf die Rückkehr des PCs.")
            first_failure = False

        time.sleep(10.0)



def _installed_precheck_payload(
    catalog: dict[str, Any],
    selected_keys: list[str],
) -> list[dict[str, Any]]:
    # Metadaten fuer den einmaligen Remote-Installed-Check bei --all.
    payload: list[dict[str, Any]] = []

    for key in selected_keys:
        app = catalog.get(key, {})
        installer = str(app.get("installer") or "")
        installer_stem = Path(installer).stem if installer else ""

        aliases: list[str] = []
        for value in (
            str(app.get("name") or ""),
            key.replace("_", " "),
            installer_stem,
            str(app.get("winget_id") or ""),
        ):
            value = value.strip()
            if value and value.casefold() not in {x.casefold() for x in aliases}:
                aliases.append(value)

        payload.append({
            "key": key,
            "name": str(app.get("name") or key),
            "type": str(app.get("type") or ""),
            "creates_path": str(app.get("creates_path") or "").strip(),
            "aliases": aliases,
        })

    return payload


def precheck_installed_apps(
    *,
    project: Path,
    host: str,
    catalog: dict[str, Any],
    selected_keys: list[str],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    timeout: float = 45.0,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    # Sicherer Precheck vor "Alle Programme".
    #
    # 1) creates_path gesetzt: exakt Test-Path. Falls der Pfad fehlt, wird
    #    NICHT auf einen moeglicherweise alten Registry-Rest ausgewichen.
    # 2) kein creates_path: konservativer Match gegen Windows Uninstall Registry.
    # 3) bei technischem Fehler wird nichts uebersprungen.

    if not selected_keys:
        return {}, None

    payload = _installed_precheck_payload(catalog, selected_keys)
    apps_json = json.dumps(payload, ensure_ascii=False)

    powershell = r'''
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AppsJson
)

function Normalize-Name {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    $v = $Value.ToLowerInvariant()
    $v = $v -replace '\.(exe|msi)$', ''
    $v = $v -replace '[^a-z0-9äöüß]+', ' '
    $v = $v -replace '\s+', ' '
    return $v.Trim()
}

function Get-CoreTokens {
    param([string]$Value)

    $normalized = Normalize-Name $Value
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @()
    }

    $noise = @(
        'setup', 'installer', 'install', 'installation',
        'windows', 'win32', 'win64', 'x86', 'x64', 'amd64',
        '32bit', '64bit', '32', '64',
        'de', 'deu', 'german', 'en', 'eng'
    )

    $tokens = @()

    foreach ($token in ($normalized -split ' ')) {
        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($noise -contains $token) {
            continue
        }

        if ($token -match '^v?\d+([._-]\d+)*$') {
            continue
        }

        if ($token -match '^\d+$') {
            continue
        }

        $tokens += $token
    }

    return @($tokens)
}

function Test-DisplayNameMatch {
    param(
        [string]$DisplayName,
        [object[]]$Aliases
    )

    $displayNormalized = Normalize-Name $DisplayName
    if ([string]::IsNullOrWhiteSpace($displayNormalized)) {
        return $false
    }

    foreach ($aliasObj in $Aliases) {
        $alias = [string]$aliasObj
        $aliasNormalized = Normalize-Name $alias

        if ([string]::IsNullOrWhiteSpace($aliasNormalized)) {
            continue
        }

        if ($displayNormalized -eq $aliasNormalized) {
            return $true
        }

        $coreTokens = @(Get-CoreTokens $alias)
        if ($coreTokens.Count -eq 0) {
            continue
        }

        $displayTokens = @($displayNormalized -split ' ')

        if ($coreTokens.Count -eq 1) {
            $single = [string]$coreTokens[0]
            if ($single.Length -ge 3 -and
                $displayTokens.Count -gt 0 -and
                $displayTokens[0] -eq $single) {
                return $true
            }
            continue
        }

        $allPresent = $true
        foreach ($token in $coreTokens) {
            if (-not ($displayTokens -contains [string]$token)) {
                $allPresent = $false
                break
            }
        }

        if ($allPresent) {
            return $true
        }
    }

    return $false
}

$registryRows = @()

$machinePaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($path in $machinePaths) {
    $scope = if ($path -like '*WOW6432Node*') { 'HKLM-32' } else { 'HKLM-64' }
    $items = @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)

    foreach ($item in $items) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item.DisplayName)) {
            $registryRows += [pscustomobject]@{
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                Scope = $scope
            }
        }
    }
}

$userRoots = @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue)

foreach ($root in $userRoots) {
    $sid = [string]$root.PSChildName

    if ($sid -notmatch '^S-1-5-21-' -and $sid -notmatch '^S-1-12-1-') {
        continue
    }

    $userPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $items = @(Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue)

    foreach ($item in $items) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item.DisplayName)) {
            $registryRows += [pscustomobject]@{
                DisplayName = [string]$item.DisplayName
                DisplayVersion = [string]$item.DisplayVersion
                Scope = "HKU:$sid"
            }
        }
    }
}

$shortcutRows = @()

$shortcutRoots = @(
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
)

foreach ($root in $userRoots) {
    $sid = [string]$root.PSChildName

    if ($sid -notmatch '^S-1-5-21-' -and $sid -notmatch '^S-1-12-1-') {
        continue
    }

    try {
        $profilePath = (Get-ItemProperty "Registry::HKEY_USERS\$sid\Volatile Environment" -ErrorAction SilentlyContinue).USERPROFILE
        if (-not [string]::IsNullOrWhiteSpace([string]$profilePath)) {
            $shortcutRoots += (Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs')
        }
    }
    catch {
    }
}

foreach ($shortcutRoot in ($shortcutRoots | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $shortcutRoot)) {
        continue
    }

    $shortcuts = @(Get-ChildItem -LiteralPath $shortcutRoot -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue)
    foreach ($shortcut in $shortcuts) {
        $shortcutRows += [pscustomobject]@{
            Name = [string]$shortcut.BaseName
            Path = [string]$shortcut.FullName
        }
    }
}

$programDirRows = @()

foreach ($programRoot in @('C:\Program Files', 'C:\Program Files (x86)')) {
    if (-not (Test-Path -LiteralPath $programRoot)) {
        continue
    }

    $dirs = @(Get-ChildItem -LiteralPath $programRoot -Directory -ErrorAction SilentlyContinue)
    foreach ($dir in $dirs) {
        $programDirRows += [pscustomobject]@{
            Name = [string]$dir.Name
            Path = [string]$dir.FullName
        }
    }
}

$apps = @($AppsJson | ConvertFrom-Json)
$result = @{}

foreach ($app in $apps) {
    $key = [string]$app.key
    $createsPath = [string]$app.creates_path

    $entry = [ordered]@{
        installed = $false
        method = 'none'
        reason = 'Kein sicherer Installed-Nachweis gefunden.'
        matched_name = ''
        matched_version = ''
        matched_scope = ''
    }

    if (-not [string]::IsNullOrWhiteSpace($createsPath)) {
        if (Test-Path -LiteralPath $createsPath) {
            $entry.installed = $true
            $entry.method = 'creates_path'
            $entry.reason = "creates_path existiert: $createsPath"
        }
        else {
            $entry.method = 'creates_path_missing'
            $entry.reason = "creates_path fehlt: $createsPath; Registry-Fallback absichtlich nicht verwendet."
        }
    }
    else {
        foreach ($row in $registryRows) {
            if (Test-DisplayNameMatch -DisplayName $row.DisplayName -Aliases @($app.aliases)) {
                $entry.installed = $true
                $entry.method = 'uninstall_registry'
                $entry.matched_name = [string]$row.DisplayName
                $entry.matched_version = [string]$row.DisplayVersion
                $entry.matched_scope = [string]$row.Scope

                $versionText = if ([string]::IsNullOrWhiteSpace([string]$row.DisplayVersion)) {
                    ''
                }
                else {
                    " Version $($row.DisplayVersion)"
                }

                $entry.reason = "Windows Uninstall-Registry: $($row.DisplayName)$versionText [$($row.Scope)]"
                break
            }
        }

        if (-not $entry.installed) {
            foreach ($shortcut in $shortcutRows) {
                if (Test-DisplayNameMatch -DisplayName $shortcut.Name -Aliases @($app.aliases)) {
                    $entry.installed = $true
                    $entry.method = 'start_menu'
                    $entry.matched_name = [string]$shortcut.Name
                    $entry.matched_scope = 'StartMenu'
                    $entry.reason = "Startmenü-Eintrag gefunden: $($shortcut.Path)"
                    break
                }
            }
        }

        if (-not $entry.installed) {
            foreach ($dir in $programDirRows) {
                if (Test-DisplayNameMatch -DisplayName $dir.Name -Aliases @($app.aliases)) {
                    $entry.installed = $true
                    $entry.method = 'program_files'
                    $entry.matched_name = [string]$dir.Name
                    $entry.matched_scope = 'ProgramFiles'
                    $entry.reason = "Programmordner gefunden: $($dir.Path)"
                    break
                }
            }
        }
    }

    $result[$key] = $entry
}

$json = $result | ConvertTo-Json -Compress -Depth 8
$bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
$marker = [Convert]::ToBase64String($bytes)

$Ansible.Result = @{
    Marker = $marker
    CheckedApps = $apps.Count
}
$Ansible.Changed = $false
'''

    play = [{
        "name": "Mavi Installed-Precheck",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Installierte Programme vor Kataloglauf erkennen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "AppsJson": apps_json,
                    },
                },
                "register": "mavi_installed_precheck",
            },
            {
                "name": "Mavi Installed-Precheck Marker",
                "ansible.builtin.debug": {
                    "msg": "Mavi_INSTALLED_PRECHECK_B64={{ mavi_installed_precheck.result.Marker }}"
                },
            },
        ],
    }]

    tmp_path: Path | None = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yml",
            prefix="mavi-installed-precheck-",
            delete=False,
        ) as fh:
            yaml.safe_dump(
                play,
                fh,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
            tmp_path = Path(fh.name)

        (
            ansible_executable,
            ansible_python,
            inventory_path,
            runtime_environment,
            transport_vars,
        ) = _bound_ansible_session_context(
            host=host,
            ansible_session=ansible_session,
        )

        cmd = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i",
            str(inventory_path),
            str(tmp_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        if transport_vars:
            cmd.extend([
                "--extra-vars",
                json.dumps(transport_vars, ensure_ascii=True, separators=(",", ":")),
            ])

        try:
            completed = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=max(5.0, timeout),
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired:
            return {}, (
                f"Installed-Precheck nach {timeout:g}s ohne Antwort. "
                "Aus Sicherheitsgruenden wird nichts uebersprungen."
            )
        except FileNotFoundError:
            return {}, (
                "ansible-playbook wurde nicht gefunden. "
                "Aus Sicherheitsgruenden wird nichts uebersprungen."
            )

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(
            r"Mavi_INSTALLED_PRECHECK_B64=([A-Za-z0-9+/=]+)",
            combined,
        )

        if completed.returncode != 0 or not match:
            detail = ""
            meaningful = [
                line.strip()
                for line in combined.splitlines()
                if line.strip()
            ]
            if meaningful:
                detail = " Letzte Ausgabe: " + meaningful[-1][:240]

            return {}, (
                "Installed-Precheck konnte nicht sicher ausgewertet werden."
                + detail
                + " Es wird nichts uebersprungen."
            )

        try:
            raw = base64.b64decode(match.group(1)).decode("utf-8")
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {}, (
                f"Installed-Precheck lieferte ungueltige Daten ({exc}). "
                "Es wird nichts uebersprungen."
            )

        if not isinstance(decoded, dict):
            return {}, (
                "Installed-Precheck lieferte kein Dictionary. "
                "Es wird nichts uebersprungen."
            )

        clean: dict[str, dict[str, Any]] = {}

        for key, value in decoded.items():
            if isinstance(value, dict):
                clean[str(key)] = value

        return clean, None

    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _build_install_command(
    *,
    project: Path,
    playbook: Path,
    host: str,
    catalog_file: Path,
    software_names: list[str],
    target_user: str,
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    check: bool,
) -> list[str]:
    extra = {
        "catalog_file": str(catalog_file),
        "install_all": False,
        "software_names": software_names,
        "target_user": target_user,
    }
    (
        ansible_executable,
        ansible_python,
        inventory_path,
        _runtime_environment,
        transport_vars,
    ) = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    extra.update(transport_vars)

    cmd = [
        str(ansible_python),
        "-I",
        str(ansible_executable),
        "-i",
        str(inventory_path),
        str(playbook),
        "--limit",
        host,
        "--vault-password-file",
        str(vault_password_file),
        "-e",
        json.dumps(extra, ensure_ascii=False),
    ]

    if check:
        cmd.append("--check")

    return cmd


def cmd_install(args: argparse.Namespace) -> None:
    from .catalogs import (
        _validate_catalog_for_persistence,
        catalog_path,
        get_catalog,
        prompt,
        resolve_catalog_name,
    )
    from .environment import (
        die,
        ensure_initialized,
        project_paths,
    )
    from .remote import (
        _close_client_ansible_session,
        _host_inventory_entry,
        _open_client_ansible_session,
    )
    from .reports import redact_sensitive_text

    ensure_initialized(args.project, quiet=True)
    p = project_paths(args.project)

    # --limit darf hier niemals ein Ansible-Muster wie "all", "windows"
    # oder "PC-*" erhalten. Nur ein exakt vorhandener Windows-Host ist gültig.
    _inventory, _windows, _host_data = _host_inventory_entry(
        args.project,
        str(args.host),
    )
    del _inventory, _windows, _host_data

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    selected_catalog_path = catalog_path(args.project, catalog_name)
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]

    print(f"Katalog: {catalog_name}")

    if args.all:
        if not catalog:
            die(f"Katalog '{catalog_name}' ist leer.")
        names: list[str] = []
    else:
        names = args.software or []
        if not names:
            die("Software angeben oder --all verwenden.")
        missing = [x for x in names if x not in catalog]
        if missing:
            die(
                f"Nicht im Katalog '{catalog_name}': "
                + ", ".join(missing)
            )

    selected_keys = list(catalog.keys()) if args.all else names
    _validate_catalog_for_persistence(
        {
            "software_catalog": {
                key: catalog[key]
                for key in selected_keys
            }
        },
        require_installer_integrity=True,
    )

    target_user = args.target_user or ""
    if (
        selected_apps_need_user(
            args.project,
            names,
            args.all,
            catalog_name,
        )
        and not target_user
        and sys.stdin.isatty()
    ):
        print(
            "\nMindestens ein Paket benötigt einen sichtbaren INTERAKTIVEN Benutzerkontext.\n"
            "Enter = aktuell am Windows-PC angemeldeten Benutzer automatisch verwenden."
        )
        target_user = prompt(
            "Zielbenutzer, z. B. EXAMPLE\\Max.Mustermann",
            "",
        )

    live_apps = {
        key: catalog[key]
        for key in selected_keys
        if key in catalog
    }

    status_interval = float(
        getattr(args, "status_interval", 10.0)
    )
    live_probe_enabled = bool(getattr(args, "live_probe", True))
    sequence_mode = len(selected_keys) > 1

    print()
    print("Mavi INSTALLPLAN")
    print("===============")

    for index, key in enumerate(selected_keys, 1):
        app = catalog.get(key, {})
        app_name = app.get("name", key)
        context = app.get("context", "machine")
        installer = (
            f"WinGet:{app.get('winget_id', '?')}"
            if str(app.get("type") or "").lower() == "winget"
            else (Path(str(app.get("installer", ""))).name or "(unbekannt)")
        )
        arguments = app.get("arguments")

        if arguments in (None, ""):
            arguments = "(KEINE)"
        else:
            arguments = redact_sensitive_text(arguments)

        print(
            f"  {index:02d}. {key}: {app_name} | "
            f"{context} | {installer} | "
            f"Parameter: {arguments}"
        )

    print()
    print(
        f"Live-Status während laufender Installer: "
        f"alle {status_interval:g}s"
    )
    print(
        "Remote-Prozess-/Log-Probe: "
        + ("AKTIV" if live_probe_enabled else "AUS")
    )

    if sequence_mode:
        print()
        print("Mavi SMART-SEQUENZ: AKTIV")
        print("  Programme werden strikt NACHEINANDER installiert.")
        if args.all and not args.check:
            print("  Bereits installierte Programme werden VOR dem Installerstart erkannt und übersprungen.")
            print("  Läuft derselbe Setup-Installer bereits, wird KEINE Doppelinstanz gestartet.")
        print("  Das nächste startet erst nach Ende/Timeout des aktuellen Pakets.")
        print("  Ein einzelner Paketfehler beendet die restliche Liste NICHT.")
        if live_probe_enabled and not args.check:
            print("  Abgekoppelte neue Installer-Kindprozesse bekommen bis zu 90s Nachlauf.")
        print("  Nach einem möglichen Windows-Neustart wartet Mavi vor dem nächsten Paket auf win_ping.")

    vault_password = getpass.getpass("Vault password: ")
    vault_password_file = create_temporary_vault_password_file(vault_password)
    ansible_session: dict[str, Any] | None = None
    try:
        ansible_session = _open_client_ansible_session(
            project=args.project,
            host=args.host,
            vault_password_file=vault_password_file,
        )
    except RuntimeError as exc:
        vault_password_file.unlink(missing_ok=True)
        die(str(exc), code=2)

    results: list[dict[str, Any]] = []

    installed_precheck: dict[str, dict[str, Any]] = {}

    try:
        if args.all and not args.check:
            print()
            print("[Mavi SMART] Prüfe zuerst, welche Programme bereits installiert sind ...")

            installed_precheck, precheck_error = precheck_installed_apps(
                project=args.project,
                host=args.host,
                catalog=catalog,
                selected_keys=selected_keys,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
                timeout=45.0,
            )

            if precheck_error:
                print("[Mavi SMART] WARNUNG: " + precheck_error)
                print("  Der Kataloglauf geht normal weiter; es wird nichts blind übersprungen.")
            else:
                installed_count = sum(
                    1
                    for value in installed_precheck.values()
                    if bool(value.get("installed"))
                )
                print(
                    f"[Mavi SMART] Installed-Precheck fertig: "
                    f"{installed_count} von {len(selected_keys)} Paket(en) "
                    "sicher als bereits installiert erkannt."
                )

        for index, key in enumerate(selected_keys, 1):
            app = catalog[key]
            app_name = str(app.get("name") or key)

            if index > 1 and sequence_mode and not args.check:
                if not wait_for_host_ready(
                    project=args.project,
                    host=args.host,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    max_wait_seconds=180.0,
                ):
                    print()
                    print("[Mavi SMART] Ziel-PC ist nach 180s nicht erreichbar.")
                    print("  Die verbleibenden Pakete können ohne Verbindung nicht sicher gestartet werden.")
                    for remaining_key in selected_keys[index - 1:]:
                        results.append({
                            "key": remaining_key,
                            "rc": 4,
                            "status": "NICHT GESTARTET",
                            "note": "Ziel-PC nicht erreichbar",
                        })
                    break

            print()
            print("=" * 72)
            print(f"Mavi PAKET {index}/{len(selected_keys)}: {key} | {app_name}")
            print("=" * 72)

            detected = installed_precheck.get(key, {}) if args.all else {}

            if bool(detected.get("installed")):
                reason = str(
                    detected.get("reason")
                    or "Bereits installiert."
                )

                print("[Mavi SMART] BEREITS INSTALLIERT -> Installer wird NICHT gestartet.")
                print("  Nachweis: " + reason)

                results.append({
                    "key": key,
                    "rc": 0,
                    "status": "BEREITS DA",
                    "note": reason,
                })
                continue

            baseline_pids: set[int] = set()
            baseline_probe: dict[str, Any] | None = None

            if sequence_mode and live_probe_enabled and not args.check:
                baseline_probe, baseline_error = run_remote_live_probe(
                    project=args.project,
                    host=args.host,
                    app=app,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    timeout=12.0,
                )

                if baseline_probe is not None:
                    baseline_pids = _probe_pid_set(baseline_probe)

                    already_running = _existing_target_installer_processes(
                        baseline_probe
                    )

                    if already_running:
                        details = ", ".join(
                            f"{item.get('Name', '?')} PID={item.get('Pid', '?')} "
                            f"Laufzeit={item.get('Runtime', '?')}"
                            for item in already_running[:6]
                        )

                        print(
                            "[Mavi SMART] INSTALLER LÄUFT BEREITS -> "
                            "kein zweites Exemplar wird gestartet."
                        )
                        print("  Gefunden: " + details)
                        print(
                            "  Paket wird übersprungen. So blockiert eine "
                            "alte/laufende Setup-Instanz nicht den Gesamtlauf."
                        )

                        results.append({
                            "key": key,
                            "rc": 0,
                            "status": "LÄUFT BEREITS",
                            "note": details,
                        })
                        continue

                elif baseline_error:
                    print(
                        "[Mavi SMART] Start-Baseline für Nachlauf nicht verfügbar: "
                        + baseline_error
                    )

            cmd = _build_install_command(
                project=args.project,
                playbook=p["playbook"],
                host=args.host,
                catalog_file=selected_catalog_path,
                software_names=[key],
                target_user=target_user,
                vault_password_file=vault_password_file,
                ansible_session=ansible_session,
                check=bool(args.check),
            )

            return_code = run_install_subprocess(
                cmd,
                args.project,
                host=args.host,
                apps={key: app},
                ansible_session=ansible_session,
                status_interval=status_interval,
                vault_password_file=vault_password_file,
                live_probe=live_probe_enabled,
            )

            if return_code == 130:
                results.append({
                    "key": key,
                    "rc": return_code,
                    "status": "ABGEBROCHEN",
                    "note": "Benutzerabbruch",
                })
                break

            settle_ok = True
            settle_note = ""
            if (
                sequence_mode
                and live_probe_enabled
                and not args.check
            ):
                settle_ok, settle_note = wait_for_post_install_settle(
                    project=args.project,
                    host=args.host,
                    app=app,
                    vault_password_file=vault_password_file,
                    ansible_session=ansible_session,
                    baseline_pids=baseline_pids,
                    max_wait_seconds=90.0,
                    poll_seconds=5.0,
                )

                if not settle_ok:
                    print()
                    print("[Mavi SMART] WARNUNG: " + settle_note)
                    print("  Die Serie läuft trotzdem weiter, damit ein Paket den gesamten Katalog nicht blockiert.")

            results.append({
                "key": key,
                "rc": return_code,
                "status": "OK" if return_code == 0 else "FEHLER",
                "note": settle_note if not settle_ok else "",
            })

            if return_code != 0 and sequence_mode:
                print()
                print(
                    f"[Mavi SMART] '{key}' endete mit Code {return_code}. "
                    "Das nächste Paket wird trotzdem versucht."
                )

    finally:
        _close_client_ansible_session(ansible_session)
        vault_password_file.unlink(missing_ok=True)

    print()
    print("Mavi INSTALL-ZUSAMMENFASSUNG")
    print("==========================")
    for item in results:
        note = f" | {item['note']}" if item.get("note") else ""
        print(
            f"  {item['status']:<15} {item['key']} "
            f"(Code {item['rc']}){note}"
        )

    if any(item.get("rc") == 130 for item in results):
        raise SystemExit(130)

    failed = [
        item for item in results
        if int(item.get("rc", 1)) != 0
    ]

    if failed:
        print()
        print(
            f"{len(failed)} von {len(results)} Paket(en) waren nicht erfolgreich. "
            "Alle sicher erreichbaren Pakete wurden trotzdem abgearbeitet."
        )
        raise SystemExit(2)

    print()
    print(f"Alle {len(results)} Paket(e) erfolgreich abgeschlossen.")
    raise SystemExit(0)

__all__ = (
    "load_inventory",
    "ensure_windows_tree",
    "cmd_host_add",
    "cmd_host_list",
    "shlex_quote",
    "run_subprocess",
    "ANSI_ESCAPE_RE",
    "strip_ansi",
    "format_elapsed",
    "is_live_install_task",
    "task_software_key",
    "print_live_install_status",
    "print_general_wait_status",
    "_stdout_reader",
    "create_temporary_vault_password_file",
    "VAULT_SECRET_VARIABLE_RE",
    "_credentials_vault_path",
    "_atomic_write_private_text",
    "_encrypted_vault_variable_block",
    "_upsert_encrypted_vault_variable",
    "_prompt_secret_twice",
    "_store_vault_secret",
    "cmd_credentials_setup",
    "cmd_credentials_set",
    "redact_live_text",
    "_probe_process_map",
    "print_remote_live_probe",
    "_bound_ansible_session_context",
    "run_remote_live_probe",
    "run_install_subprocess",
    "cmd_ping",
    "selected_apps_need_user",
    "_existing_target_installer_processes",
    "_probe_pid_set",
    "_new_busy_installer_processes",
    "wait_for_post_install_settle",
    "wait_for_host_ready",
    "_installed_precheck_payload",
    "precheck_installed_apps",
    "_build_install_command",
    "cmd_install",
)
