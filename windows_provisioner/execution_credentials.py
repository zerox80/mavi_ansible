# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Vault- und Zugangsdatenverwaltung."""

from __future__ import annotations


from ._dependencies import (
    Any,
    Path,
    argparse,
    getpass,
    os,
    re,
    secrets,
    shutil,
    subprocess,
    sys,
    tempfile,
)


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

    from .execution import (
        create_temporary_vault_password_file,
    )
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

    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )
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
