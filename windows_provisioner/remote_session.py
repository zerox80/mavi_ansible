# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Temporäre Inventories und Kerberos-Sitzungen.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    base64,
    binascii,
    datetime,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    ssl,
    subprocess,
    tempfile,
    timezone,
)



def _temporary_psrp_vault_inventory(project: Path, host: str) -> Path | None:
    """Leere SSH-Credential-Overrides nur für einen PSRP-Probe-Lauf ausblenden.

    Beim SSH-Umbau setzt Mavi absichtlich leere Hostwerte, damit das SSH-Plugin
    niemals auf ein geerbtes Vault-Passwort zurückgreift. Für PSRP/Kerberos
    wären genau diese leeren Werte aber ein Host-Override über das echte
    Gruppen-Vault-Passwort. Diese private Inventarkopie entfernt deshalb
    ausschließlich leere SSH-Maskierungen; sie enthält nie entschlüsselte
    Zugangsdaten und wird nach dem einzelnen Probe-Lauf gelöscht.
    """
    from .remote import (
        _host_inventory_entry,
    )

    from .environment import (
        atomic_write_yaml,
        project_paths,
    )

    inventory, _windows, host_data = _host_inventory_entry(project, host)
    removed = False
    for key in (
        "ansible_password",
        "ansible_ssh_pass",
        "ansible_ssh_password",
        "ansible_psrp_password",
        "ansible_winrm_pass",
        "ansible_winrm_password",
    ):
        value = host_data.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            if key in host_data:
                host_data.pop(key, None)
                removed = True
    if not removed:
        return None

    source_path = project_paths(project)["inventory"]
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".mavi-psrp-vault-",
        suffix=".yml",
        dir=str(source_path.parent),
    )
    os.close(descriptor)
    temporary_path = Path(raw_path)
    try:
        # Derselbe Inventarordner ist wichtig: Ansible findet dort weiterhin
        # die vorhandenen group_vars und damit den verschlüsselten Vault-Wert.
        atomic_write_yaml(temporary_path, inventory)
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _retain_single_inventory_host(inventory: dict[str, Any], host: str) -> None:
    """Alle statischen Inventory-Hostlisten auf genau einen Alias beschränken."""

    def prune_group(group: Any) -> None:
        if not isinstance(group, dict):
            return
        raw_hosts = group.get("hosts")
        if isinstance(raw_hosts, dict):
            group["hosts"] = {
                name: value
                for name, value in raw_hosts.items()
                if str(name) == host
            }
        elif isinstance(raw_hosts, list):
            group["hosts"] = [name for name in raw_hosts if str(name) == host]
        children = group.get("children")
        if isinstance(children, dict):
            for child in children.values():
                prune_group(child)

    for top_level_group in inventory.values():
        prune_group(top_level_group)


def _temporary_single_host_inventory(
    project: Path,
    host: str,
    *,
    inherit_vault_psrp_credentials: bool = False,
) -> Path:
    """Private Inventarkopie erzeugen, in der nur der Zielhost existiert.

    Dadurch bleibt der Aufruf auch dann ein echter Ein-Host-Lauf, wenn der
    Inventory-Alias mit einem Ansible-Pattern oder Gruppennamen kollidiert.
    """
    from .remote import (
        _host_inventory_entry,
        _retain_single_inventory_host,
    )

    from .environment import (
        atomic_write_yaml,
        project_paths,
    )

    inventory, _windows, host_data = _host_inventory_entry(project, host)
    if inherit_vault_psrp_credentials:
        for key in (
            "ansible_password",
            "ansible_ssh_pass",
            "ansible_ssh_password",
            "ansible_psrp_password",
            "ansible_winrm_pass",
            "ansible_winrm_password",
        ):
            value = host_data.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                host_data.pop(key, None)

    _retain_single_inventory_host(inventory, host)
    source_path = project_paths(project)["inventory"]
    descriptor, raw_path = tempfile.mkstemp(
        prefix=".mavi-single-host-",
        suffix=".yml",
        dir=str(source_path.parent),
    )
    os.close(descriptor)
    temporary_path = Path(raw_path)
    try:
        # Neben hosts.yml bleiben group_vars und Vault-Auflösung unverändert
        # erreichbar; nur weitere Inventory-Hosts fehlen in dieser Kopie.
        atomic_write_yaml(temporary_path, inventory)
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _vault_psrp_password_for_host(project: Path, host: str, vault_password_file: Path) -> str:
    """Das bestehende Vault-Passwort nur im Speicher für einen Kerberos-TGT lesen.

    Das SSH-Inventar darf absichtlich leere Passwortwerte enthalten. Für diese
    eine Abfrage werden ausschließlich solche leeren Maskierungen entfernt,
    damit Ansible den regulären Vault-Wert auflöst. Die entschlüsselte Antwort
    bleibt im Arbeitsspeicher und wird nie protokolliert oder gespeichert.
    """
    from .remote import (
        _temporary_psrp_vault_inventory,
        _vault_host_context,
    )

    from .environment import project_paths

    temporary_inventory_path: Path | None = None
    try:
        temporary_inventory_path = _temporary_psrp_vault_inventory(project, host)
        resolved = _vault_host_context(
            project,
            host,
            vault_password_file,
            inventory_path=temporary_inventory_path or project_paths(project)["inventory"],
        )
    finally:
        if temporary_inventory_path is not None:
            temporary_inventory_path.unlink(missing_ok=True)

    for key in ("ansible_password", "ansible_winrm_pass", "ansible_winrm_password"):
        value = resolved.get(key)
        if isinstance(value, str) and value:
            # `kinit` bekommt die Kennung über stdin; Zeilenumbrüche würden
            # dessen Passwortdialog mehrdeutig machen und sind für dieses
            # automatisierte Verfahren absichtlich nicht zugelassen.
            if "\r" in value or "\n" in value:
                raise RuntimeError(
                    "Das entschlüsselte Ansible-Passwort enthält einen Zeilenumbruch und kann nicht sicher "
                    "für den automatischen Kerberos-Ticket-Schritt verwendet werden."
                )
            return value
    raise RuntimeError(
        "Im entschlüsselten Ansible-Vault fehlt ein nichtleeres ansible_password "
        "(alternativ ansible_winrm_pass/ansible_winrm_password) für Kerberos."
    )


def _discard_kerberos_ticket_cache(cache_directory: Path, cache_path: Path) -> None:
    """Den ausschließlich von Mavi angelegten Datei-Cache bestmöglich entfernen."""
    try:
        cache_path.unlink(missing_ok=True)
    finally:
        try:
            cache_directory.rmdir()
        except OSError:
            # Ein fehlgeschlagener Cleanup darf keinen möglicherweise
            # erfolgreichen, bereits sicher abgeschlossenen Nachweis verfälschen.
            pass


def _verify_kerberos_ticket_cache(
    *,
    cache_path: Path,
    ansible_python: Path,
    target_fqdn: str,
) -> str:
    """TGT und passenden host/FQDN-Dienstticketpfad im echten Ansible-Python prüfen.

    `creds=None` ist hier absichtlich: Genau diesen Default-CCache-Pfad benutzt
    pyspnego für einen leeren CredentialCache ebenfalls. Ein expliziter
    Benutzername würde GSSAPI dagegen auf eine benannte Cache-Credential
    festlegen und kann bei AD-Namenskanonisierung an "Matching credential not
    found" scheitern, obwohl das TGT gültig ist.
    """
    from .remote import (
        _ansible_runtime_environment,
        _normalize_winrm_dns_name,
    )

    from .reports import redact_sensitive_text

    fqdn = _normalize_winrm_dns_name(target_fqdn, label="Kerberos-Ziel-FQDN")
    if not cache_path.is_file() or cache_path.stat().st_size <= 0:
        raise RuntimeError("Der private Kerberos-Ticket-Cache fehlt oder ist leer.")

    target_literal = json.dumps(f"host@{fqdn}")
    probe = (
        "import gssapi\n"
        "mech = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')\n"
        "credential = gssapi.Credentials(usage='initiate', mechs=[mech])\n"
        "principal = str(credential.name).strip()\n"
        "if not principal: raise RuntimeError('Kerberos-Cache enthält keinen Initiator-Principal')\n"
        f"target = gssapi.Name({target_literal}, name_type=gssapi.NameType.hostbased_service)\n"
        "context = gssapi.SecurityContext(name=target, mech=mech, usage='initiate')\n"
        "token = context.step()\n"
        "if not token: raise RuntimeError('KDC lieferte kein Dienstticket für den WinRM-SPN')\n"
        "print(principal)\n"
    )
    environment = _ansible_runtime_environment(ansible_python)
    environment["KRB5CCNAME"] = f"FILE:{cache_path}"
    try:
        result = subprocess.run(
            [str(ansible_python), "-I", "-c", probe],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis hat nicht rechtzeitig geantwortet."
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis konnte nicht gestartet werden: "
            f"{redact_sensitive_text(exc)}"
        ) from exc

    if result.returncode != 0:
        detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
        raise RuntimeError(
            f"Der private Kerberos-Ticket-Cache konnte kein host/{fqdn}-Dienstticket verwenden"
            + (f": {detail}" if detail else ".")
        )
    principal = (result.stdout or "").strip()
    if not re.fullmatch(r"[^@\s]+@[A-Za-z0-9.-]+", principal):
        raise RuntimeError(
            "Der Kerberos-Dienstticketnachweis lieferte keinen gültigen Cache-Principal."
        )
    return principal


def _acquire_vault_kerberos_ticket(
    project: Path,
    *,
    host: str,
    vault_password_file: Path,
    kerberos_principal: str,
    ansible_python: Path,
    target_fqdn: str,
) -> tuple[Path, Path, str]:
    """TGT in einem privaten Einmal-Cache erzeugen, nie in der Login-Session."""
    from .remote import (
        _ansible_runtime_environment,
        _discard_kerberos_ticket_cache,
        _vault_psrp_password_for_host,
        _verify_kerberos_ticket_cache,
    )

    from .reports import redact_sensitive_text

    principal = str(kerberos_principal or "").strip()
    if not principal or principal.count("@") != 1:
        raise ValueError("Für den automatischen Kerberos-Nachweis fehlt ein gültiger UPN-Principal.")
    kinit = shutil.which("kinit")
    if not kinit:
        raise RuntimeError(
            "kinit fehlt auf dem Ansible-Server. Mavi kann ohne einen echten Kerberos-TGT keinen "
            "Kerberos-only-WinRM-Transport aktivieren."
        )

    password = _vault_psrp_password_for_host(project, host, vault_password_file)
    cache_directory = Path(tempfile.mkdtemp(prefix=".mavi-kerberos-ticket-"))
    cache_path = cache_directory / "krb5cc"
    cache_name = f"FILE:{cache_path}"
    try:
        if os.name != "nt":
            os.chmod(cache_directory, 0o700)
        environment = _ansible_runtime_environment(ansible_python)
        environment["KRB5CCNAME"] = cache_name
        try:
            result = subprocess.run(
                [str(kinit), "-c", cache_name, principal],
                input=password + "\n",
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Der automatische Kerberos-Ticket-Schritt hat nicht rechtzeitig geantwortet.") from exc
        except OSError as exc:
            raise RuntimeError(
                f"Der automatische Kerberos-Ticket-Schritt konnte nicht gestartet werden: "
                f"{redact_sensitive_text(exc)}"
            ) from exc
        finally:
            # Keine Referenz auf das entschlüsselte Vault-Passwort länger als
            # bis zur unmittelbaren stdin-Übergabe behalten.
            password = ""

        if result.returncode != 0:
            detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
            raise RuntimeError(
                "Der automatische Kerberos-Ticket-Schritt wurde vom AD abgelehnt"
                + (f": {detail}" if detail else ".")
            )
        if not cache_path.is_file() or cache_path.stat().st_size <= 0:
            raise RuntimeError("Der automatische Kerberos-Ticket-Schritt hat keinen verwendbaren Ticket-Cache erzeugt.")
        if os.name != "nt":
            os.chmod(cache_path, 0o600)
        cache_principal = _verify_kerberos_ticket_cache(
            cache_path=cache_path,
            ansible_python=ansible_python,
            target_fqdn=target_fqdn,
        )
        return cache_directory, cache_path, cache_principal
    except BaseException:
        _discard_kerberos_ticket_cache(cache_directory, cache_path)
        raise


def _open_client_ansible_session(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
) -> dict[str, Any]:
    """Gebundene Ansible-Laufzeit samt privatem Kerberos-Cache öffnen."""

    from .remote import (
        _kerberos_cache_connection_overrides,
    )
    from .remote import (
        _acquire_vault_kerberos_ticket,
        _ansible_playbook_runtime,
        _ansible_runtime_environment,
        _effective_host_var,
        _host_inventory_entry,
        _saved_winrm_https_transport,
    )

    from .environment import project_paths
    from .reports import redact_sensitive_text

    _inventory, windows, host_data = _host_inventory_entry(project, host)
    ansible_executable, ansible_python = _ansible_playbook_runtime()
    session: dict[str, Any] = {
        "host": host,
        "ansible_executable": ansible_executable,
        "ansible_python": ansible_python,
        "inventory_path": project_paths(project)["inventory"],
        "environment": _ansible_runtime_environment(ansible_python),
        "extra_vars": {},
        "kerberos_ticket_directory": None,
        "kerberos_ticket_path": None,
    }

    connection = str(
        _effective_host_var(windows, host_data, "ansible_connection", "psrp")
        or "psrp"
    ).strip().lower()
    auth = str(
        _effective_host_var(windows, host_data, "ansible_psrp_auth", "")
        or ""
    ).strip().lower()
    saved_state = host_data.get("mavi_winrm_https")
    saved_kerberos = (
        isinstance(saved_state, dict)
        and saved_state.get("kerberos_verified") is True
        and str(saved_state.get("auth", "") or "").strip().lower() == "kerberos"
    )
    if connection != "psrp" or (auth != "kerberos" and not saved_kerberos):
        return session

    protocol = str(
        _effective_host_var(windows, host_data, "ansible_psrp_protocol", "") or ""
    ).strip().lower()
    if protocol and protocol != "https":
        raise RuntimeError(
            "Die Client-Ansible-Sitzung verwendet PSRP/Kerberos nur mit dem gespeicherten HTTPS-Endpunkt."
        )

    try:
        _settings, fqdn, _ca_cert, kerberos_principal = _saved_winrm_https_transport(
            project,
            host_data,
        )
        cache_directory, cache_path, cache_principal = _acquire_vault_kerberos_ticket(
            project,
            host=host,
            vault_password_file=vault_password_file,
            kerberos_principal=kerberos_principal,
            ansible_python=ansible_python,
            target_fqdn=fqdn,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        raise RuntimeError(
            "Die private Kerberos-Sitzung für die Client-Aktion konnte nicht "
            f"vorbereitet werden: {redact_sensitive_text(exc)}"
        ) from exc

    session["kerberos_ticket_directory"] = cache_directory
    session["kerberos_ticket_path"] = cache_path
    session["environment"]["KRB5CCNAME"] = f"FILE:{cache_path}"
    session["extra_vars"] = _kerberos_cache_connection_overrides()
    print(
        f"  ✓ Private Kerberos-Sitzung: {cache_principal}; "
        f"host/{fqdn} ist bestätigt."
    )
    return session


def _close_client_ansible_session(session: dict[str, Any] | None) -> None:
    """Den von der äußeren Client-Sitzung besessenen Ticket-Cache entfernen."""
    from .remote import (
        _discard_kerberos_ticket_cache,
    )

    if session is None:
        return
    cache_directory = session.get("kerberos_ticket_directory")
    cache_path = session.get("kerberos_ticket_path")
    if isinstance(cache_directory, Path) and isinstance(cache_path, Path):
        _discard_kerberos_ticket_cache(cache_directory, cache_path)
    session["kerberos_ticket_directory"] = None
    session["kerberos_ticket_path"] = None
    environment = session.get("environment")
    if isinstance(environment, dict):
        environment.pop("KRB5CCNAME", None)
