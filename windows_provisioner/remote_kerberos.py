# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Kerberos-Konfiguration und Identitäten.

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



def _kerberos_runtime_config_path(project: Path) -> Path:
    """Den festen, nicht systemweiten KRB5-Pfad eines Mavi-Projekts liefern."""
    from .environment import project_paths

    return project_paths(project)["kerberos_runtime_dir"] / "krb5.conf"


def _normalize_kerberos_dns_server(value: str) -> str | None:
    """Eine für direkte AD-DNS-Abfragen sichere Resolver-IP normalisieren."""
    raw = str(value or "").strip().strip("[]")
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if (
        parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_link_local
    ):
        return None
    return str(parsed)


def _configured_kerberos_dns_servers(settings: dict[str, Any]) -> list[str]:
    """Echte Controller-DNS-Server ohne DNS-Suchpfad-Mehrdeutigkeit ermitteln."""
    from .remote import (
        _normalize_kerberos_dns_server,
    )

    candidates: list[tuple[int, int, str]] = []
    seen: set[str] = set()
    sequence = 0

    def add(raw_value: str, priority: int) -> None:
        nonlocal sequence
        server = _normalize_kerberos_dns_server(raw_value)
        if not server or server in seen:
            return
        parsed = ipaddress.ip_address(server)
        # Ein lokaler Stub kann ein sinnvoller Fallback sein, darf aber einen
        # echten Link-/Global-Resolver aus resolvectl nie verdrängen.
        if parsed.is_loopback:
            priority += 100
        seen.add(server)
        sequence += 1
        candidates.append((priority, sequence, server))

    configured = str(settings.get("kerberos_dns_server", "") or "").strip()
    if configured:
        add(configured, 0)

    resolvectl = shutil.which("resolvectl")
    if resolvectl:
        try:
            result = subprocess.run(
                [resolvectl, "dns"],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            resolver_output = (result.stdout or "") + "\n" + (result.stderr or "")
            for token in re.findall(r"[0-9A-Fa-f:.%]+", resolver_output):
                add(token, 10)

    resolv_conf = Path("/etc/resolv.conf")
    try:
        for line in resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"^\s*nameserver\s+(\S+)", line, flags=re.IGNORECASE)
            if match:
                add(match.group(1), 20)
    except OSError:
        pass

    return [server for _, _, server in sorted(candidates)]


def _direct_dns_query(
    dig_executable: str,
    dns_server: str,
    query_name: str,
    record_type: str,
) -> list[str]:
    """Eine kurze, shell-freie DNS-Abfrage direkt an einen vertrauten Resolver senden."""
    try:
        result = subprocess.run(
            [
                dig_executable,
                f"@{dns_server}",
                "+time=2",
                "+tries=1",
                "+short",
                query_name,
                record_type,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]


def _discover_kerberos_kdc_endpoints(settings: dict[str, Any]) -> tuple[str, ...]:
    """AD-KDCs via SRV und A direkt am tatsächlich konfigurierten DNS auflösen."""
    from .remote import (
        _configured_kerberos_dns_servers,
        _direct_dns_query,
        _normalize_winrm_dns_name,
    )

    domain = _normalize_winrm_dns_name(
        str(settings.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    dig_executable = shutil.which("dig")
    if not dig_executable:
        raise RuntimeError(
            "Für die sichere direkte AD-KDC-Ermittlung fehlt 'dig' auf dem Controller. "
            "Mavi aktiviert ohne bestätigten KDC keinen WinRM-Kerberos-Transport."
        )
    dns_servers = _configured_kerberos_dns_servers(settings)
    if not dns_servers:
        raise RuntimeError(
            "Kein verwendbarer DNS-Server für die direkte AD-KDC-Ermittlung gefunden. "
            "Mavi aktiviert ohne bestätigten KDC keinen WinRM-Kerberos-Transport."
        )

    srv_records: list[tuple[int, int, int, str, int, str]] = []
    for resolver_index, dns_server in enumerate(dns_servers):
        for service in ("_kerberos._tcp", "_kerberos._udp"):
            query_name = f"{service}.{domain}"
            for line in _direct_dns_query(dig_executable, dns_server, query_name, "SRV"):
                parts = line.split()
                if len(parts) != 4:
                    continue
                try:
                    priority = int(parts[0])
                    weight = int(parts[1])
                    port = int(parts[2])
                except ValueError:
                    continue
                if not (0 <= priority <= 65535 and 0 <= weight <= 65535 and 1 <= port <= 65535):
                    continue
                try:
                    target = _normalize_winrm_dns_name(parts[3], label="AD-KDC aus DNS-SRV")
                except ValueError:
                    continue
                if target == domain or not target.endswith("." + domain):
                    continue
                srv_records.append((priority, -weight, resolver_index, target, port, dns_server))

    endpoints: list[str] = []
    seen_endpoints: set[str] = set()
    for _, _, _, target, port, dns_server in sorted(srv_records):
        for answer in _direct_dns_query(dig_executable, dns_server, target, "A"):
            try:
                address = ipaddress.ip_address(answer)
            except ValueError:
                continue
            if (
                address.version != 4
                or address.is_unspecified
                or address.is_multicast
                or address.is_loopback
                or address.is_link_local
            ):
                continue
            endpoint = str(address) if port == 88 else f"{address}:{port}"
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                endpoints.append(endpoint)

    if not endpoints:
        raise RuntimeError(
            "Der AD-DNS lieferte keinen verwendbaren IPv4-KDC für "
            f"{domain}. Mavi aktiviert WinRM-Kerberos ohne bestätigten KDC nicht."
        )
    return tuple(endpoints)


def _activate_existing_kerberos_runtime_config(project: Path) -> Path | None:
    """Vorhandene Mavi-Kerberos-Konfiguration nur für diesen Mavi-Prozess binden."""

    from .remote import (
        _kerberos_runtime_config_path,
    )

    path = _kerberos_runtime_config_path(project)
    if not path.is_file():
        return None
    # KRB5_CONFIG wird nur in diesem Python-Prozess und dessen Kindern gesetzt;
    # die Login-Shell, /etc/krb5.conf und sonstige Programme bleiben unverändert.
    os.environ["KRB5_CONFIG"] = str(path)
    return path


def _prepare_kerberos_runtime_config(
    project: Path,
    settings: dict[str, Any],
) -> tuple[Path, tuple[str, ...]]:
    """Eine restriktive KRB5-Konfiguration mit direkt bestätigten AD-KDCs schreiben."""
    from .remote import (
        _discover_kerberos_kdc_endpoints,
        _kerberos_runtime_config_path,
        _normalize_winrm_dns_name,
    )

    from .openssh import _atomic_write_bytes

    domain = _normalize_winrm_dns_name(
        str(settings.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    if "." not in domain:
        raise ValueError("winrm_https.domain_suffix muss eine AD-Domäne wie example.invalid sein.")

    # Kerberos-Realm-Namen sind konventionsgemäß großgeschrieben. Der direkte
    # SRV-Lookup erfolgt hier einmal an den echten AD-DNS-Server; danach nutzt
    # der Ansible-Worker nur numerisch bestätigte KDC-Endpunkte und hängt nicht
    # an einem fehlerhaften lokalen Resolver-/Stub-Pfad.
    realm = domain.upper()
    kdc_endpoints = _discover_kerberos_kdc_endpoints(settings)
    path = _kerberos_runtime_config_path(project)
    kdc_lines = "".join(f"        kdc = {endpoint}\n" for endpoint in kdc_endpoints)
    content = (
        "# Mavi-managed Kerberos runtime configuration; contains no secrets.\n"
        "# Used only by Mavi and its child processes; never copied to /etc.\n"
        "[libdefaults]\n"
        f"    default_realm = {realm}\n"
        "    dns_lookup_kdc = false\n"
        "    dns_lookup_realm = false\n"
        "    rdns = false\n"
        "\n"
        "[realms]\n"
        f"    {realm} = {{\n"
        f"{kdc_lines}"
        "    }\n"
        "\n"
        "[domain_realm]\n"
        f"    {domain} = {realm}\n"
        f"    .{domain} = {realm}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    _atomic_write_bytes(path, content.encode("utf-8"), mode=0o600)
    os.environ["KRB5_CONFIG"] = str(path)
    return path, kdc_endpoints


def _winrm_https_target_identity(
    host: str,
    host_data: dict[str, Any],
    settings: dict[str, Any],
) -> dict[str, Any]:
    """FQDN und SANs aus dem vorhandenen Inventory-Host sicher ableiten."""
    from .remote import (
        _normalize_winrm_dns_name,
    )

    raw_host = str(host or "").strip().rstrip(".")
    if not raw_host:
        raise ValueError("Der Inventory-Hostname für WinRM HTTPS fehlt.")
    base_label = raw_host.split(".", 1)[0]
    short_name = _normalize_winrm_dns_name(base_label, label="Windows-Computername")

    configured_fqdn = str(host_data.get("mavi_winrm_fqdn", "") or "").strip()
    if configured_fqdn:
        fqdn = _normalize_winrm_dns_name(configured_fqdn, label="mavi_winrm_fqdn")
    elif "." in raw_host:
        fqdn = _normalize_winrm_dns_name(raw_host, label="Inventory-Hostname")
    else:
        fqdn = f"{short_name}.{settings['domain_suffix']}"

    suffix = "." + str(settings["domain_suffix"])
    if not fqdn.endswith(suffix) or fqdn == str(settings["domain_suffix"]):
        raise ValueError(
            f"WinRM-FQDN '{fqdn}' liegt nicht in der konfigurierten Domäne {settings['domain_suffix']}."
        )

    endpoint = str(host_data.get("ansible_host", "") or host).strip().rstrip(".")
    if not endpoint:
        raise ValueError("ansible_host fehlt für den Windows-PC.")

    dns_sans: list[str] = []
    ip_sans: list[str] = []
    for name in (fqdn, short_name):
        if name not in dns_sans:
            dns_sans.append(name)
    try:
        parsed_endpoint = ipaddress.ip_address(endpoint)
    except ValueError:
        endpoint_dns = _normalize_winrm_dns_name(endpoint, label="ansible_host")
        if endpoint_dns not in dns_sans:
            dns_sans.append(endpoint_dns)
    else:
        if (
            parsed_endpoint.is_unspecified
            or parsed_endpoint.is_multicast
            or parsed_endpoint.is_loopback
            or parsed_endpoint.is_link_local
        ):
            raise ValueError("ansible_host für WinRM HTTPS darf keine Sonder- oder Wildcard-IP sein.")
        ip_sans.append(str(parsed_endpoint))

    return {
        "fqdn": fqdn,
        "short_name": short_name,
        "endpoint": endpoint,
        "dns_sans": dns_sans,
        "ip_sans": ip_sans,
    }


def _kerberos_principal_for_host(
    windows: dict[str, Any],
    host_data: dict[str, Any],
    settings: dict[str, Any],
    *,
    vault_ansible_user: str = "",
) -> str:
    """UPN aus Konfiguration oder dem bereits entschlüsselten Inventory bestimmen."""
    from .remote import (
        _effective_host_var,
    )

    configured = str(settings.get("kerberos_principal", "") or "").strip()
    source = (
        configured
        or str(_effective_host_var(windows, host_data, "ansible_user", "") or "").strip()
        or str(vault_ansible_user or "").strip()
    )
    if not source:
        raise ValueError(
            "Kein Kerberos-Principal auffindbar. ansible_user als UPN setzen oder "
            "winrm_https.kerberos_principal konfigurieren."
        )
    if "@" in source:
        principal = source
    else:
        account = source.rsplit("\\", 1)[-1].strip()
        if not account:
            raise ValueError("ansible_user enthält keinen verwendbaren Kerberos-Kontonamen.")
        principal = f"{account}@{settings['domain_suffix']}"
    if (
        any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in principal)
        or principal.count("@") != 1
    ):
        raise ValueError("Der Kerberos-Principal ist ungültig.")
    account, realm = principal.rsplit("@", 1)
    if not account or realm.casefold().rstrip(".") != str(settings["domain_suffix"]).casefold():
        raise ValueError(
            f"Der Kerberos-Principal muss zur Mavi-Domäne {settings['domain_suffix']} gehören."
        )
    # DNS-Domänennamen sind nicht case-sensitiv, Kerberos-Realm-Namen jedoch
    # schon. Der gültige AD-Realm bleibt deshalb immer das kanonische Uppercase
    # der zentral geprüften Mavi-Domäne — unabhängig davon, wie ein Vault-UPN
    # oder ansible_user geschrieben wurde.
    return f"{account}@{str(settings['domain_suffix']).upper()}"


def _vault_host_context(
    project: Path,
    host: str,
    vault_password_file: Path,
    *,
    inventory_path: Path | None = None,
) -> dict[str, Any]:
    """Hostvariablen ausschließlich durch Ansible selbst entschlüsseln.

    group_vars (auch Vault-Dateien) stehen absichtlich nicht im Roh-YAML des
    Inventars. Die
    vollständige JSON-Antwort wird nie ausgegeben, weil sie Secrets enthalten
    kann.
    """
    from .remote import (
        _ansible_controller_python,
        _ansible_inventory_executable,
        _ansible_runtime_environment,
    )

    from .environment import project_paths

    ansible_python = _ansible_controller_python()
    executable = _ansible_inventory_executable()
    effective_inventory = inventory_path or project_paths(project)["inventory"]
    try:
        result = subprocess.run(
            [
                str(ansible_python),
                "-I",
                str(executable),
                "-i", str(effective_inventory),
                "--host", host,
                "--vault-password-file", str(vault_password_file),
            ],
            cwd=str(project),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=_ansible_runtime_environment(ansible_python),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            "Der entschlüsselte Ansible-Hostkontext konnte nicht gelesen werden."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            "Ansible konnte den Hostkontext mit dem eingegebenen Vault-Passwort nicht entschlüsseln."
        )
    try:
        resolved = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Ansible lieferte keinen lesbaren entschlüsselten Hostkontext.") from exc
    if not isinstance(resolved, dict):
        raise RuntimeError("Ansible lieferte einen ungültigen entschlüsselten Hostkontext.")
    return resolved


def _vault_ansible_user_for_host(project: Path, host: str, vault_password_file: Path) -> str:
    """Liest ausschließlich ansible_user aus dem von Ansible entschlüsselten Host-Kontext."""
    from .remote import (
        _vault_host_context,
    )

    resolved = _vault_host_context(project, host, vault_password_file)
    value = resolved.get("ansible_user", "")
    return value if isinstance(value, str) else ""


def _kerberos_cache_connection_overrides() -> dict[str, str]:
    """PSRP auf die Default-Credential des privaten Kerberos-Caches festlegen."""
    return {
        "ansible_user": "",
        "ansible_psrp_user": "",
        "ansible_password": "",
        "ansible_psrp_password": "",
        "ansible_winrm_pass": "",
        "ansible_winrm_password": "",
    }
