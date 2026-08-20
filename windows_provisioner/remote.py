# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Transport-, Kerberos- und WinRM-Grundlagen."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    base64,
    binascii,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    subprocess,
    tempfile,
)

def get_ssh_settings(project: Path) -> dict[str, Any]:
    """Mavi-SSH-Einstellungen laden, ohne bestehende Projekte zu verbiegen."""
    from .environment import (
        load_yaml,
        project_paths,
    )

    p = project_paths(project)
    config = load_yaml(p["config"], {}) or {}
    ssh_cfg = config.get("ssh", {}) or {}

    raw_key = str(ssh_cfg.get("private_key", "") or "").strip()
    key_path = Path(raw_key).expanduser() if raw_key else p["ssh_key"]

    try:
        port = int(ssh_cfg.get("port", 22) or 22)
    except (TypeError, ValueError):
        port = 22

    if not 1 <= port <= 65535:
        port = 22

    raw_known_hosts = str(ssh_cfg.get("known_hosts", "") or "").strip()
    known_hosts = Path(raw_known_hosts).expanduser() if raw_known_hosts else p["ssh_known_hosts"]

    return {
        "private_key": key_path,
        "public_key": Path(str(key_path) + ".pub"),
        "known_hosts": known_hosts,
        "port": port,
    }


def _ssh_environment_marker(project: Path) -> str:
    """Stable project-scoped marker; never matches keys from another project."""
    project_identity = str(project.expanduser().resolve()).casefold().encode("utf-8")
    digest = hashlib.sha256(project_identity).hexdigest()[:16]
    return f"mavi-provisioner-{digest}"


def _host_inventory_entry(project: Path, host: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    from .environment import die
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    inv = load_inventory(project)
    windows = ensure_windows_tree(inv)
    hosts = windows.get("hosts", {}) or {}
    if host not in hosts:
        die(f"PC '{host}' ist nicht im Inventory vorhanden.")
    data = hosts[host] or {}
    if not isinstance(data, dict):
        data = {}
        hosts[host] = data
    return inv, windows, data


def _effective_host_var(windows: dict[str, Any], host_data: dict[str, Any], key: str, default: Any = None) -> Any:
    if key in host_data:
        return host_data.get(key)
    return (windows.get("vars", {}) or {}).get(key, default)


def _connection_label(windows: dict[str, Any], host_data: dict[str, Any]) -> str:
    connection = str(_effective_host_var(windows, host_data, "ansible_connection", "psrp") or "psrp").lower()
    if connection == "ssh":
        return "SSH"
    if connection == "winrm":
        return "WinRM"
    if connection == "psrp":
        return "PSRP"
    return connection.upper()


def _clear_host_transport_vars(host_data: dict[str, Any]) -> None:
    for key in (
        "ansible_connection",
        "ansible_port",
        "ansible_shell_type",
        "ansible_ssh_private_key_file",
        "ansible_ssh_common_args",
        "ansible_ssh_host_key_checking",
        "ansible_ssh_password_mechanism",
        "ansible_password",
        "ansible_ssh_pass",
        "ansible_ssh_password",
        "ansible_psrp_protocol",
        "ansible_psrp_auth",
        "ansible_psrp_cert_validation",
        "ansible_psrp_ca_cert",
        "ansible_psrp_cert_trust_path",
        "ansible_psrp_message_encryption",
        "ansible_psrp_ignore_proxy",
        "ansible_psrp_negotiate_hostname_override",
        "ansible_psrp_negotiate_service",
        "ansible_psrp_negotiate_send_cbt",
    ):
        host_data.pop(key, None)


def _apply_ssh_transport(
    project: Path,
    host_data: dict[str, Any],
    *,
    key_path: Path | None = None,
    port: int | None = None,
) -> tuple[Path, int]:
    from .environment import die
    from .execution import shlex_quote

    settings = get_ssh_settings(project)
    resolved_key = (key_path or settings["private_key"]).expanduser().resolve()
    resolved_port = int(port or settings["port"] or 22)
    if not 1 <= resolved_port <= 65535:
        die("SSH-Port muss zwischen 1 und 65535 liegen.")

    _clear_host_transport_vars(host_data)
    known_hosts = Path(settings["known_hosts"]).expanduser().resolve()

    host_data["ansible_connection"] = "ssh"
    host_data["ansible_shell_type"] = "powershell"
    host_data["ansible_port"] = resolved_port
    host_data["ansible_ssh_private_key_file"] = str(resolved_key)

    # SSH muss bei Mavi wirklich Key-only sein. Der Windows-Gruppenbereich enthält
    # häufig ein geerbtes/vaulted ansible_password für PSRP. Ohne expliziten
    # Host-Override interpretiert das SSH-Plugin dieses Passwort ebenfalls als
    # SSH-Passwort und startet den Passwortmechanismus statt sauber nur den Key
    # zu verwenden. Leere SSH-Password-Aliase überschreiben das Gruppenpasswort
# für diesen Host; beim Wechsel auf den verifizierten PSRP-HTTPS-Endpunkt werden
# sie wieder entfernt.
    host_data["ansible_password"] = ""
    host_data["ansible_ssh_pass"] = ""
    host_data["ansible_ssh_password"] = ""

    # Host-Key-Prüfung bleibt absichtlich aktiv. Mavi verwendet eine eigene
    # known_hosts-Datei, damit keine globale ~/.ssh-Konfiguration verändert wird.
    host_data["ansible_ssh_host_key_checking"] = True
    host_data["ansible_ssh_common_args"] = (
        f"-o UserKnownHostsFile={shlex_quote(str(known_hosts))} "
        "-o StrictHostKeyChecking=yes -o IdentitiesOnly=yes"
    )
    host_data.pop("mavi_remote_management_disabled", None)
    return resolved_key, resolved_port


def _apply_psrp_transport(host_data: dict[str, Any]) -> None:
    """Legacy-Transport absichtlich sperren: Mavi erzeugt kein HTTP/NTLM mehr."""
    from .environment import die

    del host_data
    die(
        "PSRP über HTTP/5985 mit NTLM ist in Mavi v0.8.48 deaktiviert. "
        "Zuerst OpenSSH einrichten und danach 'mavi-provisioner ssh winrm-https <HOST>' verwenden."
    )


def _psrp_https_inventory_vars(
    settings: dict[str, Any],
    *,
    fqdn: str,
    ca_cert: Path,
) -> dict[str, Any]:
    """Nur sichere PSRP-Variablen für einen einzelnen Windows-Host erzeugen."""
    return {
        "ansible_connection": "psrp",
        "ansible_port": int(settings["port"]),
        "ansible_psrp_protocol": "https",
        "ansible_psrp_auth": str(settings["auth"]),
        "ansible_psrp_cert_validation": "validate",
        "ansible_psrp_ca_cert": str(ca_cert.resolve()),
        "ansible_psrp_message_encryption": str(settings["message_encryption"]),
        # PSRP darf für den internen Verwaltungsverkehr nie einen Proxy
        # verwenden. Die TLS-Verbindung geht direkt zum Inventory-Host.
        "ansible_psrp_ignore_proxy": True,
        # Bei Inventory-IP bleibt der Kerberos-SPN trotzdem der echte FQDN.
        "ansible_psrp_negotiate_hostname_override": fqdn,
        # Ansible-core 2.21 verwendet zwar bereits `host` als Standard. Mavi
        # speichert ihn trotzdem explizit, damit der vorgeschaltete
        # Kerberos-Dienstticketnachweis exakt denselben SPN verwendet.
        "ansible_psrp_negotiate_service": "host",
        # Explizit setzen, damit der Schutz auch bei älteren Defaultwerten gilt.
        "ansible_psrp_negotiate_send_cbt": True,
    }


def _apply_psrp_https_transport(
    host_data: dict[str, Any],
    *,
    settings: dict[str, Any],
    fqdn: str,
    ca_cert: Path,
    kerberos_principal: str = "",
) -> None:
    """Host erst nach positiver HTTPS-Prüfung dauerhaft auf PSRP TLS umstellen."""
    # Ein eventuell host-spezifisch in Vault hinterlegtes PSRP-Passwort darf
    # beim Transportwechsel nicht verloren gehen. SSH-Leerwerte werden nur
    # übernommen, wenn sie zuvor tatsächlich gesetzt waren.
    preserved_credentials = {
        key: host_data[key]
        for key in (
            "ansible_password",
            "ansible_psrp_password",
            "ansible_winrm_pass",
            "ansible_winrm_password",
        )
        if key in host_data and str(host_data[key] or "").strip()
    }
    _clear_host_transport_vars(host_data)
    host_data.update(preserved_credentials)
    host_data.update(_psrp_https_inventory_vars(settings, fqdn=fqdn, ca_cert=ca_cert))
    host_data.pop("mavi_remote_management_disabled", None)
    if kerberos_principal:
        host_data["ansible_user"] = kerberos_principal


def _remember_winrm_https_state(
    host_data: dict[str, Any],
    *,
    settings: dict[str, Any],
    fqdn: str,
    ca_cert: Path,
    kerberos_principal: str,
) -> None:
    """Nur nach doppeltem Kerberos-Nachweis persistierte Transport-Metadaten."""
    from .openssh import _sha256_file

    host_data["mavi_winrm_https"] = {
        "version": 1,
        "kerberos_verified": True,
        "auth": "kerberos",
        "fqdn": fqdn,
        "port": int(settings["port"]),
        "kerberos_principal": kerberos_principal,
        "ca_sha256": _sha256_file(ca_cert).lower(),
    }


def _saved_winrm_https_transport(
    project: Path,
    host_data: dict[str, Any],
) -> tuple[dict[str, Any], str, Path, str]:
    """Gespeicherte Kerberos-HTTPS-Endstufe eng prüfen, nie raten oder downgraden."""
    from .openssh import _sha256_file

    state = host_data.get("mavi_winrm_https")
    if not isinstance(state, dict) or state.get("kerberos_verified") is not True:
        raise ValueError(
            "Für diesen Host ist kein erfolgreich geprüfter Mavi-WinRM-HTTPS/Kerberos-Endzustand gespeichert. "
            "HTTP/NTLM wird nicht als Ersatz aktiviert."
        )
    settings = _winrm_https_settings(project)
    if str(state.get("auth", "")).strip().lower() != "kerberos":
        raise ValueError("Der gespeicherte WinRM-Status ist nicht Kerberos-only und wird nicht verwendet.")
    try:
        saved_port = int(state.get("port"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Der gespeicherte WinRM-HTTPS-Port ist ungültig.") from exc
    if saved_port != int(settings["port"]):
        raise ValueError(
            "Der gespeicherte WinRM-HTTPS-Port passt nicht zur aktuellen Mavi-Konfiguration. "
            "Mavi schaltet nicht still auf einen anderen Transport um."
        )
    fqdn = _normalize_winrm_dns_name(str(state.get("fqdn", "") or ""), label="gespeicherter WinRM-FQDN")
    suffix = "." + str(settings["domain_suffix"])
    if not fqdn.endswith(suffix) or fqdn == str(settings["domain_suffix"]):
        raise ValueError("Der gespeicherte WinRM-FQDN liegt nicht in der Mavi-Domäne.")
    ca_cert = _winrm_pki_paths(project)["ca_cert"]
    if not ca_cert.is_file():
        raise ValueError("Die lokale Mavi-WinRM-CA fehlt; Mavi ersetzt eine Vertrauenswurzel niemals still.")
    expected_hash = str(state.get("ca_sha256", "") or "").lower()
    actual_hash = _sha256_file(ca_cert).lower()
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or not secrets.compare_digest(expected_hash, actual_hash):
        raise ValueError("Die lokale Mavi-WinRM-CA stimmt nicht mit dem geprüften Host-Status überein.")
    kerberos_principal = str(state.get("kerberos_principal", "") or "").strip()
    if not kerberos_principal:
        raise ValueError("Der geprüfte Kerberos-Principal für diesen Host fehlt.")
    return settings, fqdn, ca_cert, kerberos_principal


def _apply_saved_winrm_https_transport(project: Path, host_data: dict[str, Any]) -> None:
    """Inventory ausschließlich auf einen zuvor verifizierten Kerberos-TLS-Transport umstellen."""
    settings, fqdn, ca_cert, kerberos_principal = _saved_winrm_https_transport(project, host_data)
    _apply_psrp_https_transport(
        host_data,
        settings=settings,
        fqdn=fqdn,
        ca_cert=ca_cert,
        kerberos_principal=kerberos_principal,
    )


def _normalize_winrm_dns_name(value: str, *, label: str) -> str:
    """DNS-Namen für Zertifikate und Kerberos-Overrides eng validieren."""
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        raise ValueError(f"{label} fehlt oder enthält ungültige Zeichen.")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"{label} ist kein gültiger DNS-Name.") from exc
    labels = normalized.split(".")
    if any(
        not item
        or len(item) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", item)
        for item in labels
    ):
        raise ValueError(f"{label} ist kein gültiger DNS-Name.")
    return normalized


def _winrm_https_settings(project: Path) -> dict[str, Any]:
    """Zentrale, sichere PSRP-HTTPS-Konfiguration laden und prüfen."""
    from .environment import get_config

    config = get_config(project)
    raw = config.get("winrm_https", {}) or {}
    if not isinstance(raw, dict):
        raise ValueError("winrm_https muss ein Konfigurationsobjekt sein.")

    suffix = _normalize_winrm_dns_name(
        str(raw.get("domain_suffix", "") or ""),
        label="winrm_https.domain_suffix",
    )
    if "." not in suffix:
        raise ValueError("winrm_https.domain_suffix muss eine Domäne wie example.invalid sein.")

    try:
        port = int(raw.get("port", 5986) or 5986)
    except (TypeError, ValueError) as exc:
        raise ValueError("winrm_https.port muss eine gültige TCP-Portnummer sein.") from exc
    if port != 5986:
        raise ValueError(
            "winrm_https.port muss 5986 sein. Mavi verwendet den dokumentierten "
            "WinRM-HTTPS-Standardport und erstellt keinen abweichenden Listener."
        )

    auth = str(raw.get("auth", "kerberos") or "kerberos").strip().lower()
    if auth != "kerberos":
        raise ValueError(
            "winrm_https.auth muss 'kerberos' sein. Mavi aktiviert weder "
            "Negotiate- noch NTLM-Fallbacks."
        )
    message_encryption = str(raw.get("message_encryption", "always") or "always").strip().lower()
    if message_encryption not in {"auto", "always"}:
        raise ValueError("winrm_https.message_encryption darf nur auto oder always sein.")
    kerberos_principal = str(raw.get("kerberos_principal", "") or "").strip()
    if kerberos_principal and (
        any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in kerberos_principal)
        or kerberos_principal.count("@") != 1
    ):
        raise ValueError("winrm_https.kerberos_principal muss ein einzelner UPN wie admin@example.invalid sein.")
    kerberos_dns_server = str(raw.get("kerberos_dns_server", "") or "").strip()
    if kerberos_dns_server:
        try:
            parsed_dns_server = ipaddress.ip_address(kerberos_dns_server)
        except ValueError as exc:
            raise ValueError("winrm_https.kerberos_dns_server muss eine einzelne DNS-Server-IP sein.") from exc
        if (
            parsed_dns_server.is_unspecified
            or parsed_dns_server.is_multicast
            or parsed_dns_server.is_link_local
        ):
            raise ValueError("winrm_https.kerberos_dns_server darf keine Sonder- oder Link-Local-IP sein.")
        kerberos_dns_server = str(parsed_dns_server)
    if raw.get("disable_http_after_verified") is False:
        raise ValueError(
            "disable_http_after_verified darf nicht false sein: Mavi behält keinen HTTP/NTLM-Rückweg."
        )

    return {
        "domain_suffix": suffix,
        "port": port,
        "auth": auth,
        "kerberos_principal": kerberos_principal,
        "kerberos_dns_server": kerberos_dns_server,
        "message_encryption": message_encryption,
        "disable_http_after_verified": True,
    }


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
    resolved = _vault_host_context(project, host, vault_password_file)
    value = resolved.get("ansible_user", "")
    return value if isinstance(value, str) else ""


def _winrm_pki_paths(project: Path) -> dict[str, Path]:
    """Pfadlayout der separaten, nie veröffentlichten Mavi-WinRM-CA."""
    from .environment import project_paths

    root = project_paths(project)["winrm_pki_dir"]
    return {
        "root": root,
        "ca_key": root / "mavi-winrm-root-ca.key.pem",
        "ca_cert": root / "mavi-winrm-root-ca.cert.pem",
        "ca_der": root / "mavi-winrm-root-ca.cer",
        "requests": root / "requests",
        "certs": root / "certs",
        "profiles": root / "profiles",
        "state": root / "state",
    }


def _winrm_local_command(command: list[str], *, description: str) -> str:
    """Lokalen OpenSSL-Schritt ohne Geheimnisse in der Ausgabe ausführen."""
    from .reports import redact_sensitive_text

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise RuntimeError(f"{description} konnte nicht gestartet werden: {redact_sensitive_text(exc)}") from exc
    if result.returncode != 0:
        detail = redact_sensitive_text((result.stderr or result.stdout or "").strip())
        raise RuntimeError(
            f"{description} ist mit Exit-Code {result.returncode} fehlgeschlagen"
            + (f": {detail}" if detail else ".")
        )
    return (result.stdout or "").strip()


def _ensure_winrm_ca(project: Path) -> dict[str, Path]:
    """Einmalig eine von der Bootstrap-CA isolierte WinRM-CA erzeugen."""
    paths = _winrm_pki_paths(project)
    root = paths["root"]
    root.mkdir(parents=True, exist_ok=True)
    for directory_key in ("root", "requests", "certs", "profiles", "state"):
        directory = paths[directory_key]
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass

    ca_key = paths["ca_key"]
    ca_cert = paths["ca_cert"]
    if ca_cert.exists() and not ca_key.exists():
        raise RuntimeError(
            "Die Mavi-WinRM-CA existiert, aber ihr privater Schlüssel fehlt. "
            "Mavi ersetzt eine Vertrauenswurzel niemals still; Backup wiederherstellen."
        )
    if not shutil.which("openssl"):
        raise RuntimeError("OpenSSL fehlt auf dem Ansible-Server; die Mavi-WinRM-CA kann nicht sicher erzeugt werden.")

    if not ca_key.exists():
        _winrm_local_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_key),
            ],
            description="Privaten Schlüssel der Mavi-WinRM-CA erzeugen",
        )
    try:
        os.chmod(ca_key, 0o600)
    except OSError:
        pass

    if not ca_cert.exists():
        _winrm_local_command(
            [
                "openssl", "req", "-x509", "-new", "-sha256",
                "-key", str(ca_key), "-out", str(ca_cert), "-days", "3650",
                "-subj", "/CN=Mavi WinRM TLS Root CA/O=Mavi/OU=Internal Automation",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
            ],
            description="Mavi-WinRM-CA-Zertifikat erzeugen",
        )
    ca_der = paths["ca_der"]
    if not ca_der.exists():
        temporary_der = ca_der.with_name("." + ca_der.name + ".new")
        try:
            _winrm_local_command(
                ["openssl", "x509", "-in", str(ca_cert), "-outform", "DER", "-out", str(temporary_der)],
                description="Öffentliches Mavi-WinRM-CA-Zertifikat für Windows erzeugen",
            )
            os.replace(temporary_der, ca_der)
        finally:
            temporary_der.unlink(missing_ok=True)
    if not ca_der.is_file() or not ca_der.stat().st_size:
        raise RuntimeError("Das öffentliche Mavi-WinRM-CA-Zertifikat fehlt oder ist leer.")
    try:
        os.chmod(ca_cert, 0o644)
        os.chmod(ca_der, 0o644)
    except OSError:
        pass
    return paths


def _winrm_leaf_openssl_config(dns_sans: list[str], ip_sans: list[str]) -> str:
    """Zertifikatserweiterungen werden lokal festgelegt, niemals aus der CSR kopiert."""
    alt_lines: list[str] = []
    for index, name in enumerate(dns_sans, start=1):
        alt_lines.append(f"DNS.{index} = {name}")
    for index, value in enumerate(ip_sans, start=1):
        alt_lines.append(f"IP.{index} = {value}")
    if not alt_lines:
        raise ValueError("Für das WinRM-Zertifikat fehlt ein zulässiger SAN-Eintrag.")
    return "\n".join([
        "[server_ext]",
        "basicConstraints = critical, CA:FALSE",
        "keyUsage = critical, digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid,issuer",
        "subjectAltName = @alt_names",
        "",
        "[alt_names]",
        *alt_lines,
        "",
    ])


def _issue_winrm_server_certificate(
    project: Path,
    *,
    host: str,
    identity: dict[str, Any],
    csr_pem: bytes,
) -> dict[str, Any]:
    """Eine auf Windows erzeugte CSR prüfen und mit der Mavi-WinRM-CA signieren."""
    from .openssh import (
        _atomic_write_bytes,
        _sha256_file,
    )

    paths = _ensure_winrm_ca(project)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(host or "WINDOWS")).strip("._-") or "WINDOWS"
    request_id = secrets.token_hex(12)
    csr_path = paths["requests"] / f"{safe_host}-{request_id}.csr.pem"
    profile_path = paths["profiles"] / f"{safe_host}-{request_id}.cnf"
    cert_pem = paths["certs"] / f"{safe_host}-{request_id}.cert.pem"
    cert_der = paths["certs"] / f"{safe_host}-{request_id}.cer"
    temporary_pem = paths["certs"] / f".{safe_host}-{request_id}.cert.new"

    _atomic_write_bytes(csr_path, csr_pem, mode=0o600)
    _atomic_write_bytes(
        profile_path,
        _winrm_leaf_openssl_config(identity["dns_sans"], identity["ip_sans"]).encode("utf-8"),
        mode=0o600,
    )
    try:
        _winrm_local_command(
            ["openssl", "req", "-in", str(csr_path), "-noout", "-verify"],
            description="WinRM-Zertifikatsanfrage auf gültige Signatur prüfen",
        )
        subject = _winrm_local_command(
            ["openssl", "req", "-in", str(csr_path), "-noout", "-subject"],
            description="WinRM-Zertifikatsanfrage auslesen",
        )
        if identity["fqdn"].casefold() not in subject.casefold():
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Die Windows-CSR gehört nicht zum erwarteten WinRM-FQDN "
                f"{identity['fqdn']}."
            )

        _winrm_local_command(
            [
                "openssl", "x509", "-req", "-sha256", "-in", str(csr_path),
                "-CA", str(paths["ca_cert"]), "-CAkey", str(paths["ca_key"]),
                "-set_serial", "0x" + secrets.token_hex(16),
                "-out", str(temporary_pem), "-days", "825",
                "-extfile", str(profile_path), "-extensions", "server_ext",
            ],
            description="WinRM-Serverzertifikat mit der Mavi-WinRM-CA signieren",
        )
        _winrm_local_command(
            ["openssl", "verify", "-CAfile", str(paths["ca_cert"]), str(temporary_pem)],
            description="Signiertes WinRM-Serverzertifikat gegen die Mavi-WinRM-CA prüfen",
        )
        purpose = _winrm_local_command(
            ["openssl", "x509", "-in", str(temporary_pem), "-noout", "-purpose"],
            description="Server-Authentifizierung des WinRM-Zertifikats prüfen",
        )
        if not re.search(r"^SSL server\s*:\s*Yes\s*$", purpose, flags=re.IGNORECASE | re.MULTILINE):
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Das signierte WinRM-Zertifikat besitzt keine gültige "
                "Server-Authentication-Verwendung."
            )
        _winrm_local_command(
            ["openssl", "x509", "-in", str(temporary_pem), "-outform", "DER", "-out", str(cert_der)],
            description="WinRM-Serverzertifikat für Windows bereitstellen",
        )
        os.replace(temporary_pem, cert_pem)
        try:
            os.chmod(cert_pem, 0o600)
            os.chmod(cert_der, 0o600)
        except OSError:
            pass
    finally:
        temporary_pem.unlink(missing_ok=True)

    return {
        "ca_cert": paths["ca_cert"],
        "ca_der": paths["ca_der"],
        "ca_der_sha256": _sha256_file(paths["ca_der"]).lower(),
        "cert_pem": cert_pem,
        "cert_der": cert_der,
        "cert_sha256": _sha256_file(cert_der).lower(),
        "request_id": request_id,
    }


def _remove_host_winrm_certificate_artifacts(
    project: Path,
    host: str,
) -> tuple[int, list[str]]:
    """Nur die eindeutig diesem Host zugeordneten WinRM-PKI-Dateien löschen."""
    from .reports import redact_sensitive_text

    paths = _winrm_pki_paths(project)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(host or "WINDOWS")).strip("._-") or "WINDOWS"
    escaped_host = re.escape(safe_host)
    file_patterns = {
        "requests": re.compile(rf"^{escaped_host}-[a-f0-9]{{24}}\.csr\.pem$"),
        "profiles": re.compile(rf"^{escaped_host}-[a-f0-9]{{24}}\.cnf$"),
        "certs": re.compile(
            rf"^(?:{escaped_host}-[a-f0-9]{{24}}\.(?:cert\.pem|cer)|"
            rf"\.{escaped_host}-[a-f0-9]{{24}}\.cert\.new)$"
        ),
    }
    removed = 0
    warnings: list[str] = []
    if paths["root"].is_symlink():
        warnings.append(f"Verknüpfte WinRM-PKI-Basis wurde nicht bereinigt: {paths['root']}")
        return removed, warnings
    try:
        expected_root = paths["root"].resolve(strict=True)
    except OSError as exc:
        if paths["root"].exists():
            warnings.append(f"WinRM-PKI-Basis konnte nicht geprüft werden: {redact_sensitive_text(exc)}")
        return removed, warnings

    for directory_key, filename_pattern in file_patterns.items():
        directory = paths[directory_key]
        if not directory.exists():
            continue
        if directory.is_symlink():
            warnings.append(f"Verknüpfter WinRM-PKI-Ordner wurde nicht bereinigt: {directory}")
            continue
        try:
            resolved_directory = directory.resolve(strict=True)
            if resolved_directory.parent != expected_root:
                warnings.append(
                    f"Unerwarteter WinRM-PKI-Pfad wurde nicht bereinigt: {resolved_directory}"
                )
                continue
            candidates = list(directory.iterdir())
        except OSError as exc:
            warnings.append(
                f"WinRM-PKI-Ordner {directory} konnte nicht gelesen werden: "
                f"{redact_sensitive_text(exc)}"
            )
            continue

        for candidate in candidates:
            if filename_pattern.fullmatch(candidate.name) is None:
                continue
            try:
                if candidate.is_dir() and not candidate.is_symlink():
                    warnings.append(f"Unerwarteter Ordner wurde nicht entfernt: {candidate}")
                    continue
                candidate.unlink()
                removed += 1
            except OSError as exc:
                warnings.append(
                    f"Hostbezogene WinRM-PKI-Datei {candidate} konnte nicht entfernt werden: "
                    f"{redact_sensitive_text(exc)}"
                )

    return removed, warnings


def _absolute_without_symlink(path: Path) -> Path:
    """Absoluten Pfad bilden, ohne die für venv essenzielle Symlink-Identität zu verlieren."""
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _ansible_playbook_candidates() -> list[Path]:
    """Bevorzugte Ansible-Startpunkte ohne PATH-/sudo-Mehrdeutigkeit liefern."""
    raw_candidates: list[Path] = []

    # Bei einem sudo-Start bleibt die Benutzer-pipx-Installation der korrekte
    # Ansible-Kontext. /root/.local oder /usr/bin dürfen sie nicht verdrängen.
    sudo_user = str(os.environ.get("SUDO_USER", "") or "").strip()
    if sudo_user and sudo_user != "root" and re.fullmatch(r"[A-Za-z0-9_.-]+", sudo_user):
        try:
            import pwd

            sudo_home = Path(pwd.getpwnam(sudo_user).pw_dir)
            raw_candidates.append(sudo_home / ".local" / "bin" / "ansible-playbook")
        except (ImportError, KeyError, OSError):
            pass

    raw_candidates.append(Path.home() / ".local" / "bin" / "ansible-playbook")
    path_executable = shutil.which("ansible-playbook")
    if path_executable:
        raw_candidates.append(Path(path_executable))

    candidates: list[Path] = []
    seen: set[Path] = set()
    for candidate in raw_candidates:
        try:
            if not candidate.is_file():
                continue
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        candidates.append(resolved)
    return candidates


_ANSIBLE_RUNTIME_CACHE: tuple[Path, Path] | None = None


def _ansible_playbook_runtime() -> tuple[Path, Path]:
    """Exakten Ansible-Startpunkt und dessen wirklichen Python-Interpreter koppeln."""
    global _ANSIBLE_RUNTIME_CACHE
    if _ANSIBLE_RUNTIME_CACHE is not None:
        executable, interpreter = _ANSIBLE_RUNTIME_CACHE
        if executable.is_file() and interpreter.is_file():
            return _ANSIBLE_RUNTIME_CACHE

    candidates = _ansible_playbook_candidates()
    if not candidates:
        raise RuntimeError("ansible-playbook fehlt auf dem Controller.")

    for executable in candidates:
        # `ansible-playbook --version` wird vom tatsächlichen Ansible-Prozess
        # erzeugt und nennt dessen Python samt absolutem Pfad.
        try:
            version_result = subprocess.run(
                [str(executable), "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            version_result = None
        if version_result is not None and version_result.returncode == 0:
            version_output = (version_result.stdout or "") + "\n" + (version_result.stderr or "")
            for line in version_output.splitlines():
                match = re.search(
                    r"^\s*python\s+version\s*=.*\((/[^)]+)\)\s*$",
                    line,
                    re.IGNORECASE,
                )
                if not match:
                    continue
                reported = Path(match.group(1).strip()).expanduser()
                if reported.is_file():
                    # NIEMALS resolve(): venv/bin/python ist absichtlich ein
                    # Symlink auf das Basis-Python. Nur der logische Venv-Pfad
                    # aktiviert pyvenv.cfg und damit dessen site-packages.
                    _ANSIBLE_RUNTIME_CACHE = (
                        executable,
                        _absolute_without_symlink(reported),
                    )
                    return _ANSIBLE_RUNTIME_CACHE

        # Fallback nur auf den Shebang genau dieses Startpunkts. Es gibt keinen
        # Rückfall auf sys.executable, da dies erneut zwei Umgebungen vermischen würde.
        try:
            first_line = executable.open("r", encoding="utf-8", errors="replace").readline().strip()
        except OSError:
            first_line = ""
        if not first_line.startswith("#!"):
            continue
        shebang = first_line[2:].strip().split()
        if not shebang:
            continue
        interpreter = shebang[0]
        if Path(interpreter).name == "env" and len(shebang) > 1:
            env_arguments = shebang[1:]
            if env_arguments and env_arguments[0] == "-S":
                env_arguments = env_arguments[1:]
            interpreter_name = next(
                (value for value in env_arguments if value and not value.startswith("-")),
                "",
            )
            interpreter = shutil.which(interpreter_name) or ""
        if interpreter and Path(interpreter).is_file():
            _ANSIBLE_RUNTIME_CACHE = (
                executable,
                _absolute_without_symlink(Path(interpreter)),
            )
            return _ANSIBLE_RUNTIME_CACHE

    raise RuntimeError(
        "Der Python-Interpreter des verfügbaren ansible-playbook konnte nicht eindeutig ermittelt werden."
    )


def _ansible_playbook_executable() -> Path:
    return _ansible_playbook_runtime()[0]


def _ansible_controller_python() -> Path:
    return _ansible_playbook_runtime()[1]


def _ansible_inventory_executable() -> Path:
    """ansible-inventory aus exakt derselben Installation wie ansible-playbook."""
    candidate = _ansible_playbook_executable().with_name("ansible-inventory")
    if not candidate.is_file():
        raise RuntimeError(
            "ansible-inventory fehlt in der erkannten Ansible-Umgebung."
        )
    return candidate


def _ansible_runtime_environment(ansible_python: Path) -> dict[str, str]:
    """Saubere Prozessumgebung für den gebundenen venv-/pipx-Interpreter."""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PATH"] = str(ansible_python.parent) + os.pathsep + environment.get("PATH", "")
    venv_root = ansible_python.parent.parent
    if (venv_root / "pyvenv.cfg").is_file():
        environment["VIRTUAL_ENV"] = str(venv_root)
    return environment


def _python_imports_gssapi(python_executable: Path) -> bool:
    """Die vollständige PSRP-/pyspnego-Kerberos-Kette im Ansible-Venv prüfen."""
    probe = (
        "import gssapi, krb5, pypsrp\n"
        "from spnego import _gss\n"
        "assert _gss.HAS_GSSAPI, _gss.GSSAPI_IMP_ERR\n"
        "assert _gss.HAS_IOV, _gss.GSSAPI_IOV_IMP_ERR\n"
    )
    try:
        result = subprocess.run(
            [str(python_executable), "-I", "-c", probe],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env=_ansible_runtime_environment(python_executable),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _controller_root_prefix() -> list[str]:
    """Root-Prefix für die einmalige Controller-Paketinstallation."""
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if not sudo:
        raise RuntimeError(
            "GSSAPI fehlt und sudo ist für die automatische Controller-Einrichtung nicht verfügbar."
        )
    return [sudo]


def _ansible_pipx_venv_root(ansible_python: Path) -> Path | None:
    """pipx-Venv-Wurzel ausschließlich aus dem unaufgelösten Interpreterpfad ableiten."""
    lexical_python = _absolute_without_symlink(ansible_python)
    for parent in lexical_python.parents:
        if parent.parent.name != "venvs" or parent.parent.parent.name != "pipx":
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+", parent.name) and (parent / "pyvenv.cfg").is_file():
            return parent
    return None


def _ansible_pipx_package(ansible_python: Path) -> str:
    """pipx-Paketname aus .../pipx/venvs/<paket>/bin/python ableiten."""
    venv_root = _ansible_pipx_venv_root(ansible_python)
    return venv_root.name if venv_root is not None else ""


def _pipx_command_for_ansible(ansible_python: Path) -> list[str]:
    """pipx im Besitz genau der erkannten Ansible-Umgebung ausführen."""
    pipx_path: Path | None = None
    lexical_python = _absolute_without_symlink(ansible_python)
    venv_root = _ansible_pipx_venv_root(lexical_python)
    for parent in lexical_python.parents:
        if parent.name != ".local":
            continue
        associated = parent / "bin" / "pipx"
        if associated.is_file():
            pipx_path = _absolute_without_symlink(associated)
            break
    if pipx_path is None:
        discovered = shutil.which("pipx")
        if discovered:
            pipx_path = _absolute_without_symlink(Path(discovered))
    if pipx_path is None:
        raise RuntimeError("Die erkannte Ansible-pipx-Umgebung kann nicht repariert werden, weil pipx fehlt.")

    geteuid = getattr(os, "geteuid", None)
    if not callable(geteuid):
        return [str(pipx_path)]
    try:
        # Nicht den Python-Symlink statten: dessen Ziel /usr/bin gehört root.
        runtime_owner = (venv_root or lexical_python.parent.parent).stat().st_uid
    except OSError:
        runtime_owner = geteuid()
    if runtime_owner == geteuid():
        return [str(pipx_path)]

    # Wurde das gesamte Mavi-Skript mit sudo gestartet, muss pipx trotzdem als
    # Besitzer der Benutzerumgebung laufen. Sonst sucht pipx irrtümlich unter /root.
    if geteuid() == 0:
        try:
            import pwd

            owner_name = pwd.getpwuid(runtime_owner).pw_name
        except (ImportError, KeyError, OSError) as exc:
            raise RuntimeError("Der Besitzer der Ansible-pipx-Umgebung konnte nicht ermittelt werden.") from exc
        sudo = shutil.which("sudo")
        if not sudo:
            raise RuntimeError("sudo fehlt für die Reparatur der Benutzer-pipx-Umgebung.")
        return [sudo, "-u", owner_name, "-H", str(pipx_path)]

    raise RuntimeError("Die Ansible-pipx-Umgebung gehört einem anderen Benutzer und ist nicht sicher änderbar.")


def _ensure_psrp_kerberos_controller_dependencies(*, force_pipx_inject: bool = False) -> None:
    """Offizielle PSRP-Kerberos-Abhängigkeiten vor jeder Windows-Änderung bereitstellen."""
    from .openssh import _root_command

    ansible_executable, ansible_python = _ansible_playbook_runtime()
    pipx_package = _ansible_pipx_package(ansible_python)
    gssapi_available = _python_imports_gssapi(ansible_python)
    if gssapi_available and not force_pipx_inject:
        return

    print("\nMavi KERBEROS-CONTROLLER-SETUP")
    print("================================")
    if gssapi_available:
        print("  → Der Ansible-Worker meldete GSSAPI trotz Vorprüfung als fehlend; Mavi repariert die pipx-Umgebung einmalig.")
    else:
        print("  → GSSAPI fehlt im Python-Kontext von Ansible und wird einmalig eingerichtet.")
    print(f"  → Ansible-Start:  {ansible_executable}")
    print(f"  → Ansible-Python: {ansible_python}")
    if pipx_package:
        print(f"  → pipx-Paket:      {pipx_package}")

    if not gssapi_available:
        apt_get = shutil.which("apt-get")
        if apt_get:
            root_prefix = _controller_root_prefix()
            noninteractive = ["env", "DEBIAN_FRONTEND=noninteractive"]
            _root_command(
                [*root_prefix, *noninteractive, apt_get, "update"],
                description="Kerberos-Paketlisten aktualisieren",
            )
            _root_command(
                [
                    *root_prefix,
                    *noninteractive,
                    apt_get,
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "krb5-user",
                    "libkrb5-dev",
                    "python3-dev",
                    "gcc",
                    "python3-gssapi",
                ],
                description="Kerberos, GSSAPI und Python-Buildabhängigkeiten installieren",
            )
        else:
            raise RuntimeError(
                "GSSAPI fehlt. Die automatische Einrichtung unterstützt hier Debian/Ubuntu mit apt-get."
            )

    if _python_imports_gssapi(ansible_python) and not force_pipx_inject:
        print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")
        return

    # pipx-Umgebungen werden ausschließlich über die dafür vorgesehene
    # Injection erweitert. Ein direktes `venv/bin/python -m pip` kann zwar
    # funktionieren, umgeht aber pipx' Paketverwaltung und war bei der realen
    # Mavi-Ansible-Installation mit Python 3.14 nicht zuverlässig.
    ansible_python_text = str(_absolute_without_symlink(ansible_python))
    system_python_candidates = {
        _absolute_without_symlink(candidate)
        for directory in (Path("/usr/bin"), Path("/bin"))
        for candidate in directory.glob("python*")
        if candidate.is_file()
        and re.fullmatch(r"python\d+(?:\.\d+)*", candidate.name)
    }
    if pipx_package:
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "inject",
                "--force",
                pipx_package,
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"PSRP-Kerberos-Extra in pipx-Paket {pipx_package} injizieren",
        )
    elif _absolute_without_symlink(ansible_python) not in system_python_candidates:
        _root_command(
            [
                ansible_python_text,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description="PSRP-Kerberos-Extra in die isolierte Ansible-Umgebung installieren",
        )

    # `inject` ist der vorgesehene pipx-Weg. Sollte dessen Extra-Auflösung die
    # vollständige pyspnego-Kette dennoch nicht bereitstellen, installiert Mavi
    # die vier konkreten Kerberos-Komponenten direkt in exakt dieselbe Venv.
    if pipx_package and not _python_imports_gssapi(ansible_python):
        pipx_command = _pipx_command_for_ansible(ansible_python)
        _root_command(
            [
                *pipx_command,
                "runpip",
                pipx_package,
                "install",
                "--upgrade",
                "--force-reinstall",
                "--no-cache-dir",
                "gssapi>=1.6.0",
                "krb5>=0.3.0",
                "pyspnego[kerberos]>=0.7.0,<1.0.0",
                "pypsrp[kerberos]>=0.4.0,<1.0.0",
            ],
            description=f"Kerberos-Komponenten im pipx-Paket {pipx_package} vollständig reparieren",
        )

    if not _python_imports_gssapi(ansible_python):
        raise RuntimeError(
            "Die vollständige GSSAPI-/Kerberos-/IOV-Kette ist nach der Einrichtung "
            f"im Ansible-Python {ansible_python} weiterhin nicht verfügbar."
        )
    print("  ✓ GSSAPI, Kerberos und WinRM-IOV sind im Ansible-Python verfügbar.")


def _is_missing_gssapi_failure(exc: BaseException) -> bool:
    """Eindeutige Ausfälle der lokalen GSSAPI-/Kerberos-Kette erkennen."""
    folded = str(exc).casefold()
    return (
        "gssapiproxy requires the python gssapi library" in folded
        or (
            "no module named" in folded
            and any(module in folded for module in ("gssapi", "krb5"))
        )
        or "gssapi iov extension not available" in folded
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


def _vault_psrp_password_for_host(project: Path, host: str, vault_password_file: Path) -> str:
    """Das bestehende Vault-Passwort nur im Speicher für einen Kerberos-TGT lesen.

    Das SSH-Inventar darf absichtlich leere Passwortwerte enthalten. Für diese
    eine Abfrage werden ausschließlich solche leeren Maskierungen entfernt,
    damit Ansible den regulären Vault-Wert auflöst. Die entschlüsselte Antwort
    bleibt im Arbeitsspeicher und wird nie protokolliert oder gespeichert.
    """
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


def _open_client_ansible_session(
    *,
    project: Path,
    host: str,
    vault_password_file: Path,
) -> dict[str, Any]:
    """Gebundene Ansible-Laufzeit samt privatem Kerberos-Cache öffnen."""
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
        _effective_host_var(windows, host_data, "ansible_psrp_auth", "") or ""
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


def _run_winrm_temporary_play(
    project: Path,
    *,
    host: str,
    play: list[dict[str, Any]],
    vault_password_file: Path,
    description: str,
    extra_vars: dict[str, Any] | None = None,
    inherit_vault_psrp_credentials: bool = False,
    use_vault_kerberos_ticket: bool = False,
    kerberos_principal: str = "",
    kerberos_target_fqdn: str = "",
    timeout: float = 180.0,
) -> str:
    """Kurzlebigen Ansible-Play sicher ausführen und Fehler kompakt schwärzen."""
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import strip_ansi
    from .reports import redact_sensitive_text

    playbook_path: Path | None = None
    temporary_inventory_path: Path | None = None
    kerberos_ticket_directory: Path | None = None
    kerberos_ticket_path: Path | None = None
    effective_extra_vars = dict(extra_vars or {})
    try:
        fd, raw_path = tempfile.mkstemp(prefix=".mavi-winrm-tls-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_path)
        atomic_write_yaml(playbook_path, play)

        if inherit_vault_psrp_credentials:
            temporary_inventory_path = _temporary_psrp_vault_inventory(project, host)
        inventory_path = temporary_inventory_path or project_paths(project)["inventory"]

        ansible_executable, ansible_python = _ansible_playbook_runtime()
        runtime_environment = _ansible_runtime_environment(ansible_python)
        if use_vault_kerberos_ticket:
            kerberos_ticket_directory, kerberos_ticket_path, cache_principal = _acquire_vault_kerberos_ticket(
                project,
                host=host,
                vault_password_file=vault_password_file,
                kerberos_principal=kerberos_principal,
                ansible_python=ansible_python,
                target_fqdn=kerberos_target_fqdn,
            )
            runtime_environment["KRB5CCNAME"] = f"FILE:{kerberos_ticket_path}"
            # pyspnego verwendet bei einem nichtleeren Benutzernamen eine
            # benannte Cache-Credential. Das war der Auslöser für den echten
            # "Matching credential not found"-Fehler. Leere Werte sind hier
            # kein Fallback: Sie zwingen ausschließlich den vorher geprüften
            # Standard-CCache; weder Passwort noch NTLM stehen diesem Proof
            # zur Verfügung.
            effective_extra_vars.update(_kerberos_cache_connection_overrides())
            print(
                f"  ✓ Privater Kerberos-Cache: {cache_principal}; "
                f"host/{kerberos_target_fqdn} ist bestätigt."
            )
        command = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i", str(inventory_path),
            str(playbook_path),
            "--limit", host,
            "--vault-password-file", str(vault_password_file),
        ]
        if effective_extra_vars:
            # Die Overlay-Variablen enthalten ausschließlich Transport- und
            # Zertifikatspfade sowie explizit leere Credential-Sperren, nie
            # ein Passwort oder privates Schlüsselmaterial.
            command.extend([
                "--extra-vars",
                json.dumps(effective_extra_vars, ensure_ascii=True, separators=(",", ":")),
            ])
        try:
            completed = subprocess.run(
                command,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{description} hat nach {int(timeout)} Sekunden nicht geantwortet.") from exc
        except OSError as exc:
            raise RuntimeError(f"{description} konnte nicht gestartet werden: {redact_sensitive_text(exc)}") from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        if completed.returncode != 0:
            folded = combined.casefold()
            if "decryption failed" in folded or "no vault secrets" in folded:
                raise RuntimeError(
                    "Der Ansible-Vault konnte nicht entschlüsselt werden. "
                    "Bitte das Mavi-Vault-Passwort eingeben, nicht das Domänen-/Windows-Passwort."
                )
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-12:])
            raise RuntimeError(
                f"{description} ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )
        return combined
    finally:
        if kerberos_ticket_directory is not None and kerberos_ticket_path is not None:
            _discard_kerberos_ticket_cache(kerberos_ticket_directory, kerberos_ticket_path)
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if temporary_inventory_path is not None:
            temporary_inventory_path.unlink(missing_ok=True)


def _winrm_csr_play(
    *,
    identity: dict[str, Any],
    request_id: str,
) -> list[dict[str, Any]]:
    """Play, der den privaten Schlüssel ausschließlich auf Windows erzeugt."""
    ip_san = str((identity.get("ip_sans") or [""])[0] or "")
    powershell = r'''[CmdletBinding()]
param(
    [string]$Fqdn,
    [string]$ShortName,
    [string]$IpSan,
    [string]$RequestId
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Fqdn) -or [string]::IsNullOrWhiteSpace($ShortName)) {
    throw 'Mavi WinRM TLS: FQDN oder Kurzname fehlt.'
}
if ($RequestId -notmatch '^[a-f0-9]{16,64}$') {
    throw 'Mavi WinRM TLS: interne Request-ID ist ungültig.'
}
if ($IpSan) {
    $parsedIp = $null
    if (-not [System.Net.IPAddress]::TryParse($IpSan, [ref]$parsedIp)) {
        throw "Mavi WinRM TLS: IP-SAN ist ungültig: $IpSan"
    }
}

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
if (-not (Test-Path -LiteralPath $certreq -PathType Leaf)) {
    throw "certreq.exe fehlt: $certreq"
}
$workDir = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$infPath = Join-Path $workDir ("request-$RequestId.inf")
$csrPath = Join-Path $workDir ("request-$RequestId.req")
Remove-Item -LiteralPath $infPath, $csrPath -Force -ErrorAction SilentlyContinue

$sanParts = @("dns=$Fqdn", "dns=$ShortName")
if (-not [string]::IsNullOrWhiteSpace($IpSan)) {
    $sanParts += "ipaddress=$IpSan"
}
$sanText = $sanParts -join '&'
$infLines = @(
    '[Version]',
    'Signature="$Windows NT$"',
    '',
    '[NewRequest]',
    ('Subject = "CN=' + $Fqdn + '"'),
    'KeyAlgorithm = RSA',
    'KeyLength = 3072',
    'HashAlgorithm = sha256',
    'MachineKeySet = TRUE',
    'Exportable = FALSE',
    'ProviderName = "Microsoft Software Key Storage Provider"',
    'RequestType = PKCS10',
    'KeyUsage = 0xa0',
    ('FriendlyName = "Mavi WinRM HTTPS ' + $Fqdn + '"'),
    '',
    '[Extensions]',
    '2.5.29.17 = "{text}"',
    ('_continue_ = "' + $sanText + '"'),
    '2.5.29.37 = "{text}"',
    '_continue_ = "1.3.6.1.5.5.7.3.1"'
)
Set-Content -LiteralPath $infPath -Value $infLines -Encoding ascii -Force
& $certreq -new $infPath $csrPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
    throw "certreq -new konnte keine CSR erzeugen (Exit-Code $LASTEXITCODE)."
}

$csrText = [System.IO.File]::ReadAllText($csrPath, [System.Text.Encoding]::ASCII)
if ($csrText -notmatch 'BEGIN (NEW )?CERTIFICATE REQUEST') {
    throw 'certreq lieferte keine PEM-kodierte Zertifikatsanfrage.'
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($csrText))
$Ansible.Result = @{ CsrMarker = $marker; RequestPath = $csrPath }
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM TLS CSR sicher auf Windows erzeugen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Nicht exportierbaren WinRM-Serverschlüssel und CSR erstellen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "Fqdn": identity["fqdn"],
                        "ShortName": identity["short_name"],
                        "IpSan": ip_san,
                        "RequestId": request_id,
                    },
                },
                "register": "mavi_winrm_csr",
            },
            {
                "name": "Mavi WinRM CSR an den Controller zurückgeben",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_CSR_B64_BEGIN={{ mavi_winrm_csr.result.CsrMarker }}_END",
                },
            },
        ],
    }]


def _extract_winrm_csr(play_output: str) -> bytes:
    """Die nur öffentliche CSR aus der Ansible-Ausgabe eindeutig entnehmen."""
    match = re.search(
        r"Mavi_WINRM_CSR_B64_BEGIN=([A-Za-z0-9+/=\s]+?)_END",
        str(play_output or ""),
    )
    if not match:
        raise RuntimeError("Die Windows-CSR wurde nicht vollständig an Mavi zurückgegeben.")
    encoded = re.sub(r"\s+", "", match.group(1))
    try:
        csr = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("Die Windows-CSR ist nicht gültig Base64-kodiert.") from exc
    decoded = csr.decode("ascii", errors="replace")
    if "BEGIN CERTIFICATE REQUEST" not in decoded and "BEGIN NEW CERTIFICATE REQUEST" not in decoded:
        raise RuntimeError("Die zurückgegebene Windows-CSR hat kein erwartetes PEM-Format.")
    return csr


def _winrm_install_https_play(
    *,
    certificate_path: str,
    certificate_sha256: str,
    ca_certificate_path: str,
    ca_certificate_sha256: str,
    identity: dict[str, Any],
    settings: dict[str, Any],
    ansible_server_ip: str,
) -> list[dict[str, Any]]:
    """Play für Zertifikatsannahme, HTTPS-Listener und enges Firewall-Scoping."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$CertificatePath,
    [string]$ExpectedSha256,
    [string]$RootCertificatePath,
    [string]$ExpectedRootSha256,
    [string]$Fqdn,
    [string]$AnsibleServerIp,
    [int]$Port,
    [string]$RuleName
)

$ErrorActionPreference = 'Stop'
if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Zertifikats-SHA-256 ist ungültig.'
}
if ($ExpectedRootSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Mavi WinRM TLS: erwarteter Root-CA-SHA-256 ist ungültig.'
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw 'Mavi WinRM TLS: Port ist ungültig.'
}
$parsedAnsibleIp = $null
if (-not [System.Net.IPAddress]::TryParse($AnsibleServerIp, [ref]$parsedAnsibleIp)) {
    throw "Mavi WinRM TLS: ansible_server_ip ist ungültig: $AnsibleServerIp"
}
if ($parsedAnsibleIp.Equals([System.Net.IPAddress]::Any) -or $parsedAnsibleIp.Equals([System.Net.IPAddress]::IPv6Any)) {
    throw 'Mavi WinRM TLS: ansible_server_ip darf kein Wildcard-Wert sein.'
}
if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: signiertes Zertifikat fehlt: $CertificatePath"
}
if (-not (Test-Path -LiteralPath $RootCertificatePath -PathType Leaf)) {
    throw "Mavi WinRM TLS: öffentliche Mavi-Root-CA fehlt: $RootCertificatePath"
}
$actualSha256 = [string](Get-FileHash -LiteralPath $CertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualSha256.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: WinRM-Zertifikat wurde vor der Annahme verändert. Erwartet=$ExpectedSha256 Ist=$actualSha256"
}
$actualRootSha256 = [string](Get-FileHash -LiteralPath $RootCertificatePath -Algorithm SHA256 -ErrorAction Stop).Hash
if (-not $actualRootSha256.Equals($ExpectedRootSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "SICHERHEITSABBRUCH: Mavi-WinRM-Root-CA wurde vor der Annahme verändert. Erwartet=$ExpectedRootSha256 Ist=$actualRootSha256"
}

$rootCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCertificatePath)
$basicConstraints = @($rootCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
if ($basicConstraints.Count -ne 1) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA hat keine eindeutige Basic-Constraints-Erweiterung.'
}
$decodedConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()
$decodedConstraints.CopyFrom($basicConstraints[0])
if (-not $decodedConstraints.CertificateAuthority) {
    throw 'Mavi WinRM TLS: die bereitgestellte Root-CA ist kein CA-Zertifikat.'
}
Import-Certificate -FilePath $RootCertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop | Out-Null

$certreq = Join-Path $env:WINDIR 'System32\certreq.exe'
& $certreq -accept $CertificatePath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "certreq -accept konnte das Mavi-WinRM-Zertifikat nicht annehmen (Exit-Code $LASTEXITCODE)."
}

$selected = $null
foreach ($candidate in @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop)) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $candidateHash = ([System.BitConverter]::ToString($sha.ComputeHash($candidate.RawData))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
    if ($candidateHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        $selected = $candidate
        break
    }
}
if ($null -eq $selected) {
    throw 'Mavi WinRM TLS: das exakt signierte Zertifikat wurde nicht im LocalMachine\\My Store gefunden.'
}
if (-not $selected.HasPrivateKey) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat hat keinen lokalen privaten Schlüssel.'
}
if (-not $selected.Issuer.Equals($rootCertificate.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Mavi WinRM TLS: das Serverzertifikat wurde nicht von der erwarteten Mavi-Root-CA ausgestellt.'
}
if ($selected.NotAfter -le (Get-Date).AddDays(1)) {
    throw 'Mavi WinRM TLS: das angenommene Zertifikat läuft zu früh ab.'
}
$hasServerAuth = $false
foreach ($extension in @($selected.Extensions)) {
    if ([string]$extension.Oid.Value -ne '2.5.29.37') { continue }
    $ekuExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]$extension
    foreach ($usage in @($ekuExtension.EnhancedKeyUsages)) {
        if ([string]$usage.Value -eq '1.3.6.1.5.5.7.3.1') {
            $hasServerAuth = $true
            break
        }
    }
    if ($hasServerAuth) { break }
}
if (-not $hasServerAuth) {
    throw 'Mavi WinRM TLS: dem Zertifikat fehlt Server Authentication EKU.'
}
$chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
if (-not $chain.Build($selected)) {
    $chainStatus = (@($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join '; ')
    throw "Mavi WinRM TLS: die lokale Windows-Zertifikatskette ist nicht gültig: $chainStatus"
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "SICHERHEITSABBRUCH: Die OpenSSH-Sitzung von $($currentIdentity.Name) besitzt keinen erhöhten lokalen Administrator-Token."
}

$httpBlockRuleName = 'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP'
$setupIsolationRuleName = 'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'

# Ein früherer, abgebrochener Lauf kann Negotiate bereits deaktiviert haben.
# Der lokale WSMan:-Provider verwaltet selbst localhost:47001 und würde sich
# dann selbst aussperren. Vor der ausschließlich lokalen Reparatur werden
# deshalb beide Netzwerkports vollständig abgeschottet. Block-Regeln haben
# unter Windows Vorrang vor eventuell vorhandenen Allow-Regeln.
Get-NetFirewallRule -DisplayName $httpBlockRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $httpBlockRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort 5985 -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $setupIsolationRuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Block -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress Any -EdgeTraversalPolicy Block | Out-Null

New-Item -Path $policyPath -Force | Out-Null
# Nur während vollständig blockierter 5985/5986-Ports darf der lokale
# WSMan-Provider wieder administrieren. Von außen ist Negotiate dabei niemals
# erreichbar. Der finally-Block erzwingt anschließend wieder Kerberos-only.
Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 1 -Force
Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
Restart-Service -Name WinRM -Force -ErrorAction Stop

try {
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false -Force -ErrorAction Stop

    $httpsListeners = @(
        Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
        Where-Object { $_.Keys -contains 'Transport=HTTPS' }
    )
    if ($httpsListeners.Count -gt 0) {
        $managedExistingListeners = @()
        foreach ($listener in $httpsListeners) {
            # WSMan-Listener stellen Hostname, Port und Fingerabdruck als
            # Kindelemente bereit, nicht verlässlich als direkte Eigenschaften
            # des Listener-Containers. Direkter Property-Zugriff lieferte bei
            # einem vorhandenen Listener einen leeren Fingerabdruck; der daraus
            # gebildete Cert:-Pfad zeigte dann auf den gesamten X509Store.
            $listenerValues = @{}
            foreach ($listenerValue in @(Get-ChildItem -LiteralPath $listener.PSPath -ErrorAction Stop)) {
                $listenerValueName = [string]$listenerValue.Name
                if (-not [string]::IsNullOrWhiteSpace($listenerValueName)) {
                    $listenerValues[$listenerValueName] = [string]$listenerValue.Value
                }
            }
            $listenerThumbprint = ([string]$listenerValues['CertificateThumbprint']).Trim() -replace '\s', ''
            $listenerHostname = ([string]$listenerValues['Hostname']).Trim()
            $listenerPort = 0
            $listenerPortIsValid = [int]::TryParse(
                ([string]$listenerValues['Port']).Trim(),
                [ref]$listenerPort
            )
            if ($listenerThumbprint -notmatch '^[a-fA-F0-9]{40}$') {
                throw 'SICHERHEITSABBRUCH: Ein vorhandener WinRM-HTTPS-Listener enthält keinen gültigen Zertifikatfingerabdruck. Mavi verändert diesen TLS-Endpunkt nicht.'
            }
            $listenerCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\My\$listenerThumbprint") -ErrorAction SilentlyContinue
            $listenerChainIsMavi = $false
            if ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $listenerChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $listenerChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                try {
                    if ($listenerChain.Build($listenerCertificate) -and $listenerChain.ChainElements.Count -gt 0) {
                        $listenerRoot = $listenerChain.ChainElements[$listenerChain.ChainElements.Count - 1].Certificate
                        $listenerChainIsMavi = $listenerRoot.Thumbprint.Equals(
                            $rootCertificate.Thumbprint,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
                }
                finally {
                    $listenerChain.Dispose()
                }
            }
            $expectedFriendlyName = "Mavi WinRM HTTPS $Fqdn"
            $listenerIsMaviManaged = (
                $listenerPortIsValid -and
                ($listenerPort -eq $Port) -and
                $listenerHostname.Equals($Fqdn, [System.StringComparison]::OrdinalIgnoreCase) -and
                ($listenerCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) -and
                ([string]$listenerCertificate.FriendlyName).Equals($expectedFriendlyName, [System.StringComparison]::Ordinal) -and
                $listenerChainIsMavi
            )
            if (-not $listenerIsMaviManaged) {
                throw 'SICHERHEITSABBRUCH: Es existiert bereits ein fremder WinRM-HTTPS-Listener. Mavi ersetzt fremde TLS-Endpunkte nie still.'
            }
            $managedExistingListeners += [PSCustomObject]@{
                Listener = $listener
                CertificateThumbprint = $listenerThumbprint
            }
        }

        $alreadyCurrent = @(
            $managedExistingListeners | Where-Object {
                ([string]$_.CertificateThumbprint).Equals($selected.Thumbprint, [System.StringComparison]::OrdinalIgnoreCase)
            }
        )
        if ($managedExistingListeners.Count -ne 1 -or $alreadyCurrent.Count -ne 1) {
            foreach ($listener in $managedExistingListeners) {
                Remove-Item -LiteralPath $listener.Listener.PSPath -Recurse -Force -ErrorAction Stop
            }
            New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
        }
    }
    else {
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Transport = 'HTTPS'; Address = '*' } -ValueSet @{ Hostname = $Fqdn; CertificateThumbprint = $selected.Thumbprint } -ErrorAction Stop | Out-Null
    }

$existingAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    $portFilter = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
    foreach ($filter in $portFilter) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains [string]$Port) {
            if ([string]$rule.DisplayName -ne $RuleName) { $existingAllowRules += $rule }
        }
    }
}
if ($existingAllowRules.Count -gt 0) {
    $names = ($existingAllowRules | Select-Object -ExpandProperty DisplayName -Unique) -join ', '
    throw "SICHERHEITSABBRUCH: Bereits aktive Firewall-Freigabe(n) für TCP/$Port gefunden: $names. Mavi lässt keinen breiteren parallelen HTTPS-Zugang stehen."
}
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $RuleName -Group 'Mavi Provisioner' -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $Port -RemoteAddress $AnsibleServerIp -EdgeTraversalPolicy Block | Out-Null
$managedRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
$managedPort = @($managedRule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object -First 1)
$managedAddress = @($managedRule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object -First 1)
if ($managedPort.Count -ne 1 -or [string]$managedPort[0].Protocol -ne 'TCP' -or -not (@($managedPort[0].LocalPort) -contains [string]$Port)) {
    throw 'Mavi WinRM TLS: die eigene TCP-Port-Firewallregel konnte nicht exakt geprüft werden.'
}
$managedRemoteAddresses = @($managedAddress[0].RemoteAddress)
if ($managedAddress.Count -ne 1 -or $managedRemoteAddresses.Count -ne 1 -or [string]$managedRemoteAddresses[0] -ne $AnsibleServerIp) {
    throw 'Mavi WinRM TLS: die eigene Firewallregel ist nicht exakt auf die Ansible-IP beschränkt.'
}

# HTTP vollständig entfernen, solange der lokale Provider in der isolierten
# Phase noch erreichbar ist. Die dauerhafte Block-Regel für 5985 bleibt auch
# danach bestehen.
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remainingHttpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remainingHttpListeners.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallAllowRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallAllowRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}
}
finally {
    # Diese ADMX-gestützten Dienstwerte sind die fail-closed Endstellung.
    # Der Block für 5986 bleibt bei jedem Fehler erhalten. Damit ist während
    # und nach einem fehlgeschlagenen Lauf weder HTTP noch Negotiate von außen
    # erreichbar; OpenSSH bleibt als Reparaturkanal bestehen.
    New-Item -Path $policyPath -Force | Out-Null
    Set-ItemProperty -Path $policyPath -Name AllowUnencryptedTraffic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowKerberos -Type DWord -Value 1 -Force
    Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowBasic -Type DWord -Value 0 -Force
    Set-ItemProperty -Path $policyPath -Name AllowCredSSP -Type DWord -Value 0 -Force
    Restart-Service -Name WinRM -Force -ErrorAction Stop
}

$finalPolicy = Get-ItemProperty -Path $policyPath -ErrorAction Stop
if ([int]$finalPolicy.AllowUnencryptedTraffic -ne 0 -or
    [int]$finalPolicy.AllowKerberos -ne 1 -or
    [int]$finalPolicy.AllowNegotiate -ne 0 -or
    [int]$finalPolicy.AllowBasic -ne 0 -or
    [int]$finalPolicy.AllowCredSSP -ne 0) {
    throw 'SICHERHEITSABBRUCH: Die WinRM-Dienstrichtlinie ist nicht Kerberos-only.'
}
$remainingHttpAllowRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $remainingHttpAllowRules += $rule
            break
        }
    }
}
if ($remainingHttpAllowRules.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}

# Erst nach dem finalen Service-Neustart fällt die Setup-Isolation für 5986.
# Die enge Allow-Regel von ausschließlich der Ansible-IP bleibt bestehen.
Get-NetFirewallRule -DisplayName $setupIsolationRuleName -ErrorAction Stop |
    Remove-NetFirewallRule -ErrorAction Stop

$result = [ordered]@{
    Thumbprint = $selected.Thumbprint
    CertificateSha256 = $actualSha256.ToLowerInvariant()
    Fqdn = $Fqdn
    Port = $Port
    FirewallRule = $RuleName
    Http5985Blocked = $true
    KerberosOnly = $true
}
$marker = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $true
'''
    remote_dir = r"C:\ProgramData\Mavi\WinRM-TLS"
    remote_path = remote_dir + r"\mavi-winrm-server.cer"
    remote_ca_path = remote_dir + r"\mavi-winrm-root-ca.cer"
    return [{
        "name": "Mavi WinRM HTTPS sicher einrichten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Mavi WinRM TLS-Arbeitsordner sicherstellen",
                "ansible.windows.win_file": {"path": remote_dir, "state": "directory"},
            },
            {
                "name": "Öffentliche Mavi-WinRM-Root-CA nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": ca_certificate_path,
                    "dest": remote_ca_path,
                    "force": True,
                },
            },
            {
                "name": "Signiertes Mavi-WinRM-Zertifikat nach Windows kopieren",
                "ansible.windows.win_copy": {
                    "src": certificate_path,
                    "dest": remote_path,
                    "force": True,
                },
            },
            {
                "name": "WinRM HTTPS-Listener und enge Firewallregel konfigurieren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "CertificatePath": remote_path,
                        "ExpectedSha256": certificate_sha256,
                        "RootCertificatePath": remote_ca_path,
                        "ExpectedRootSha256": ca_certificate_sha256,
                        "Fqdn": identity["fqdn"],
                        "AnsibleServerIp": ansible_server_ip,
                        "Port": int(settings["port"]),
                        "RuleName": "Mavi-WinRM-HTTPS-Ansible-In-TCP",
                    },
                },
                "register": "mavi_winrm_https_install",
            },
            {
                "name": "Mavi WinRM HTTPS-Ergebnis auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINRM_HTTPS_B64={{ mavi_winrm_https_install.result.Marker }}",
                },
            },
        ],
    }]


def _winrm_remove_http_play() -> list[dict[str, Any]]:
    """HTTP-Listener ausschließlich über die bereits geprüfte TLS-Verbindung entfernen."""
    powershell = r'''[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$httpListeners = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
foreach ($listener in $httpListeners) {
    Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
}
$remaining = @(
    Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop |
    Where-Object { $_.Keys -contains 'Transport=HTTP' }
)
if ($remaining.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens ein WinRM-HTTP-Listener ist weiterhin aktiv.'
}
$httpFirewallRules = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $httpFirewallRules += $rule
            break
        }
    }
}
foreach ($rule in @($httpFirewallRules | Select-Object -Unique)) {
    Disable-NetFirewallRule -InputObject $rule -ErrorAction Stop | Out-Null
}
$stillEnabled = @()
foreach ($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop)) {
    foreach ($filter in @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)) {
        if ([string]$filter.Protocol -eq 'TCP' -and @($filter.LocalPort) -contains '5985') {
            $stillEnabled += $rule
            break
        }
    }
}
if ($stillEnabled.Count -gt 0) {
    throw 'SICHERHEITSABBRUCH: mindestens eine TCP/5985-Firewallfreigabe ist weiterhin aktiv.'
}
$Ansible.Result = @{ RemovedHttpListeners = $httpListeners.Count }
$Ansible.Changed = ($httpListeners.Count -gt 0)
'''
    return [{
        "name": "Mavi WinRM HTTP nach HTTPS-Nachweis abschalten",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Alte WinRM-HTTP-Listener entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                },
            },
        ],
    }]


def _winrm_reset_play(
    *,
    root_thumbprint: str,
    disable_openssh: bool = False,
    public_key_prefix: str = "",
    key_marker: str = "",
    openssh_firewall_rule: str = "",
) -> list[dict[str, Any]]:
    """Mavi-WinRM über den unabhängigen OpenSSH-Kanal auf Stand 0 setzen."""
    powershell = r'''[CmdletBinding()]
param(
    [string]$RootThumbprint = '',
    [int]$DisableOpenSshValue = 0,
    [string]$CurrentKeyPrefix = '',
    [string]$CurrentKeyMarker = '',
    [string]$OpenSshFirewallRuleName = ''
)

$ErrorActionPreference = 'Stop'
$disableOpenSsh = ($DisableOpenSshValue -eq 1)
$RootThumbprint = ($RootThumbprint -replace '\s', '').ToUpperInvariant()
if (-not [string]::IsNullOrWhiteSpace($RootThumbprint) -and $RootThumbprint -notmatch '^[A-F0-9]{40}$') {
    throw 'Mavi WinRM Reset: Der Root-CA-Fingerabdruck ist ungültig.'
}
if ($disableOpenSsh -and $OpenSshFirewallRuleName -notmatch '^[A-Za-z0-9_.-]{1,255}$') {
    throw 'Mavi Remote-Aus: Der Name der OpenSSH-Firewallregel ist ungültig.'
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Mavi WinRM Reset benötigt einen erhöhten lokalen Administrator-Token; aktuell: $($identity.Name)"
}

$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
$policyNames = @(
    'AllowUnencryptedTraffic',
    'AllowKerberos',
    'AllowNegotiate',
    'AllowBasic',
    'AllowCredSSP'
)
$firewallNames = @(
    'Mavi-WinRM-HTTPS-Ansible-In-TCP',
    'Mavi-WinRM-HTTP-Dauerhaft-Block-TCP',
    'Mavi-WinRM-HTTPS-Setup-Isolation-TCP'
)
$workDirectory = Join-Path $env:ProgramData 'Mavi\WinRM-TLS'
$removedListeners = 0
$removedCertificates = 0
$removedFirewallRules = 0
$removedOpenSshKeys = 0
$openSshDisableScheduled = $false
$remainingListeners = -1
$cleanupError = $null

try {
    # Ein Mavi-Endzustand blockiert Negotiate per Richtlinie. Für die lokale
    # WSMan:-Verwaltung über die unabhängige SSH-Sitzung wird es kurz aktiviert.
    New-Item -Path $policyPath -Force | Out-Null
    Set-ItemProperty -Path $policyPath -Name AllowNegotiate -Type DWord -Value 1 -Force
    Set-Service -Name WinRM -StartupType Manual -ErrorAction Stop
    Start-Service -Name WinRM -ErrorAction SilentlyContinue
    Restart-Service -Name WinRM -Force -ErrorAction Stop

    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $false -Force -ErrorAction Stop
    Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force -ErrorAction Stop

    $listeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop)
    foreach ($listener in $listeners) {
        Remove-Item -LiteralPath $listener.PSPath -Recurse -Force -ErrorAction Stop
        $removedListeners++
    }
    # Den WSMan-Provider nur abfragen, solange WinRM noch läuft. Ein Zugriff
    # nach Stop/Disable kann lokal bis zum Ansible-Timeout blockieren.
    $remainingListeners = @(Get-ChildItem -Path WSMan:\localhost\Listener -ErrorAction Stop).Count
    if ($remainingListeners -ne 0) {
        throw 'Mavi WinRM Reset: Nicht alle WinRM-Listener konnten entfernt werden.'
    }

    foreach ($name in $firewallNames) {
        $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removedFirewallRules++
        }
    }

    $effectiveRootThumbprint = $RootThumbprint
    $remoteRootPath = Join-Path $workDirectory 'mavi-winrm-root-ca.cer'
    if ([string]::IsNullOrWhiteSpace($effectiveRootThumbprint) -and (Test-Path -LiteralPath $remoteRootPath -PathType Leaf)) {
        $remoteRoot = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remoteRootPath)
        $effectiveRootThumbprint = ([string]$remoteRoot.Thumbprint).ToUpperInvariant()
    }

    $rootSubject = ''
    if ($effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $rootCertificate = Get-Item -LiteralPath ("Cert:\LocalMachine\Root\$effectiveRootThumbprint") -ErrorAction SilentlyContinue
        if ($null -ne $rootCertificate) {
            $rootSubject = [string]$rootCertificate.Subject
        }
    }

    foreach ($storePath in @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Request')) {
        if (-not (Test-Path -LiteralPath $storePath)) { continue }
        foreach ($certificate in @(Get-ChildItem -LiteralPath $storePath -ErrorAction SilentlyContinue)) {
            $isMaviLeaf = ([string]$certificate.FriendlyName) -like 'Mavi WinRM HTTPS *'
            if (-not [string]::IsNullOrWhiteSpace($rootSubject)) {
                $isMaviLeaf = $isMaviLeaf -or ([string]$certificate.Issuer).Equals(
                    $rootSubject,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
            if ($isMaviLeaf) {
                Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
                $removedCertificates++
            }
        }
    }

    if ($effectiveRootThumbprint -match '^[A-F0-9]{40}$') {
        $rootPath = "Cert:\LocalMachine\Root\$effectiveRootThumbprint"
        if (Test-Path -LiteralPath $rootPath) {
            Remove-Item -LiteralPath $rootPath -Force -ErrorAction Stop
            $removedCertificates++
        }
    }

    if (Test-Path -LiteralPath $workDirectory) {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force -ErrorAction Stop
    }
}
catch {
    $cleanupError = $_.Exception.Message
}
finally {
    if (Test-Path -LiteralPath $policyPath) {
        foreach ($name in $policyNames) {
            Remove-ItemProperty -LiteralPath $policyPath -Name $name -Force -ErrorAction SilentlyContinue
        }
    }
    Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
}

if (-not [string]::IsNullOrWhiteSpace($cleanupError)) {
    throw "Mavi WinRM Reset wurde nicht vollständig ausgeführt: $cleanupError"
}

$service = Get-Service -Name WinRM -ErrorAction Stop
$serviceStartValue = [int](Get-ItemPropertyValue `
    -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM' `
    -Name Start `
    -ErrorAction Stop
)
if ($remainingListeners -ne 0 -or [string]$service.Status -ne 'Stopped' -or $serviceStartValue -ne 4) {
    throw 'Mavi WinRM Reset: Der abschließende Stand-0-Nachweis ist fehlgeschlagen.'
}

if ($disableOpenSsh) {
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($null -eq $sshdService) {
        throw 'Mavi Remote-Aus: Der OpenSSH-Serverdienst sshd wurde nicht gefunden.'
    }

    # Der laufende SSH-Kanal darf seine Erfolgsmeldung noch zurückgeben. Der
    # Dienst wird bereits jetzt für jeden Neustart deaktiviert und wenige
    # Sekunden später durch einen einmaligen SYSTEM-Task gestoppt.
    Set-Service -Name sshd -StartupType Disabled -ErrorAction Stop

    $keyFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    if (Test-Path -LiteralPath $keyFile -PathType Leaf) {
        $keyLines = @(Get-Content -LiteralPath $keyFile -ErrorAction Stop)
        $keptKeyLines = New-Object 'System.Collections.Generic.List[string]'
        foreach ($keyLineObject in $keyLines) {
            $keyLine = [string]$keyLineObject
            $trimmedKeyLine = $keyLine.Trim()
            $isMaviKey = $false
            if (-not [string]::IsNullOrWhiteSpace($CurrentKeyMarker)) {
                $markerPattern = '(^|\s)' + [regex]::Escape($CurrentKeyMarker) + '(\s|$)'
                $isMaviKey = $trimmedKeyLine -match $markerPattern
            }
            if (
                -not $isMaviKey -and
                -not [string]::IsNullOrWhiteSpace($CurrentKeyPrefix) -and
                ($trimmedKeyLine -eq $CurrentKeyPrefix -or $trimmedKeyLine.StartsWith($CurrentKeyPrefix + ' '))
            ) {
                $isMaviKey = $true
            }
            if ($isMaviKey) {
                $removedOpenSshKeys++
                continue
            }
            $keptKeyLines.Add($keyLine)
        }
        if ($removedOpenSshKeys -gt 0) {
            [System.IO.File]::WriteAllLines(
                $keyFile,
                [string[]]$keptKeyLines,
                [System.Text.Encoding]::ASCII
            )
        }
    }

    $taskName = 'Mavi-Disable-RemoteAccess-' + [Guid]::NewGuid().ToString('N')
    $childScript = @'
$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 20
Get-NetFirewallRule -Name '__MAVI_FIREWALL_RULE_NAME__' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Stop-Service -Name sshd -Force -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType Disabled -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '__MAVI_TASK_NAME__' -Confirm:$false -ErrorAction SilentlyContinue
'@
    $childScript = $childScript.Replace('__MAVI_TASK_NAME__', $taskName)
    $childScript = $childScript.Replace('__MAVI_FIREWALL_RULE_NAME__', $OpenSshFirewallRuleName)
    $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $taskAction = New-ScheduledTaskAction `
        -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedScript"
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $taskAction `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Force | Out-Null
    $beforeTaskRun = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop).LastRunTime
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $taskStartDeadline = (Get-Date).AddSeconds(6)
    do {
        Start-Sleep -Milliseconds 250
        $scheduledTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $scheduledTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        if ($scheduledTask.State -eq 'Running' -or $scheduledTaskInfo.LastRunTime -gt $beforeTaskRun) {
            $openSshDisableScheduled = $true
            break
        }
    } while ((Get-Date) -lt $taskStartDeadline)
    if (-not $openSshDisableScheduled) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        throw 'Mavi Remote-Aus: Der verzögerte sshd-Stopp konnte nicht gestartet werden.'
    }
}

$Ansible.Result = @{
    RemovedListeners = $removedListeners
    RemovedCertificates = $removedCertificates
    RemovedFirewallRules = $removedFirewallRules
    RemovedOpenSshKeys = $removedOpenSshKeys
    OpenSshDisableScheduled = $openSshDisableScheduled
    WinRMState = [string]$service.Status
    WinRMStartMode = 'Disabled'
}
$Ansible.Changed = $true
'''
    return [{
        "name": "Mavi WinRM und Kerberos-Transport auf Stand 0 zurücksetzen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "WinRM-Listener, Mavi-Zertifikate, Regeln und Richtlinien entfernen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "RootThumbprint": root_thumbprint,
                        "DisableOpenSshValue": 1 if disable_openssh else 0,
                        "CurrentKeyPrefix": public_key_prefix,
                        "CurrentKeyMarker": key_marker,
                        "OpenSshFirewallRuleName": openssh_firewall_rule,
                    },
                },
            },
        ],
    }]


def _winrm_kerberos_https_ping_play() -> list[dict[str, Any]]:
    """Minimaler echter PSRP-Test; die Aufrufer legen die TLS/Kerberos-Variablen als Overlay fest."""
    return [{
        "name": "Mavi Kerberos-HTTPS-Nachweis",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "PSRP über strikt validiertes HTTPS und Kerberos prüfen",
                "ansible.windows.win_ping": {},
            },
        ],
    }]

__all__ = (
    "get_ssh_settings",
    "_ssh_environment_marker",
    "_host_inventory_entry",
    "_effective_host_var",
    "_connection_label",
    "_clear_host_transport_vars",
    "_apply_ssh_transport",
    "_apply_psrp_transport",
    "_psrp_https_inventory_vars",
    "_apply_psrp_https_transport",
    "_remember_winrm_https_state",
    "_saved_winrm_https_transport",
    "_apply_saved_winrm_https_transport",
    "_normalize_winrm_dns_name",
    "_winrm_https_settings",
    "_kerberos_runtime_config_path",
    "_normalize_kerberos_dns_server",
    "_configured_kerberos_dns_servers",
    "_direct_dns_query",
    "_discover_kerberos_kdc_endpoints",
    "_activate_existing_kerberos_runtime_config",
    "_prepare_kerberos_runtime_config",
    "_winrm_https_target_identity",
    "_kerberos_principal_for_host",
    "_vault_host_context",
    "_vault_ansible_user_for_host",
    "_winrm_pki_paths",
    "_winrm_local_command",
    "_ensure_winrm_ca",
    "_winrm_leaf_openssl_config",
    "_issue_winrm_server_certificate",
    "_remove_host_winrm_certificate_artifacts",
    "_absolute_without_symlink",
    "_ansible_playbook_candidates",
    "_ANSIBLE_RUNTIME_CACHE",
    "_ansible_playbook_runtime",
    "_ansible_playbook_executable",
    "_ansible_controller_python",
    "_ansible_inventory_executable",
    "_ansible_runtime_environment",
    "_python_imports_gssapi",
    "_controller_root_prefix",
    "_ansible_pipx_venv_root",
    "_ansible_pipx_package",
    "_pipx_command_for_ansible",
    "_ensure_psrp_kerberos_controller_dependencies",
    "_is_missing_gssapi_failure",
    "_temporary_psrp_vault_inventory",
    "_vault_psrp_password_for_host",
    "_discard_kerberos_ticket_cache",
    "_verify_kerberos_ticket_cache",
    "_acquire_vault_kerberos_ticket",
    "_kerberos_cache_connection_overrides",
    "_open_client_ansible_session",
    "_close_client_ansible_session",
    "_run_winrm_temporary_play",
    "_winrm_csr_play",
    "_extract_winrm_csr",
    "_winrm_install_https_play",
    "_winrm_remove_http_play",
    "_winrm_reset_play",
    "_winrm_kerberos_https_ping_play",
)
