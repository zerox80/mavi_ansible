# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Transport- und WinRM-Einstellungen.

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


def _host_inventory_entry(project: Path, host: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    from .remote import (
        _validate_inventory_host_alias,
    )

    from .environment import die
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    try:
        _validate_inventory_host_alias(host)
    except ValueError as exc:
        die(str(exc))

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
    from .remote import (
        _effective_host_var,
    )

    connection = str(_effective_host_var(windows, host_data, "ansible_connection", "psrp") or "psrp").lower()
    if connection == "mavi_disabled":
        return "AUS"
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


def _apply_remote_management_disabled_transport(host_data: dict[str, Any]) -> None:
    """Den Host trotz geerbter Gruppenvariablen explizit fail-closed schalten."""
    from .remote import (
        _clear_host_transport_vars,
    )

    _clear_host_transport_vars(host_data)
    # windows.vars verwendet in bestehenden Projekten häufig SSH als Standard.
    # Ein bloßes Entfernen des Host-Overrides würde diesen abgeschalteten Host
    # deshalb sofort wieder auf SSH erben lassen. Der absichtlich nicht
    # existierende Connection-Plugin-Name verhindert Remote-Ausführungen, bis
    # cmd_ssh_use den Transport nach dem lokalen Starter bewusst neu setzt.
    host_data["ansible_connection"] = "mavi_disabled"


def _apply_ssh_transport(
    project: Path,
    host_data: dict[str, Any],
    *,
    key_path: Path | None = None,
    port: int | None = None,
) -> tuple[Path, int]:
    from .remote import (
        _clear_host_transport_vars,
        get_ssh_settings,
    )

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
    # Der aktive Ansible-Port und -Key werden beim Wechsel auf PSRP ersetzt bzw.
    # entfernt. Beide SSH-Werte behalten wir deshalb für Host-Key-Audits und
    # einen späteren, gezielten Rückwechsel ausdrücklich pro Host im Gedächtnis.
    host_data["mavi_ssh_port"] = resolved_port
    host_data["mavi_ssh_private_key_file"] = str(resolved_key)
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

    from .remote import (
        _clear_host_transport_vars,
        _psrp_https_inventory_vars,
    )

    # Auch Inventare, die vor Einführung des separaten Mavi-Merkfelds angelegt
    # wurden, verlieren beim Transportwechsel nicht ihren hostbezogenen Key.
    active_ssh_key = str(
        host_data.get("ansible_ssh_private_key_file", "") or ""
    ).strip()
    if active_ssh_key:
        host_data["mavi_ssh_private_key_file"] = str(
            Path(active_ssh_key).expanduser().resolve()
        )
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
    certificate_thumbprint: str,
    certificate_not_after: str,
    root_thumbprint: str,
    root_not_after: str,
    pruned_server_certificates: int,
) -> None:
    """Nur nach doppeltem Kerberos-Nachweis persistierte Transport-Metadaten."""
    from .remote import (
        _normalized_certificate_thumbprint,
    )


    from .openssh import _sha256_file
    host_data["mavi_winrm_https"] = {
        "version": 2,
        "kerberos_verified": True,
        "auth": "kerberos",
        "fqdn": fqdn,
        "port": int(settings["port"]),
        "kerberos_principal": kerberos_principal,
        "ca_sha256": _sha256_file(ca_cert).lower(),
        "certificate_thumbprint": _normalized_certificate_thumbprint(certificate_thumbprint),
        "certificate_not_after": str(certificate_not_after or ""),
        "root_thumbprint": _normalized_certificate_thumbprint(root_thumbprint),
        "root_not_after": str(root_not_after or ""),
        "pruned_server_certificates": max(0, int(pruned_server_certificates)),
    }


def _saved_winrm_https_transport(
    project: Path,
    host_data: dict[str, Any],
) -> tuple[dict[str, Any], str, Path, str]:
    """Gespeicherte Kerberos-HTTPS-Endstufe eng prüfen, nie raten oder downgraden."""
    from .remote import (
        _normalize_winrm_dns_name,
        _winrm_https_settings,
        _winrm_pki_paths,
    )

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
    from .remote import (
        _apply_psrp_https_transport,
        _saved_winrm_https_transport,
    )

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
    from .remote import (
        _normalize_winrm_dns_name,
    )

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


def _ssh_environment_marker(project: Path) -> str:
    """Stable project-scoped marker; never matches keys from another project."""
    project_identity = str(project.expanduser().resolve()).casefold().encode("utf-8")
    digest = hashlib.sha256(project_identity).hexdigest()[:16]
    return f"mavi-provisioner-{digest}"
