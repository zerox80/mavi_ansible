# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""HTTPS-Bootstrapserver und Veröffentlichung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    ThreadPoolExecutor,
    argparse,
    as_completed,
    base64,
    datetime,
    getpass,
    hashlib,
    ipaddress,
    json,
    os,
    re,
    secrets,
    shutil,
    socket,
    ssl,
    subprocess,
    sys,
    tempfile,
    time,
    timezone,
    urllib,
    yaml,
)



def _bootstrap_settings(project: Path) -> dict[str, Any]:
    """Zentrale HTTPS-Bootstrap-Konfiguration validieren und normalisieren."""

    from .openssh import (
        _bootstrap_instance_id,
    )
    from .environment import get_config

    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "").strip()
    local_dir_raw = str(config.get("bootstrap_local_dir", "") or "").strip()
    ansible_server_ip = str(config.get("ansible_server_ip", "") or "").strip()
    expected_signer = str(config.get("openssh_msi_expected_signer", "") or "").strip()
    allowed_cidrs_raw = config.get("bootstrap_allowed_cidrs", [])
    ca_validity_raw = config.get("bootstrap_ca_validity_days", 825)
    server_validity_raw = config.get("bootstrap_server_cert_validity_days", 90)
    instance_id = _bootstrap_instance_id(project, config)

    if not base_url:
        raise ValueError("bootstrap_base_url fehlt.")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("bootstrap_base_url muss mit https:// beginnen; HTTP ist unzulässig.")
    try:
        url_port = parsed.port
    except ValueError as exc:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.") from exc
    if url_port is not None and not 1 <= url_port <= 65535:
        raise ValueError("bootstrap_base_url enthält einen ungültigen Port.")
    effective_port = url_port if url_port is not None else 443
    if not parsed.hostname:
        raise ValueError("bootstrap_base_url enthält keinen gültigen Hostnamen bzw. keine IP.")
    url_host = str(parsed.hostname)
    try:
        parsed_url_ip = ipaddress.ip_address(url_host)
    except ValueError:
        try:
            url_host_ascii = url_host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.") from exc
        if (
            len(url_host_ascii) > 253
            or not re.fullmatch(
                r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?",
                url_host_ascii,
            )
        ):
            raise ValueError("bootstrap_base_url enthält einen ungültigen DNS-Namen.")
        url_host = url_host_ascii.rstrip(".").lower()
        netloc_host = url_host
    else:
        url_host = str(parsed_url_ip)
        netloc_host = f"[{url_host}]" if parsed_url_ip.version == 6 else url_host
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("bootstrap_base_url darf keine Zugangsdaten enthalten.")
    if parsed.query or parsed.fragment:
        raise ValueError("bootstrap_base_url darf weder Query noch Fragment enthalten.")
    if any(ord(char) < 32 or ord(char) == 127 for char in base_url):
        raise ValueError("bootstrap_base_url darf keine Steuerzeichen enthalten.")
    normalized_path = parsed.path or "/"
    if not normalized_path.endswith("/"):
        normalized_path += "/"
    if (
        normalized_path == "/"
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]*/", normalized_path)
        or "//" in normalized_path
        or "\\" in normalized_path
        or any(part in {".", ".."} for part in normalized_path.split("/"))
    ):
        raise ValueError(
            "bootstrap_base_url benötigt einen eigenen einfachen URL-Pfad, z. B. /mavi-bootstrap/."
        )
    normalized_netloc = netloc_host + (f":{url_port}" if url_port is not None else "")
    base_url = urllib.parse.urlunsplit((
        "https",
        normalized_netloc,
        normalized_path,
        "",
        "",
    ))

    if not local_dir_raw:
        raise ValueError("bootstrap_local_dir fehlt.")
    local_dir_candidate = Path(local_dir_raw).expanduser()
    if not local_dir_candidate.is_absolute():
        raise ValueError("bootstrap_local_dir muss ein absoluter lokaler Pfad sein.")
    local_dir = local_dir_candidate.resolve(strict=False)
    safe_webroot_parents = (Path("/var/www"), Path("/srv"), Path("/opt"), Path("/mnt"))
    in_safe_parent = False
    for parent in safe_webroot_parents:
        try:
            local_dir.relative_to(parent)
        except ValueError:
            continue
        if local_dir != parent:
            in_safe_parent = True
            break
    if not in_safe_parent:
        raise ValueError(
            "bootstrap_local_dir muss ein eigener Unterordner unter /var/www, /srv, /opt oder /mnt sein. "
            "Empfohlen: /var/www/mavi-bootstrap"
        )
    try:
        parsed_ip = ipaddress.ip_address(ansible_server_ip)
    except ValueError as exc:
        raise ValueError("ansible_server_ip fehlt oder ist keine einzelne gültige IP-Adresse.") from exc
    if parsed_ip.is_unspecified or parsed_ip.is_multicast or parsed_ip.is_loopback or parsed_ip.is_link_local:
        raise ValueError(
            "ansible_server_ip darf weder Wildcard-, Multicast-, Loopback- noch Link-Local-Adresse sein."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in expected_signer):
        raise ValueError("openssh_msi_expected_signer darf keine Steuerzeichen enthalten.")

    try:
        ca_validity_days = int(ca_validity_raw)
        server_cert_validity_days = int(server_validity_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "bootstrap_ca_validity_days und bootstrap_server_cert_validity_days müssen Ganzzahlen sein."
        ) from exc
    if not 90 <= ca_validity_days <= 1825:
        raise ValueError("bootstrap_ca_validity_days muss zwischen 90 und 1825 liegen.")
    if not 1 <= server_cert_validity_days <= 397:
        raise ValueError("bootstrap_server_cert_validity_days muss zwischen 1 und 397 liegen.")
    if server_cert_validity_days >= ca_validity_days:
        raise ValueError(
            "bootstrap_server_cert_validity_days muss kürzer als bootstrap_ca_validity_days sein."
        )
    if allowed_cidrs_raw in (None, "", []):
        allowed_values: list[str] = []
    elif isinstance(allowed_cidrs_raw, str):
        allowed_values = [x.strip() for x in allowed_cidrs_raw.split(",") if x.strip()]
    elif isinstance(allowed_cidrs_raw, list):
        allowed_values = [str(x or "").strip() for x in allowed_cidrs_raw if str(x or "").strip()]
    else:
        raise ValueError("bootstrap_allowed_cidrs muss eine YAML-Liste oder kommaseparierte Zeichenfolge sein.")

    if not allowed_values:
        private_candidates = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        matching_private = [network for network in private_candidates if parsed_ip in network]
        if matching_private:
            allowed_networks = matching_private
        elif parsed_ip.version == 4:
            allowed_networks = [ipaddress.ip_network("0.0.0.0/0")]
        else:
            allowed_networks = [ipaddress.ip_network("::/0")]
    else:
        try:
            allowed_networks = [ipaddress.ip_network(value, strict=False) for value in allowed_values]
        except ValueError as exc:
            raise ValueError(f"Ungültiges Netz in bootstrap_allowed_cidrs: {exc}") from exc

    # Normalisieren und doppelte Netze entfernen, damit Statusvergleiche stabil bleiben.
    allowed_networks = list(dict.fromkeys(allowed_networks))

    return {
        "base_url": base_url,
        "local_dir": local_dir,
        "ansible_server_ip": str(parsed_ip),
        "expected_signer": expected_signer,
        "url_host": url_host,
        "url_path": normalized_path,
        "port": int(effective_port),
        "allowed_cidrs": [str(network) for network in allowed_networks],
        "instance_id": instance_id,
        "ca_validity_days": ca_validity_days,
        "server_cert_validity_days": server_cert_validity_days,
    }


def _bootstrap_setup_instruction(project: Path, *, reason: str = "") -> str:
    """Einmalige Fehlerhilfe für die Vollautomatik, ohne unsicheren Fallback."""
    from .environment import (
        get_config,
        project_paths,
    )
    from .reports import redact_sensitive_text

    config = get_config(project)
    base_url = str(config.get("bootstrap_base_url", "") or "<HTTPS-BASIS-URL>").strip()
    local_dir = str(config.get("bootstrap_local_dir", "") or "/var/www/mavi-bootstrap").strip()
    safe_base_url = redact_sensitive_text(base_url)
    safe_local_dir = redact_sensitive_text(local_dir)
    safe_config_path = redact_sensitive_text(project_paths(project)["config"])
    lines = []
    if reason:
        lines.extend([f"Grund: {redact_sensitive_text(reason)}", ""])
    lines.extend([
        "Die Mavi-Vollautomatik konnte das Server-Setup nicht abschließen.",
        f"  Konfiguration: {safe_config_path}",
        f"  HTTPS-Ziel:    {safe_base_url}",
        f"  Webroot:       {safe_local_dir}",
        "Nach Korrektur des gemeldeten Grundes einfach erneut starten:",
        "  mavi-provisioner ssh server-setup",
        "Mavi installiert und konfiguriert nginx, CA, SAN-Zertifikat, Webroot und Firewall selbst.",
        "Es gibt ausdrücklich keinen HTTP-Fallback und keine deaktivierte Zertifikatsprüfung.",
    ])
    return "\n".join(lines)


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _atomic_copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        shutil.copy2(source, tmp_path)
        if os.name != "nt":
            os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, destination)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bootstrap_pki_paths(project: Path) -> dict[str, Path]:
    """Alle privilegierten Bootstrap-Artefakte strikt pro Laufzeitprojekt isolieren."""

    from .openssh import (
        _bootstrap_instance_id,
    )
    instance_id = _bootstrap_instance_id(project)
    root = Path("/etc/mavi-bootstrap/instances") / instance_id
    pki = root / "pki"
    return {
        "root": root,
        "pki": pki,
        "ca_archive": root / "trusted-roots",
        "ca_key": pki / "mavi-bootstrap-root-ca.key.pem",
        "ca_cert": pki / "mavi-bootstrap-root-ca.cert.pem",
        "server_key": pki / "mavi-bootstrap-server.key.pem",
        "server_cert": pki / "mavi-bootstrap-server.cert.pem",
        "server_csr": pki / "mavi-bootstrap-server.csr.pem",
        "openssl_config": pki / "mavi-bootstrap-server.cnf",
        "state": root / "server-state.json",
        "nginx_config": Path(f"/etc/nginx/conf.d/mavi-bootstrap-{instance_id}.conf"),
        "system_ca": Path(
            f"/usr/local/share/ca-certificates/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
        "system_ca_anchor": Path(
            f"/etc/pki/ca-trust/source/anchors/mavi-bootstrap-{instance_id}-root-ca.crt"
        ),
    }


def _bootstrap_launcher_roots(project: Path) -> tuple[Path | None, str]:
    """Lokalen Ablagepfad und den dazugehörigen Windows-Pfad ableiten."""
    from .environment import get_config

    config = get_config(project)
    source = config.get("software_source", {}) or {}
    local_override = str(config.get("bootstrap_launcher_local_dir", "") or "").strip()
    windows_override = str(config.get("bootstrap_launcher_windows_dir", "") or "").strip()

    if local_override:
        local_root = Path(local_override).expanduser()
        if not local_root.is_absolute():
            raise ValueError("bootstrap_launcher_local_dir muss absolut sein.")
    else:
        software_local = str(source.get("local_root", "") or "").strip()
        local_root = Path(software_local).expanduser() / "Mavi-Bootstrap" if software_local else None
    if local_root is not None:
        if not local_root.is_absolute():
            raise ValueError("Die lokale Mavi-Starterablage muss ein absoluter Pfad sein.")
        local_root = local_root.resolve(strict=False)
        if local_root == Path("/") or len(local_root.parts) < 3:
            raise ValueError("Die lokale Mavi-Starterablage darf kein System- oder Mount-Wurzelpfad sein.")

    if windows_override:
        windows_root = windows_override.rstrip("\\/")
    else:
        drive = str(source.get("drive", "") or "").strip().replace("/", "\\").rstrip("\\")
        unc_root = str(source.get("unc_root", "") or "").strip().replace("/", "\\").rstrip("\\")
        windows_base = drive or unc_root
        windows_root = windows_base + "\\Mavi-Bootstrap" if windows_base else ""
    if windows_root:
        if any(ord(char) < 32 or ord(char) == 127 for char in windows_root):
            raise ValueError("Die Windows-Starterablage enthält unzulässige Steuerzeichen.")
        if not (re.match(r"^[A-Za-z]:\\", windows_root) or windows_root.startswith("\\\\")):
            raise ValueError("Die Windows-Starterablage muss ein absoluter Laufwerks- oder UNC-Pfad sein.")

    return local_root, windows_root


def _root_command(command: list[str], *, description: str, quiet: bool = False) -> None:
    from .environment import die
    from .reports import redact_sensitive_text

    print(f"  → {description}")
    try:
        if quiet:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            result = subprocess.run(command, check=False)
    except OSError as exc:
        die(f"{description} konnte nicht gestartet werden: {exc}")
    if result.returncode != 0:
        detail = ""
        if quiet and result.stderr:
            detail = "\n\n" + redact_sensitive_text(result.stderr.strip())
        die(f"{description} ist mit Exit-Code {result.returncode} fehlgeschlagen.{detail}")


def _install_bootstrap_server_packages() -> None:
    from .openssh import (
        _root_command,
    )

    from .environment import die

    required = ("nginx", "openssl", "ssh-keygen")
    ca_updater_available = bool(
        shutil.which("update-ca-certificates") or shutil.which("update-ca-trust")
    )
    if all(shutil.which(binary) for binary in required) and ca_updater_available:
        return

    if shutil.which("apt-get"):
        _root_command(["apt-get", "update"], description="Paketlisten aktualisieren")
        _root_command(
            [
                "apt-get", "install", "-y", "--no-install-recommends",
                "nginx", "openssl", "ca-certificates", "openssh-client",
            ],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    package_manager = shutil.which("dnf") or shutil.which("yum")
    if package_manager:
        _root_command(
            [package_manager, "install", "-y", "nginx", "openssl", "ca-certificates", "openssh-clients"],
            description="nginx, OpenSSL, CA-Zertifikate und OpenSSH-Client installieren",
        )
        return

    die("Kein unterstützter Paketmanager gefunden. Unterstützt werden apt, dnf und yum.")


def _bootstrap_operator_ids(project: Path) -> tuple[int, int]:
    """Bei sudo den ursprünglichen Mavi-Benutzer statt root als Webroot-Eigentümer verwenden."""
    try:
        uid = int(os.environ.get("SUDO_UID", ""))
        gid = int(os.environ.get("SUDO_GID", ""))
        if uid >= 0 and gid >= 0:
            return uid, gid
    except (TypeError, ValueError):
        pass
    try:
        project_stat = project.stat()
        if project_stat.st_uid != 0:
            return int(project_stat.st_uid), int(project_stat.st_gid)
    except OSError:
        pass
    return int(os.getuid()), int(os.getgid())


def _nginx_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _openssl_server_config(host: str) -> str:
    try:
        parsed_host = ipaddress.ip_address(host)
    except ValueError:
        san_line = f"DNS.1 = {host}"
    else:
        san_line = f"IP.1 = {parsed_host}"
    return (
        "[req]\n"
        "prompt = no\n"
        "distinguished_name = dn\n"
        "req_extensions = req_ext\n"
        "\n"
        "[dn]\n"
        f"CN = {host}\n"
        "O = Mavi\n"
        "OU = Automated Bootstrap\n"
        "\n"
        "[req_ext]\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[server_ext]\n"
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
        "subjectAltName = @alt_names\n"
        "\n"
        "[alt_names]\n"
        f"{san_line}\n"
    )


def _create_or_reuse_bootstrap_ca(
    settings: dict[str, Any],
    paths: dict[str, Path],
    *,
    rotate: bool = False,
) -> tuple[bool, Path | None]:
    """Instanz-CA erzeugen; Rotation nur explizit und mit recoverable Archiv."""

    from .openssh import (
        _archive_bootstrap_pki_for_rotation,
        _certificate_valid_for,
    )

    from .openssh import (
        _root_command,
    )

    from .environment import die

    ca_key = paths["ca_key"]
    ca_cert = paths["ca_cert"]
    if ca_cert.exists() and not ca_key.exists():
        die(
            "Das Mavi-CA-Zertifikat existiert, aber sein privater Schlüssel fehlt. "
            "Mavi rotiert die Vertrauenswurzel absichtlich nicht still. Backup wiederherstellen."
        )
    rotation_archive: Path | None = None
    if rotate and ca_cert.exists():
        # Die alte Root vor dem recoverable Voll-PKI-Archiv zusätzlich in den
        # dauerhaften DER-Index übernehmen. Andernfalls wäre bei der ersten
        # Rotation nach einem Upgrade nur die neue Root exakt löschbar.
        _archive_bootstrap_root_ca(paths)
    if rotate and (ca_cert.exists() or ca_key.exists()):
        rotation_archive = _archive_bootstrap_pki_for_rotation(paths)
    elif ca_cert.exists():
        required_seconds = (int(settings["server_cert_validity_days"]) + 30) * 86400
        if not _certificate_valid_for(ca_cert, required_seconds):
            die(
                "Die instanzeigene Mavi-CA läuft zu früh ab oder ist nicht gültig genug für ein neues "
                "Serverzertifikat. Bewusst rotieren mit: "
                "mavi-provisioner ssh server-setup --rotate-ca --yes. "
                "Danach muss die alte CA mit ihrer archivierten Thumbprint-Liste von Ziel-PCs entfernt werden."
            )
    created = not ca_cert.exists()
    if not ca_key.exists():
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_key),
            ],
            description="private Mavi-CA erzeugen",
            quiet=True,
        )
        os.chmod(ca_key, 0o600)
    if not ca_cert.exists():
        _root_command(
            [
                "openssl", "req", "-x509", "-new", "-sha256",
                "-key", str(ca_key), "-out", str(ca_cert),
                "-days", str(settings["ca_validity_days"]),
                "-subj",
                f"/CN=Mavi Bootstrap Root CA {settings['instance_id']}/O=Mavi/OU=Automated Bootstrap",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
            ],
            description="Mavi-CA-Zertifikat erzeugen",
            quiet=True,
        )
        os.chmod(ca_cert, 0o644)
    return created, rotation_archive


def _archive_bootstrap_root_ca(paths: dict[str, Path]) -> str:
    """Aktuelle Bootstrap-CA in einem root-kontrollierten DER-Archiv binden."""
    from .openssh import (
        _atomic_write_bytes,
    )

    from .environment import die
    from .remote import (
        _certificate_der_from_file,
        _certificate_thumbprint_from_der,
    )

    try:
        certificate_der = _certificate_der_from_file(paths["ca_cert"])
        thumbprint = _certificate_thumbprint_from_der(certificate_der)
        archive = paths["ca_archive"]
        archive.mkdir(parents=True, exist_ok=True)
        if archive.is_symlink() or not archive.is_dir():
            raise ValueError("Das Bootstrap-CA-Archiv ist kein regulärer Ordner.")
        if os.name != "nt":
            os.chmod(archive, 0o755)
        destination = archive / f"{thumbprint}.cer"
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                raise ValueError("Der archivierte Bootstrap-CA-Pfad ist keine reguläre Datei.")
            archived_der = _certificate_der_from_file(destination)
            if not secrets.compare_digest(archived_der, certificate_der):
                raise ValueError(
                    "Das Bootstrap-CA-Archiv enthält unter demselben Thumbprint andere DER-Daten."
                )
        else:
            _atomic_write_bytes(destination, certificate_der, mode=0o644)
        return thumbprint
    except (OSError, ValueError) as exc:
        die(f"Die aktuelle Mavi-Bootstrap-CA konnte nicht sicher archiviert werden: {exc}")
    raise AssertionError("unreachable")


def _controller_bound_bootstrap_root_certificates(
    paths: dict[str, Path] | None = None,
    *,
    project: Path | None = None,
) -> tuple[str, dict[str, str]]:
    """Aktuelle und archivierte Bootstrap-Roots aus Controller-DER ableiten."""
    from .openssh import (
        _bootstrap_pki_paths,
    )

    from .remote import (
        _certificate_der_from_file,
        _certificate_thumbprint_from_der,
    )

    if paths is None:
        if project is None:
            raise ValueError(
                "Bootstrap-Root-Zertifikate müssen an ein Mavi-Projekt gebunden werden."
            )
        resolved_paths = _bootstrap_pki_paths(project)
    else:
        resolved_paths = paths
    current_der: bytes | None = None
    for candidate in (resolved_paths["system_ca"], resolved_paths["ca_cert"]):
        if not candidate.is_file():
            continue
        certificate_der = _certificate_der_from_file(candidate)
        if current_der is not None and not secrets.compare_digest(
            current_der,
            certificate_der,
        ):
            raise ValueError(
                "Die aktuellen Controller-Kopien der Mavi-Bootstrap-CA widersprechen sich."
            )
        current_der = certificate_der
    if current_der is None:
        raise ValueError(
            "Die aktuelle Mavi-Bootstrap-CA ist auf dem Controller nicht lesbar."
        )

    current_thumbprint = _certificate_thumbprint_from_der(current_der)
    certificates: dict[str, str] = {
        current_thumbprint: base64.b64encode(current_der).decode("ascii")
    }
    archive = resolved_paths["ca_archive"]
    if archive.exists():
        if archive.is_symlink() or not archive.is_dir():
            raise ValueError("Das Controller-Archiv der Bootstrap-CAs ist kein regulärer Ordner.")
        for candidate in sorted(archive.glob("*.cer"), key=lambda path: path.name):
            if candidate.is_symlink() or not candidate.is_file():
                raise ValueError(
                    f"Der archivierte Bootstrap-CA-Pfad ist keine reguläre Datei: {candidate}"
                )
            certificate_der = _certificate_der_from_file(candidate)
            thumbprint = _certificate_thumbprint_from_der(certificate_der)
            if candidate.stem.upper() != thumbprint:
                raise ValueError(
                    f"Archivname und DER-Thumbprint der Bootstrap-CA stimmen nicht überein: {candidate}"
                )
            encoded = base64.b64encode(certificate_der).decode("ascii")
            existing = certificates.get(thumbprint)
            if existing is not None and not secrets.compare_digest(existing, encoded):
                raise ValueError(
                    "Das Controller-Archiv enthält kollidierende Bootstrap-CA-Identitäten."
                )
            certificates[thumbprint] = encoded
    return current_thumbprint, certificates


def _issue_bootstrap_server_certificate(settings: dict[str, Any], paths: dict[str, Path]) -> None:
    from .openssh import (
        _atomic_write_bytes,
        _openssl_server_config,
        _root_command,
    )

    config_text = _openssl_server_config(settings["url_host"])
    _atomic_write_bytes(paths["openssl_config"], config_text.encode("utf-8"), mode=0o600)

    temporary_key = paths["pki"] / ".mavi-server.key.new"
    temporary_csr = paths["pki"] / ".mavi-server.csr.new"
    temporary_cert = paths["pki"] / ".mavi-server.cert.new"
    for candidate in (temporary_key, temporary_csr, temporary_cert):
        candidate.unlink(missing_ok=True)
    try:
        _root_command(
            [
                "openssl", "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(temporary_key),
            ],
            description="HTTPS-Serverschlüssel erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "req", "-new", "-sha256",
                "-key", str(temporary_key), "-out", str(temporary_csr),
                "-config", str(paths["openssl_config"]),
            ],
            description="HTTPS-Zertifikatsanfrage mit SAN erzeugen",
            quiet=True,
        )
        _root_command(
            [
                "openssl", "x509", "-req", "-sha256",
                "-in", str(temporary_csr),
                "-CA", str(paths["ca_cert"]),
                "-CAkey", str(paths["ca_key"]),
                "-CAcreateserial", "-out", str(temporary_cert),
                "-days", str(settings["server_cert_validity_days"]),
                # -extensions alleine reicht bei `openssl x509 -req` nicht aus.
                # Ohne -extfile ignoriert OpenSSL die SAN-Erweiterung und das
                # Zertifikat ist anschließend nicht für die Bootstrap-IP bzw.
                # den Bootstrap-DNS-Namen gültig.
                "-extfile", str(paths["openssl_config"]),
                "-extensions", "server_ext",
            ],
            description="HTTPS-Serverzertifikat mit Mavi-CA signieren",
            quiet=True,
        )
        os.chmod(temporary_key, 0o600)
        os.chmod(temporary_cert, 0o644)
        os.replace(temporary_key, paths["server_key"])
        os.replace(temporary_csr, paths["server_csr"])
        os.replace(temporary_cert, paths["server_cert"])
        os.chmod(paths["server_key"], 0o600)
        os.chmod(paths["server_csr"], 0o600)
        os.chmod(paths["server_cert"], 0o644)
    finally:
        for candidate in (temporary_key, temporary_csr, temporary_cert):
            candidate.unlink(missing_ok=True)


def _nginx_bootstrap_config(settings: dict[str, Any], paths: dict[str, Path]) -> str:
    from .openssh import (
        _nginx_quote,
    )

    allow_lines = ["        allow 127.0.0.1;", "        allow ::1;"]
    allow_lines.append(f"        allow {settings['ansible_server_ip']};")
    allow_lines.extend(f"        allow {cidr};" for cidr in settings["allowed_cidrs"])
    allow_lines.append("        deny all;")
    webroot = str(settings["local_dir"]).rstrip("/\\") + "/"
    listen_lines = [f"    listen {settings['port']} ssl;"]
    if ipaddress.ip_address(settings["ansible_server_ip"]).version == 6:
        listen_lines.append(f"    listen [::]:{settings['port']} ssl;")
    return "\n".join([
        f"# Automatisch verwaltet durch Mavi Provisioner; Instanz {settings['instance_id']}",
        "server {",
        *listen_lines,
        f"    server_name {_nginx_quote(settings['url_host'])};",
        f"    ssl_certificate {_nginx_quote(str(paths['server_cert']))};",
        f"    ssl_certificate_key {_nginx_quote(str(paths['server_key']))};",
        "    ssl_protocols TLSv1.2 TLSv1.3;",
        "    ssl_session_tickets off;",
        "    server_tokens off;",
        "    client_max_body_size 1m;",
        "    add_header X-Content-Type-Options nosniff always;",
        "    add_header Cache-Control \"no-store\" always;",
        "",
        f"    location ^~ {_nginx_quote(settings['url_path'])} {{",
        f"        alias {_nginx_quote(webroot)};",
        "        autoindex off;",
        "        default_type application/octet-stream;",
        "        limit_except GET HEAD { deny all; }",
        *allow_lines,
        "    }",
        "",
        "    location / { return 404; }",
        "}",
        "",
    ])


def _configure_bootstrap_firewall(settings: dict[str, Any]) -> dict[str, Any]:
    """Server-Firewall ausschließlich über instanzeigene, entfernbaren Ressourcen verwalten."""

    from .openssh import (
        _ufw_delete_tagged_rules,
    )

    from .openssh import (
        _root_command,
    )

    from .environment import die

    port = str(settings["port"])
    firewall_sources = list(settings["allowed_cidrs"])
    server_source = str(settings["ansible_server_ip"])
    firewall_tag = f"mavi-bootstrap-{settings['instance_id']}"
    if not any(
        ipaddress.ip_address(server_source) in ipaddress.ip_network(cidr)
        for cidr in firewall_sources
        if ipaddress.ip_network(cidr).version == ipaddress.ip_address(server_source).version
    ):
        firewall_sources.append(server_source)
    ufw = shutil.which("ufw")
    if ufw:
        status = subprocess.run([ufw, "status"], check=False, capture_output=True, text=True)
        if status.returncode == 0 and re.search(r"(?im)^Status:\s+active\s*$", status.stdout or ""):
            _ufw_delete_tagged_rules(ufw, firewall_tag)
            for cidr in firewall_sources:
                _root_command(
                    [
                        ufw, "allow", "from", cidr, "to", "any", "port", port,
                        "proto", "tcp", "comment", firewall_tag,
                    ],
                    description=f"UFW HTTPS/{port} für {cidr} freigeben",
                )
            return {"backend": "ufw", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}

    firewall_cmd = shutil.which("firewall-cmd")
    if firewall_cmd:
        state = subprocess.run([firewall_cmd, "--state"], check=False, capture_output=True, text=True)
        if state.returncode == 0:
            zones = subprocess.run(
                [firewall_cmd, "--permanent", "--get-zones"],
                check=False,
                capture_output=True,
                text=True,
            )
            if zones.returncode != 0:
                die("firewalld-Zonen konnten nicht gelesen werden.")
            if firewall_tag in (zones.stdout or "").split():
                _root_command(
                    [firewall_cmd, "--permanent", f"--delete-zone={firewall_tag}"],
                    description=f"alte instanzeigene firewalld-Zone {firewall_tag} entfernen",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--new-zone={firewall_tag}"],
                description=f"instanzeigene firewalld-Zone {firewall_tag} anlegen",
            )
            for cidr in firewall_sources:
                _root_command(
                    [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-source={cidr}"],
                    description=f"firewalld HTTPS/{port} für {cidr} freigeben",
                )
            _root_command(
                [firewall_cmd, "--permanent", f"--zone={firewall_tag}", f"--add-port={port}/tcp"],
                description=f"firewalld HTTPS/{port} in Instanzzone freigeben",
            )
            _root_command([firewall_cmd, "--reload"], description="firewalld neu laden")
            return {
                "backend": "firewalld",
                "tag": firewall_tag,
                "sources": firewall_sources,
                "port": int(port),
            }
    return {"backend": "none", "tag": firewall_tag, "sources": firewall_sources, "port": int(port)}


def _trust_bootstrap_ca_locally(paths: dict[str, Path]) -> None:
    from .openssh import (
        _atomic_copy_file,
        _root_command,
    )

    from .environment import die

    paths["system_ca"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_copy_file(paths["ca_cert"], paths["system_ca"])
    os.chmod(paths["system_ca"], 0o644)
    update_ca = shutil.which("update-ca-certificates")
    if update_ca:
        _root_command([update_ca], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    update_trust = shutil.which("update-ca-trust")
    if update_trust:
        anchors = paths["system_ca_anchor"]
        anchors.parent.mkdir(parents=True, exist_ok=True)
        _atomic_copy_file(paths["ca_cert"], anchors)
        _root_command([update_trust, "extract"], description="Mavi-CA im Linux-Systemvertrauen aktivieren")
        return
    die("Weder update-ca-certificates noch update-ca-trust ist verfügbar.")


def _enable_and_reload_nginx(paths: dict[str, Path]) -> None:
    from .openssh import (
        _root_command,
    )

    from .environment import die

    nginx = shutil.which("nginx")
    if not nginx:
        die("nginx wurde trotz Paketinstallation nicht gefunden.")
    _root_command([nginx, "-t"], description="nginx-Konfiguration sicher validieren")
    if shutil.which("systemctl"):
        _root_command(["systemctl", "enable", "--now", "nginx"], description="nginx aktivieren und starten")
        _root_command(["systemctl", "reload", "nginx"], description="nginx-Konfiguration laden")
    elif shutil.which("service"):
        _root_command(["service", "nginx", "restart"], description="nginx neu starten")
    else:
        die("Weder systemctl noch service ist verfügbar, um nginx zu starten.")


def _tcp_port_is_bindable(port: int, *, include_ipv6: bool) -> bool:
    """Konservativer Vorabcheck: Kann nginx den Port auf allen benötigten Familien binden?"""
    targets: list[tuple[int, tuple[Any, ...]]] = [
        (socket.AF_INET, ("0.0.0.0", port)),
    ]
    if include_ipv6 and socket.has_ipv6:
        targets.append((socket.AF_INET6, ("::", port, 0, 0)))
    for family, address in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                if family == socket.AF_INET6:
                    probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind(address)
        except OSError:
            return False
    return True


def _tcp_listener_process_names(port: int) -> set[str]:
    """Best effort: Namen der Prozesse ermitteln, die den TCP-Port bereits halten."""
    names: set[str] = set()
    ss = shutil.which("ss")
    if ss:
        try:
            result = subprocess.run(
                [ss, "-H", "-ltnp"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None:
            for line in (result.stdout or "").splitlines():
                fields = line.split()
                if len(fields) < 4 or not re.search(rf":{port}$", fields[3]):
                    continue
                for process_name in re.findall(r'\(\("([^"]+)"', line):
                    names.add(process_name.casefold())
    if names:
        return names

    fuser = shutil.which("fuser")
    if not fuser:
        return names
    try:
        result = subprocess.run(
            [fuser, "-n", "tcp", str(port)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return names
    for pid_text in re.findall(r"\b\d+\b", (result.stdout or "") + " " + (result.stderr or "")):
        try:
            process_name = Path(f"/proc/{int(pid_text)}/comm").read_text(encoding="utf-8").strip()
        except (OSError, ValueError, UnicodeError):
            continue
        if process_name:
            names.add(process_name.casefold())
    return names


def _managed_nginx_is_active() -> bool:
    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            result = subprocess.run(
                [systemctl, "is-active", "--quiet", "nginx"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    service = shutil.which("service")
    if service:
        try:
            result = subprocess.run(
                [service, "nginx", "status"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0
    return False


def _bootstrap_url_with_port(settings: dict[str, Any], port: int) -> str:
    parsed = urllib.parse.urlsplit(settings["base_url"])
    host = str(parsed.hostname or settings["url_host"])
    try:
        host_is_ipv6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        host_is_ipv6 = False
    netloc_host = f"[{host}]" if host_is_ipv6 else host
    netloc = netloc_host if port == 443 else f"{netloc_host}:{port}"
    return urllib.parse.urlunsplit(("https", netloc, parsed.path, "", ""))


def _persist_bootstrap_base_url(
    project: Path,
    base_url: str,
    *,
    fallback_uid: int,
    fallback_gid: int,
) -> None:
    """Automatisch gewählten Port zentral speichern und bestehende Dateirechte erhalten."""
    from .environment import (
        atomic_write_yaml,
        die,
        load_yaml,
        project_paths,
    )

    config_path = project_paths(project)["config"]
    existing_uid = fallback_uid
    existing_gid = fallback_gid
    existing_mode = 0o644
    try:
        current_stat = config_path.stat()
        existing_uid = int(current_stat.st_uid)
        existing_gid = int(current_stat.st_gid)
        existing_mode = int(current_stat.st_mode & 0o7777)
    except OSError:
        pass
    config = load_yaml(config_path, {}) or {}
    if not isinstance(config, dict):
        die(f"Zentrale Konfiguration ist kein YAML-Objekt: {config_path}")
    config["bootstrap_base_url"] = base_url
    try:
        atomic_write_yaml(config_path, config)
    except OSError as exc:
        die(f"Automatisch gewählter HTTPS-Port konnte nicht zentral gespeichert werden: {exc}")
    try:
        os.chown(config_path, existing_uid, existing_gid, follow_symlinks=False)
    except (AttributeError, NotImplementedError):
        pass
    except OSError as exc:
        die(f"Besitzrechte der zentralen Konfiguration konnten nicht erhalten werden: {exc}")
    os.chmod(config_path, existing_mode)


def _select_usable_bootstrap_port(
    project: Path,
    settings: dict[str, Any],
    *,
    uid: int,
    gid: int,
) -> dict[str, Any]:
    """Konfigurierten Port behalten oder einen freien, dauerhaft gespeicherten Ersatz wählen."""
    from .openssh import (
        _bootstrap_pki_paths,
        _bootstrap_settings,
        _bootstrap_url_with_port,
        _managed_nginx_is_active,
        _persist_bootstrap_base_url,
        _strict_https_probe,
        _tcp_listener_process_names,
        _tcp_port_is_bindable,
    )

    from .environment import die
    from .reports import redact_sensitive_text

    configured_port = int(settings["port"])
    include_ipv6 = ipaddress.ip_address(settings["ansible_server_ip"]).version == 6
    if _tcp_port_is_bindable(configured_port, include_ipv6=include_ipv6):
        return settings

    listeners = _tcp_listener_process_names(configured_port)
    managed_nginx_listener = (
        any(name == "nginx" or name.startswith("nginx-") for name in listeners)
        and _managed_nginx_is_active()
    )
    if managed_nginx_listener:
        health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
        endpoint_ok, endpoint_detail = _strict_https_probe(
            health_url,
            trusted_ca=_bootstrap_pki_paths(project)["system_ca"],
        )
        if endpoint_ok:
            print(
                f"  ✓ HTTPS-Port {configured_port} liefert bereits das gültige "
                "Mavi-Zertifikat und bleibt erhalten."
            )
            return settings
        print(
            f"  ! nginx nutzt HTTPS-Port {configured_port}, liefert dort aber nicht "
            "nachweislich das Mavi-Zertifikat. Mavi trennt den TLS-Endpunkt automatisch."
        )
        print(f"    Prüfung: {redact_sensitive_text(endpoint_detail)}")

    preferred_ports = [8443, 9443, 10443, 11443, 12443, 13443, 14443, 15443]
    fallback_candidates = preferred_ports + list(range(8444, 8501))
    selected_port = next(
        (
            candidate
            for candidate in fallback_candidates
            if candidate != configured_port
            and _tcp_port_is_bindable(candidate, include_ipv6=include_ipv6)
        ),
        None,
    )
    occupied_by = ", ".join(sorted(listeners)) if listeners else "einen anderen Dienst"
    if selected_port is None:
        die(
            f"HTTPS-Port {configured_port} ist durch {occupied_by} belegt, "
            "und Mavi konnte keinen freien Ersatzport finden."
        )
    fallback_url = _bootstrap_url_with_port(settings, selected_port)
    _persist_bootstrap_base_url(
        project,
        fallback_url,
        fallback_uid=uid,
        fallback_gid=gid,
    )
    print(
        f"  ! HTTPS-Port {configured_port} ist durch {occupied_by} belegt. "
        f"Mavi verwendet automatisch Port {selected_port}."
    )
    print(f"  ✓ bootstrap_base_url dauerhaft gespeichert: {fallback_url}")
    return _bootstrap_settings(project)


def _relaunch_bootstrap_server_setup_as_root(project: Path, *, rotate_ca: bool = False) -> None:
    from .environment import die

    sudo = shutil.which("sudo")
    if not sudo:
        die("Für das automatische nginx-/Zertifikats-Setup fehlt sudo.")
    executable = shutil.which(sys.argv[0]) or sys.argv[0]
    script_path = Path(executable).expanduser().resolve()
    command = [
        sudo,
        sys.executable,
        str(script_path),
        "--project",
        str(project.resolve()),
        "ssh",
        "server-setup",
        "--yes",
    ]
    if rotate_ca:
        command.append("--rotate-ca")
    print("\nMavi benötigt einmalig sudo für nginx, Zertifikat und Server-Firewall.")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        die(f"Automatisches HTTPS-Server-Setup ist mit Code {result.returncode} fehlgeschlagen.")


def cmd_ssh_server_setup(args: argparse.Namespace) -> None:
    """Kompletten HTTPS-Server inklusive privater CA automatisch einrichten."""

    from .openssh import (
        _certificate_sha1_thumbprint,
    )
    from .openssh import (
        _archive_bootstrap_root_ca,
        _atomic_copy_file,
        _atomic_write_bytes,
        _bootstrap_launcher_roots,
        _bootstrap_operator_ids,
        _bootstrap_pki_paths,
        _bootstrap_settings,
        _configure_bootstrap_firewall,
        _create_or_reuse_bootstrap_ca,
        _enable_and_reload_nginx,
        _install_bootstrap_server_packages,
        _issue_bootstrap_server_certificate,
        _nginx_bootstrap_config,
        _relaunch_bootstrap_server_setup_as_root,
        _select_usable_bootstrap_port,
        _sha256_file,
        _trust_bootstrap_ca_locally,
    )

    from .environment import (
        die,
        ensure_initialized,
    )
    from .reports import redact_sensitive_text
    from .settings import VERSION

    project = args.project.resolve()
    if os.name == "nt" or not hasattr(os, "geteuid"):
        die("Das automatische HTTPS-Server-Setup ist für Linux-Ansible-Server vorgesehen.")
    if os.geteuid() != 0:
        ensure_initialized(project, quiet=True)
        _relaunch_bootstrap_server_setup_as_root(
            project,
            rotate_ca=bool(getattr(args, "rotate_ca", False)),
        )
        return

    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    uid, gid = _bootstrap_operator_ids(project)
    rotate_ca = bool(getattr(args, "rotate_ca", False))
    if rotate_ca and not bool(getattr(args, "yes", False)):
        die("CA-Rotation benötigt die explizite Bestätigung --yes.")

    print("\nMavi VOLLAUTOMATISCHES HTTPS-SERVER-SETUP")
    print("=========================================")
    _install_bootstrap_server_packages()
    settings = _select_usable_bootstrap_port(project, settings, uid=uid, gid=gid)
    print(f"HTTPS:      {settings['base_url']}")
    print(f"Webroot:    {settings['local_dir']}")
    print(f"Instanz:    {settings['instance_id']}")
    print(f"Client-Netze: {', '.join(settings['allowed_cidrs'])}")

    paths["pki"].mkdir(parents=True, exist_ok=True)
    os.chmod(paths["root"], 0o755)
    os.chmod(paths["pki"], 0o700)
    ca_created, rotation_archive = _create_or_reuse_bootstrap_ca(
        settings,
        paths,
        rotate=rotate_ca,
    )
    archived_ca_thumbprint = _archive_bootstrap_root_ca(paths)
    _issue_bootstrap_server_certificate(settings, paths)
    _trust_bootstrap_ca_locally(paths)

    webroot: Path = settings["local_dir"]
    webroot.mkdir(parents=True, exist_ok=True)
    os.chmod(webroot, 0o755)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    _atomic_copy_file(paths["ca_cert"], webroot / "Mavi-ROOT-CA.pem")
    _atomic_write_bytes(
        webroot / ".mavi-bootstrap-owner.json",
        (json.dumps({
            "instance_id": settings["instance_id"],
            "project": str(project),
            "webroot": str(webroot),
        }, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )

    paths["nginx_config"].parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_bytes(
        paths["nginx_config"],
        _nginx_bootstrap_config(settings, paths).encode("utf-8"),
        mode=0o644,
    )
    _enable_and_reload_nginx(paths)
    firewall_state = _configure_bootstrap_firewall(settings)

    launcher_root, _windows_root = _bootstrap_launcher_roots(project)
    if launcher_root is not None:
        try:
            launcher_root.mkdir(parents=True, exist_ok=True)
            os.chmod(launcher_root, 0o755)
            os.chown(launcher_root, uid, gid, follow_symlinks=False)
        except (OSError, NotImplementedError) as exc:
            print(f"! Softwareablage wird später mit Benutzerrechten angelegt: {redact_sensitive_text(exc)}")

    for managed_path in (
        webroot,
        webroot / "Mavi-SETUP-CHECK.txt",
        webroot / "Mavi-ROOT-CA.pem",
        webroot / ".mavi-bootstrap-owner.json",
    ):
        try:
            os.chown(managed_path, uid, gid, follow_symlinks=False)
        except NotImplementedError:
            pass
        except OSError as exc:
            die(f"Webroot-Besitzrechte konnten nicht gesetzt werden: {exc}")
    state = {
        "version": VERSION,
        "instance_id": settings["instance_id"],
        "project": str(project),
        "base_url": settings["base_url"],
        "webroot": str(webroot),
        "host": settings["url_host"],
        "ansible_server_ip": settings["ansible_server_ip"],
        "port": settings["port"],
        "allowed_cidrs": settings["allowed_cidrs"],
        "firewall": firewall_state,
        "ca_sha256": _sha256_file(paths["ca_cert"]),
        "ca_windows_thumbprint": _certificate_sha1_thumbprint(paths["ca_cert"]),
        "ca_thumbprint": archived_ca_thumbprint,
        "ca_validity_days": settings["ca_validity_days"],
        "server_cert_validity_days": settings["server_cert_validity_days"],
        "ca_created": ca_created,
        "rotation_archive": str(rotation_archive) if rotation_archive is not None else "",
        "configured_epoch": time.time(),
    }
    _atomic_write_bytes(
        paths["state"],
        (json.dumps(state, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
        mode=0o644,
    )
    print("\n✓ nginx, Mavi-CA, SAN-Zertifikat, Webroot und Server-Firewall sind eingerichtet.")
    print("✓ Die CA bleibt stabil und wird bei späteren Läufen nicht still ersetzt.")
    if rotation_archive is not None:
        print(f"! Alte PKI recoverable archiviert: {rotation_archive}")
        print("! Die archivierte alte CA muss anschließend auf allen Ziel-PCs anhand der Thumbprint entfernt werden.")


def _ensure_automatic_https_server(project: Path) -> dict[str, Any]:
    """Server-Setup nur bei Bedarf automatisch mit sudo ausführen."""

    from .openssh import (
        _certificate_valid_for,
    )
    from .openssh import (
        _bootstrap_pki_paths,
        _bootstrap_settings,
        _controller_bound_bootstrap_root_certificates,
        _nginx_bootstrap_config,
        _relaunch_bootstrap_server_setup_as_root,
        _strict_https_probe,
        cmd_ssh_server_setup,
    )

    from .environment import die
    from .settings import VERSION

    settings = _bootstrap_settings(project)
    paths = _bootstrap_pki_paths(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    files_ready = all(
        path.exists()
        for path in (
            paths["system_ca"],
            paths["ca_archive"],
            paths["nginx_config"],
            paths["state"],
        )
    )
    if files_ready and hasattr(os, "geteuid") and os.geteuid() == 0:
        files_ready = all(
            path.exists()
            for path in (
                paths["ca_key"], paths["ca_cert"], paths["server_key"], paths["server_cert"],
            )
        )
    state_ready = False
    nginx_ready = False
    if files_ready:
        try:
            state = json.loads(paths["state"].read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("Ungültiger Mavi-Serverstatus")
            current_ca_thumbprint, _controller_roots = (
                _controller_bound_bootstrap_root_certificates(paths)
            )
            state_ready = (
                state.get("instance_id") == settings["instance_id"]
                and state.get("project") == str(project.resolve())
                and state.get("base_url") == settings["base_url"]
                and state.get("webroot") == str(settings["local_dir"])
                and state.get("host") == settings["url_host"]
                and state.get("ansible_server_ip") == settings["ansible_server_ip"]
                and state.get("port") == settings["port"]
                and state.get("allowed_cidrs") == settings["allowed_cidrs"]
                and state.get("ca_validity_days") == settings["ca_validity_days"]
                and state.get("server_cert_validity_days") == settings["server_cert_validity_days"]
                and state.get("ca_thumbprint") == current_ca_thumbprint
            )
            nginx_ready = paths["nginx_config"].read_text(encoding="utf-8") == _nginx_bootstrap_config(
                settings,
                paths,
            )
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            state_ready = False
            nginx_ready = False
    https_ready = False
    certificates_ready = (
        _certificate_valid_for(paths["ca_cert"], 30 * 86400)
        and _certificate_valid_for(paths["server_cert"], 7 * 86400)
    )
    if files_ready and state_ready and nginx_ready and certificates_ready:
        https_ready, _detail = _strict_https_probe(
            health_url,
            expected_body=health_body,
            trusted_ca=paths["system_ca"],
        )
    if files_ready and state_ready and nginx_ready and certificates_ready and https_ready:
        return settings

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd_ssh_server_setup(argparse.Namespace(project=project, yes=True))
    else:
        _relaunch_bootstrap_server_setup_as_root(project)

    if not paths["system_ca"].is_file():
        die("Automatisches Setup meldete Erfolg, aber das Mavi-CA-Zertifikat fehlt.")
    # Das Root-Setup kann bei einem Portkonflikt die zentrale Basis-URL
    # automatisch angepasst haben. Daher alle abgeleiteten Werte neu laden.
    settings = _bootstrap_settings(project)
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    health_url = urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt")
    https_ready, detail = _strict_https_probe(
        health_url,
        expected_body=health_body,
        trusted_ca=paths["system_ca"],
    )
    if not https_ready:
        die(f"Automatisches HTTPS-Setup wurde abgeschlossen, ist aber nicht erreichbar: {detail}")
    return settings


class _RejectBootstrapRedirects(urllib.request.HTTPRedirectHandler):
    """Feste Bootstrap-URL: auch kein HTTPS-zu-HTTP-Redirect wird verfolgt."""

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"Bootstrap-Weiterleitungen sind deaktiviert: {newurl}",
            headers,
            fp,
        )


def _strict_https_probe(
    url: str,
    *,
    expected_body: bytes | None = None,
    trusted_ca: Path | None = None,
) -> tuple[bool, str]:
    """HTTPS-Aufruf mit strikter Ketten- und Hostnamenprüfung, ohne Bypass."""
    from .openssh import (
        _RejectBootstrapRedirects,
    )

    from .settings import VERSION

    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            return False, "Sicherheitsabbruch: URL ist nicht HTTPS."
        context = ssl.create_default_context()
        if trusted_ca is not None:
            if not trusted_ca.is_file():
                return False, f"Vertrauenswürdige Mavi-CA fehlt: {trusted_ca}"
            # Ergänzt die private Mavi-CA ausdrücklich zum normalen Trust Store.
            # CERT_REQUIRED und check_hostname bleiben zwingend aktiv.
            context.load_verify_locations(cafile=str(trusted_ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        request = urllib.request.Request(url, headers={"User-Agent": f"mavi-provisioner/{VERSION}"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _RejectBootstrapRedirects(),
            urllib.request.HTTPSHandler(context=context),
        )
        with opener.open(request, timeout=10) as response:
            status = int(getattr(response, "status", 200))
            final_url = str(response.geturl() or url)
            body = response.read(1024 * 1024)
        final = urllib.parse.urlsplit(final_url)
        if (
            final.scheme.lower() != "https"
            or final.hostname != parsed.hostname
            or final.port != parsed.port
        ):
            return False, f"Unzulässige HTTPS-Weiterleitung: {final_url}"
        if status < 200 or status >= 300:
            return False, f"HTTPS antwortete mit Status {status}."
        if expected_body is not None and body != expected_body:
            return False, "HTTPS-Inhalt stimmt nicht mit dem lokal veröffentlichten Artefakt überein."
        return True, f"HTTPS erreichbar, Zertifikat und Hostname gültig (Status {status})."
    except ssl.SSLCertVerificationError as exc:
        return False, f"Zertifikatsprüfung fehlgeschlagen: {exc}"
    except ssl.SSLError as exc:
        return False, f"TLS-/CA-Prüfung fehlgeschlagen: {exc}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTPS antwortete mit Status {exc.code}."
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            return False, f"Zertifikatsprüfung fehlgeschlagen: {exc.reason}"
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"
    except (TimeoutError, OSError, ValueError) as exc:
        return False, f"HTTPS-Aufruf fehlgeschlagen: {exc}"


def _https_ssh_bootstrap_cmd(
    ps1_download_url: str,
    ps1_sha256: str,
    *,
    ca_der: bytes,
    launcher_id: str,
) -> str:
    """Erzeugt den doppelklickbaren CMD-Starter für den OpenSSH-Bootstrap."""

    from .openssh import (
        _powershell_single_quote,
    )

    if not re.fullmatch(r"[0-9A-Fa-f]{64}", ps1_sha256):
        raise ValueError("Der PS1-Hash für den Windows-Starter ist ungültig.")
    if not ca_der or len(ca_der) > 65536:
        raise ValueError("Das Mavi-CA-Zertifikat ist leer oder unerwartet groß.")
    safe_url = _powershell_single_quote(ps1_download_url)
    safe_sha = _powershell_single_quote(ps1_sha256.lower())
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", launcher_id).strip("._-") or "WINDOWS"
    ca_sha256 = hashlib.sha256(ca_der).hexdigest()
    ca_base64 = base64.b64encode(ca_der).decode("ascii")
    ca_chunks = [ca_base64[index:index + 64] for index in range(0, len(ca_base64), 64)]

    ca_import_script = (
        "$ErrorActionPreference='Stop';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "$p=Join-Path $d 'Mavi-Bootstrap-Root-CA.cer';"
        f"$expected='{ca_sha256}';"
        "$bytes=[IO.File]::ReadAllBytes($p);"
        "$sha=[Security.Cryptography.SHA256]::Create();"
        "try{$actual=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: CA SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$bytes);"
        "$now=[DateTime]::UtcNow;if($now -lt $cert.NotBefore.ToUniversalTime() -or $now -gt $cert.NotAfter.ToUniversalTime()){throw 'SICHERHEITSABBRUCH: Eingebettete Mavi-CA ist noch nicht oder nicht mehr gültig.'};"
        "$rawBc=$cert.Extensions|Where-Object{$_.Oid.Value -eq '2.5.29.19'}|Select-Object -First 1;"
        "if($null -eq $rawBc){throw 'SICHERHEITSABBRUCH: Zertifikat besitzt keine CA-BasicConstraints.'};"
        "$bc=New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension;"
        "$bc.CopyFrom($rawBc);if(-not $bc.CertificateAuthority){throw 'SICHERHEITSABBRUCH: Eingebettetes Zertifikat ist keine CA.'};"
        "$added=$false;"
        "$store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine');"
        "try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);"
        "$found=$store.Certificates.Find([Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,$cert.Thumbprint,$false);"
        "if($found.Count -eq 0){$store.Add($cert);$added=$true;Write-Host ('Mavi-CA installiert: '+$cert.Thumbprint) -ForegroundColor Green}"
        "else{Write-Host ('Mavi-CA bereits vertraut: '+$cert.Thumbprint) -ForegroundColor Green}}finally{$store.Close()};"
        "if($added){exit 17}else{exit 0}"
    )
    ca_import_b64 = base64.b64encode(ca_import_script.encode("utf-16-le")).decode("ascii")

    download_script = (
        "$ErrorActionPreference='Stop';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        f"$u='{safe_url}';$expected='{safe_sha}';"
        "$d=Join-Path $env:TEMP 'Mavi-OpenSSH-Bootstrap';"
        "New-Item -ItemType Directory -Path $d -Force|Out-Null;"
        "$p=Join-Path $d 'Mavi-OpenSSH-Setup.ps1';"
        "try{"
        "Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $p -TimeoutSec 60 -MaximumRedirection 0;"
        "if(-not(Test-Path -LiteralPath $p)){throw 'Bootstrap-Download fehlgeschlagen.'};"
        "$actual=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();"
        "if($actual -cne $expected){throw ('SICHERHEITSABBRUCH: PS1 SHA-256 stimmt nicht. Erwartet='+$expected+' Ist='+$actual)};"
        "& $p"
        "}catch{Write-Host '';Write-Host ('Mavi OpenSSH Bootstrap FEHLER: '+$_.Exception.Message) -ForegroundColor Red;"
        "Read-Host 'ENTER zum Schliessen'|Out-Null;exit 10}"
    )
    download_b64 = base64.b64encode(download_script.encode("utf-16-le")).decode("ascii")
    copied_launcher = f"Mavi-OpenSSH-Launcher-{safe_id}.cmd"
    lines = [
        "@echo off",
        "setlocal EnableExtensions DisableDelayedExpansion",
        f"title Mavi OpenSSH Vollautomatik - {safe_id}",
        "if /I \"%~1\"==\"--mavi-elevated\" goto mavi_elevated",
        f"set \"MaviCOPY=%TEMP%\\{copied_launcher}\"",
        "copy /Y \"%~f0\" \"%MaviCOPY%\" >nul",
        "if errorlevel 1 goto mavi_copy_failed",
        "echo.",
        "echo Mavi macht jetzt automatisch: UAC, CA-Vertrauen, HTTPS und OpenSSH.",
        "echo Bitte die Windows-UAC-Abfrage bestaetigen.",
        "echo.",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"try{$r=Start-Process -FilePath $env:MaviCOPY -Verb RunAs -ArgumentList @('--mavi-elevated') -Wait -PassThru;exit $r.ExitCode}catch{Write-Host $_.Exception.Message -ForegroundColor Red;exit 5}\"",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" (",
        "  echo.",
        "  echo Mavi Bootstrap meldete Fehlercode %MaviRC%.",
        "  pause",
        ")",
        "exit /b %MaviRC%",
        "",
        ":mavi_copy_failed",
        "echo FEHLER: Der Starter konnte nicht nach TEMP kopiert werden.",
        "pause",
        "exit /b 4",
        "",
        ":mavi_elevated",
        "powershell.exe -NoProfile -Command \"if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { exit 0 } else { exit 1 }\"",
        "if errorlevel 1 (",
        "  echo FEHLER: Administratorrechte wurden nicht erteilt.",
        "  pause",
        "  exit /b 5",
        ")",
        "set \"MaviDIR=%TEMP%\\Mavi-OpenSSH-Bootstrap\"",
        "if not exist \"%MaviDIR%\" mkdir \"%MaviDIR%\"",
        "set \"MaviCA64=%MaviDIR%\\Mavi-Bootstrap-Root-CA.b64\"",
        "set \"MaviCACERT=%MaviDIR%\\Mavi-Bootstrap-Root-CA.cer\"",
        f"> \"%MaviCA64%\" echo {ca_chunks[0]}",
        *[f">> \"%MaviCA64%\" echo {chunk}" for chunk in ca_chunks[1:]],
        "certutil.exe -f -decode \"%MaviCA64%\" \"%MaviCACERT%\" >nul",
        "if errorlevel 1 goto mavi_ca_failed",
        "set \"MAVI_CA_ADDED_THIS_RUN=0\"",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {ca_import_b64}",
        "set \"MaviCARC=%ERRORLEVEL%\"",
        "if \"%MaviCARC%\"==\"17\" set \"MAVI_CA_ADDED_THIS_RUN=1\"",
        "if not \"%MaviCARC%\"==\"0\" if not \"%MaviCARC%\"==\"17\" goto mavi_ca_failed",
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {download_b64}",
        "set \"MaviRC=%ERRORLEVEL%\"",
        "if not \"%MaviRC%\"==\"0\" goto mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH wurde vollautomatisch eingerichtet.",
        "exit /b 0",
        "",
        ":mavi_ca_failed",
        "echo.",
        "echo SICHERHEITSABBRUCH: Die feste Mavi-CA konnte nicht verifiziert oder importiert werden.",
        "pause",
        "exit /b 8",
        "",
        ":mavi_bootstrap_failed",
        "echo.",
        "echo Mavi OpenSSH Bootstrap meldete Fehlercode %MaviRC%.",
        "pause",
        "exit /b %MaviRC%",
        "",
    ]
    if max((len(line) for line in lines), default=0) > 7000:
        raise RuntimeError("Interner Fehler: HTTPS-Launcher-Zeile überschreitet das sichere CMD-Limit.")
    return "\r\n".join(lines)


def _deliver_ssh_launcher_to_public_desktop(
    project: Path,
    *,
    host: str,
    launcher_path: Path,
    expected_sha256: str,
) -> str:
    """Liefert den öffentlichen, hashgebundenen Starter über das bestehende PSRP/WinRM aus.

    Das ist ausschließlich ein Ersatz für eine nicht beschreibbare zentrale
    Softwareablage. Der bisherige, bereits funktionierende Verwaltungsweg wird
    verwendet; weder HTTP noch ein freigegebener Schreibzugriff werden erzeugt.
    Die Datei landet zunächst unter einem temporären Namen auf Windows, wird
    dort gegen den lokalen SHA-256 geprüft und erst dann am endgültigen Namen veröffentlicht.
    """
    from .openssh import (
        _sha256_file,
    )

    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        create_temporary_vault_password_file,
        strip_ansi,
    )
    from .remote import (
        _connection_label,
        _host_inventory_entry,
    )
    from .reports import redact_sensitive_text

    if not launcher_path.is_file():
        raise FileNotFoundError(
            "Der lokale Mavi-OpenSSH-Starter fehlt vor der Direktbereitstellung: "
            f"{launcher_path}"
        )

    expected_sha256 = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("Der lokale SHA-256 des Mavi-OpenSSH-Starters ist ungültig.")

    local_sha256 = _sha256_file(launcher_path).lower()
    if local_sha256 != expected_sha256:
        raise RuntimeError(
            "SICHERHEITSABBRUCH: Der Mavi-OpenSSH-Starter wurde vor der Direktbereitstellung verändert; "
            f"erwartet={expected_sha256} lokal={local_sha256}"
        )

    _inv, windows, host_data = _host_inventory_entry(project, host)
    connection = _connection_label(windows, host_data)
    if connection not in {"PSRP", "WinRM"}:
        raise PermissionError(
            "Die sichere Direktbereitstellung ist nur über die noch bestehende PSRP/WinRM-Verbindung möglich. "
            f"{host} verwendet derzeit {connection}."
        )

    launcher_name = launcher_path.name
    if re.fullmatch(r"[A-Za-z0-9._-]+", launcher_name) is None:
        raise ValueError("Der Name des Mavi-OpenSSH-Starters enthält unzulässige Zeichen.")

    remote_dir = r"C:\Users\Public\Desktop\Mavi-Bootstrap"
    remote_final_path = remote_dir + "\\" + launcher_name
    remote_stage_path = remote_dir + "\\." + launcher_name + ".new"
    acl_powershell = r'''[CmdletBinding()]
param([string]$Path)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Mavi-Bootstrap-Ordner fehlt: $Path"
}

$acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) {
    [void]$acl.RemoveAccessRuleAll($rule)
}

$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$rules = @(
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inherit,
        $propagation,
        $allow
    ),
    [System.Security.AccessControl.FileSystemAccessRule]::new(
        $usersSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inherit,
        $propagation,
        $allow
    )
)
foreach ($rule in $rules) {
    [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
$Ansible.Changed = $true
'''
    powershell = r'''[CmdletBinding()]
param(
    [string]$StagingPath,
    [string]$FinalPath,
    [string]$ExpectedSha256
)

$ErrorActionPreference = 'Stop'
try {
    if (-not (Test-Path -LiteralPath $StagingPath -PathType Leaf)) {
        throw "Temporärer Mavi-Starter fehlt: $StagingPath"
    }

    $stagingHash = [string](Get-FileHash -LiteralPath $StagingPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $stagingHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des temporären Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$stagingHash"
    }

    if (Test-Path -LiteralPath $FinalPath -PathType Leaf) {
        Remove-Item -LiteralPath $FinalPath -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $StagingPath -Destination $FinalPath -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $FinalPath -PathType Leaf)) {
        throw "Mavi-Starter konnte nicht auf dem öffentlichen Desktop veröffentlicht werden: $FinalPath"
    }

    $finalHash = [string](Get-FileHash -LiteralPath $FinalPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not $finalHash.Equals($ExpectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA-256 des veröffentlichten Mavi-Starters stimmt nicht überein. Erwartet=$ExpectedSha256 Erhalten=$finalHash"
    }

    $payload = [ordered]@{
        Path = $FinalPath
        Sha256 = $finalHash.ToLowerInvariant()
    }
    $json = $payload | ConvertTo-Json -Compress
    $marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $Ansible.Result = @{ Marker = $marker }
    $Ansible.Changed = $true
}
catch {
    Remove-Item -LiteralPath $StagingPath -Force -ErrorAction SilentlyContinue
    throw
}
'''
    play = [{
        "name": "Mavi OpenSSH-Starter direkt bereitstellen",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Öffentlichen Mavi-Bootstrap-Desktop anlegen",
                "ansible.windows.win_file": {
                    "path": remote_dir,
                    "state": "directory",
                },
            },
            {
                "name": "Mavi-Bootstrap-Desktop gegen unbefugtes Ändern sperren",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": acl_powershell,
                    "parameters": {
                        "Path": remote_dir,
                    },
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter temporär kopieren",
                "ansible.windows.win_copy": {
                    "src": str(launcher_path.resolve()),
                    "dest": remote_stage_path,
                    "force": True,
                },
            },
            {
                "name": "Mavi-OpenSSH-Starter prüfen und veröffentlichen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "StagingPath": remote_stage_path,
                        "FinalPath": remote_final_path,
                        "ExpectedSha256": expected_sha256,
                    },
                },
                "register": "mavi_launcher_delivery_verify",
            },
            {
                "name": "Mavi-Starter-Bereitstellung auslesen",
                "ansible.builtin.debug": {
                    "msg": "Mavi_LAUNCHER_DELIVERY_B64={{ mavi_launcher_delivery_verify.result.Marker }}"
                },
            },
        ],
    }]

    playbook_path: Path | None = None
    vault_password_file: Path | None = None
    try:
        fd, raw_playbook = tempfile.mkstemp(prefix=".mavi-ssh-launcher-delivery-", suffix=".yml")
        os.close(fd)
        playbook_path = Path(raw_playbook)
        atomic_write_yaml(playbook_path, play)

        print("  → Mavi-Starter wird über die bestehende PSRP/WinRM-Verbindung auf den öffentlichen Desktop kopiert.")
        vault_password = getpass.getpass("Vault password: ")
        vault_password_file = create_temporary_vault_password_file(vault_password)
        cmd = [
            "ansible-playbook",
            "-i",
            str(project_paths(project)["inventory"]),
            str(playbook_path),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
        ]
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung des Mavi-Starters hat nach 120 Sekunden nicht geantwortet."
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung konnte nicht gestartet werden: "
                f"{redact_sensitive_text(exc)}"
            ) from exc

        combined = (completed.stdout or "") + "\n" + (completed.stderr or "")
        match = re.search(r"Mavi_LAUNCHER_DELIVERY_B64=([A-Za-z0-9+/=]+)", combined)
        if completed.returncode != 0 or not match:
            lines = [
                redact_sensitive_text(line.strip())
                for line in strip_ansi(combined).splitlines()
                if line.strip()
            ]
            detail = " | ".join(lines[-10:])
            raise RuntimeError(
                "Die direkte PSRP/WinRM-Bereitstellung auf den öffentlichen Desktop ist fehlgeschlagen"
                + (f": {detail}" if detail else f" (Ansible-Code {completed.returncode})")
            )

        try:
            payload = json.loads(base64.b64decode(match.group(1)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Die PSRP/WinRM-Bereitstellung lieferte keinen lesbaren SHA-256-Nachweis zurück."
            ) from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Die PSRP/WinRM-Bereitstellung lieferte ein unerwartetes Ergebnis.")

        remote_sha256 = str(payload.get("Sha256", "") or "").strip().lower()
        remote_path = str(payload.get("Path", "") or "").strip()
        if remote_sha256 != expected_sha256:
            raise RuntimeError(
                "SICHERHEITSABBRUCH: SHA-256 des direkt bereitgestellten Mavi-Starters stimmt nicht überein; "
                f"erwartet={expected_sha256} Windows={remote_sha256 or '(leer)'}"
            )
        if remote_path.casefold() != remote_final_path.casefold():
            raise RuntimeError(
                "SICHERHEITSABBRUCH: Der Mavi-Starter wurde nicht am erwarteten öffentlichen Desktop-Pfad veröffentlicht."
            )
        return remote_path
    finally:
        if playbook_path is not None:
            playbook_path.unlink(missing_ok=True)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)


def _publish_https_ssh_bootstrap(
    project: Path,
    *,
    host: str,
    public_key: str,
    msi_raw: str = "",
) -> dict[str, str]:
    from .openssh import (
        _atomic_copy_file,
        _atomic_write_bytes,
        _bootstrap_pki_paths,
        _bootstrap_settings,
        _bootstrap_setup_instruction,
        _https_ssh_bootstrap_cmd,
        _sha256_file,
        _software_local_and_windows_path,
        _ssh_bootstrap_ps1,
    )

    from .remote import _certificate_thumbprint_from_der, _safe_host_token
    from .settings import VERSION

    settings = _bootstrap_settings(project)
    webroot: Path = settings["local_dir"]
    safe_host = _safe_host_token(host)
    host_dir = webroot / safe_host
    local_msi: Path | None = None
    if msi_raw:
        local_msi, _, _ = _software_local_and_windows_path(project, msi_raw)
        if local_msi is None or not local_msi.is_file():
            raise FileNotFoundError(
                "Die angegebene OpenSSH-MSI ist auf dem Ansible-Server nicht als Datei erreichbar: "
                f"{msi_raw}"
            )

    try:
        webroot.mkdir(parents=True, exist_ok=True)
        resolved_webroot = webroot.resolve(strict=True)
        host_dir.mkdir(parents=True, exist_ok=True)
        resolved_host_dir = host_dir.resolve(strict=True)
        resolved_host_dir.relative_to(resolved_webroot)
        if resolved_host_dir.parent != resolved_webroot:
            raise PermissionError("Host-Webroot muss ein direkter Unterordner des Bootstrap-Webroots sein.")
        probe_path = host_dir / ".mavi-write-probe"
        _atomic_write_bytes(probe_path, b"write-ok\n", mode=0o600)
        probe_path.unlink()
    except (OSError, ValueError) as exc:
        raise PermissionError(_bootstrap_setup_instruction(project, reason=str(exc))) from exc

    quoted_host = urllib.parse.quote(safe_host, safe="") + "/"
    host_base_url = urllib.parse.urljoin(settings["base_url"], quoted_host)
    ps1_name = f"Mavi-OpenSSH-Setup-{safe_host}.ps1"
    launcher_name = f"START-Mavi-OPENSSH-{safe_host}.cmd"
    msi_name = "OpenSSH-Win64.msi"
    msi_sha256 = ""
    msi_url = ""
    if local_msi is not None:
        msi_destination = host_dir / msi_name
        source_msi_sha256 = _sha256_file(local_msi)
        _atomic_copy_file(local_msi, msi_destination)
        copied_msi_sha256 = _sha256_file(msi_destination)
        if copied_msi_sha256 != source_msi_sha256:
            msi_destination.unlink(missing_ok=True)
            raise RuntimeError(
                "SICHERHEITSABBRUCH: OpenSSH-MSI wurde beim Kopieren verändert; "
                f"Quelle={source_msi_sha256} Ziel={copied_msi_sha256}"
            )
        msi_sha256 = source_msi_sha256
        msi_url = urllib.parse.urljoin(host_base_url, msi_name)

    pki_paths = _bootstrap_pki_paths(project)
    if not pki_paths["system_ca"].is_file():
        raise FileNotFoundError(
            "Die automatisch verwaltete Mavi-CA fehlt. 'mavi-provisioner ssh server-setup' ausführen."
        )
    try:
        ca_pem = pki_paths["system_ca"].read_text(encoding="ascii")
        ca_der = ssl.PEM_cert_to_DER_cert(ca_pem)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ValueError(f"Das Mavi-CA-Zertifikat ist nicht lesbar: {exc}") from exc
    ca_windows_thumbprint = hashlib.sha1(ca_der, usedforsecurity=False).hexdigest().upper()
    ps1_url = urllib.parse.urljoin(host_base_url, ps1_name)
    ps1_bytes = _ssh_bootstrap_ps1(
        public_key,
        bundled_msi=False,
        msi_download_url=msi_url,
        msi_sha256=msi_sha256,
        expected_signer=settings["expected_signer"],
        ansible_server_ip=settings["ansible_server_ip"],
        bootstrap_instance_id=settings["instance_id"],
        bootstrap_ca_thumbprint=ca_windows_thumbprint,
    ).encode("utf-8-sig")
    ps1_sha256 = hashlib.sha256(ps1_bytes).hexdigest()
    ca_thumbprint = _certificate_thumbprint_from_der(ca_der)
    launcher_bytes = _https_ssh_bootstrap_cmd(
        ps1_url,
        ps1_sha256,
        ca_der=ca_der,
        launcher_id=safe_host,
    ).encode("ascii", errors="strict")

    _atomic_write_bytes(host_dir / ps1_name, ps1_bytes)
    _atomic_write_bytes(host_dir / launcher_name, launcher_bytes)

    launcher_sha256 = hashlib.sha256(launcher_bytes).hexdigest()
    # Der Starter ist absichtlich immer als echte lokale Datei vorhanden. Damit
    # kann er mit `cat <Datei>` angezeigt und manuell in den Mavi-Release-Ordner
    # kopiert werden. Ein schreibgeschützter Install-Mount blockiert die
    # OpenSSH-Vorbereitung nicht und es gibt keinen PSRP-/NTLM-Kopier-Fallback.
    offline_launcher = host_dir / launcher_name
    windows_launcher = ""
    delivery_method = "manual_release_file"
    delivery_note = "Starter lokal erzeugt; manuelle Ablage im Mavi-Release-Ordner vorgesehen."
    software_share_error = ""
    metadata = {
        "version": VERSION,
        "host": host,
        "mode": "fixed_https",
        "created_epoch": time.time(),
        "launcher_url": urllib.parse.urljoin(host_base_url, launcher_name),
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "ca_thumbprint": ca_thumbprint,
        "instance_id": settings["instance_id"],
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "software_share_error": software_share_error,
    }
    _atomic_write_bytes(
        host_dir / ".mavi-bootstrap.json",
        (json.dumps(metadata, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
    )
    health_body = f"Mavi HTTPS Bootstrap v{VERSION}\n".encode("ascii")
    _atomic_write_bytes(webroot / "Mavi-SETUP-CHECK.txt", health_body)
    return {
        "local_dir": str(host_dir),
        "launcher": launcher_name,
        "launcher_url": metadata["launcher_url"],
        "launcher_sha256": launcher_sha256,
        "offline_launcher": str(offline_launcher),
        "windows_launcher": windows_launcher,
        "delivery_method": delivery_method,
        "delivery_note": delivery_note,
        "ca_der_sha256": hashlib.sha256(ca_der).hexdigest(),
        "ca_windows_thumbprint": ca_windows_thumbprint,
        "ca_thumbprint": ca_thumbprint,
        "instance_id": settings["instance_id"],
        "ps1_url": ps1_url,
        "ps1_sha256": ps1_sha256,
        "msi_url": msi_url,
        "msi_sha256": msi_sha256,
        "health_url": urllib.parse.urljoin(settings["base_url"], "Mavi-SETUP-CHECK.txt"),
        "health_body": health_body.decode("ascii"),
        "ansible_server_ip": settings["ansible_server_ip"],
        "expected_signer": settings["expected_signer"],
    }
