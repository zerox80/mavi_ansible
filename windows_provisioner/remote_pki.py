# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""WinRM-PKI und Zertifikatsausstellung.

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



def _certificate_thumbprint_from_der(certificate_der: bytes) -> str:
    """Den Windows-kompatiblen SHA-1-Thumbprint eines DER-Zertifikats liefern."""
    if not certificate_der:
        raise ValueError("Das Zertifikat ist leer.")
    try:
        digest = hashlib.sha1(certificate_der, usedforsecurity=False)
    except TypeError:
        digest = hashlib.sha1(certificate_der)
    return digest.hexdigest().upper()


def _certificate_der_from_file(path: Path) -> bytes:
    """Ein PEM- oder DER-Zertifikat als kanonische DER-Bytes lesen."""
    raw = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in raw:
        try:
            return ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"Zertifikat ist kein gültiges PEM: {path}") from exc
    if not raw:
        raise ValueError(f"Zertifikat ist leer: {path}")
    return raw


def _certificate_thumbprint_from_file(path: Path) -> str:
    """PEM- oder DER-Zertifikat exakt in den Windows-Thumbprint überführen."""
    from .remote import (
        _certificate_der_from_file,
        _certificate_thumbprint_from_der,
    )

    return _certificate_thumbprint_from_der(_certificate_der_from_file(path))


def _certificate_der_base64_from_file(path: Path) -> str:
    """Öffentliches Zertifikat für einen exakten Remote-Identitätsabgleich kodieren."""
    from .remote import (
        _certificate_der_from_file,
    )

    return base64.b64encode(_certificate_der_from_file(path)).decode("ascii")


def _bootstrap_root_ca_thumbprint(project: Path) -> str:
    """Den exakten Thumbprint der aktuell von Mavi ausgelieferten Bootstrap-CA liefern."""

    from .remote import (
        _certificate_thumbprint_from_file,
    )

    from .openssh import _bootstrap_pki_paths
    from .reports import redact_sensitive_text

    paths = _bootstrap_pki_paths(project)
    candidates = (paths["system_ca"], paths["ca_cert"])
    errors: list[str] = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            return _certificate_thumbprint_from_file(candidate)
        except (OSError, ValueError) as exc:
            errors.append(redact_sensitive_text(exc))
    detail = f" ({'; '.join(errors)})" if errors else ""
    raise RuntimeError(
        "Die aktuell von Mavi verwendete Bootstrap-CA ist auf dem Controller nicht lesbar. "
        "Der vollständige Option-11-Rückbau wird nicht mit einer unscharfen Subject-Suche ausgeführt."
        + detail
    )


def _normalized_certificate_thumbprint(value: Any) -> str:
    """Nur einen vollständigen Windows-X.509-Thumbprint akzeptieren."""
    normalized = re.sub(r"\s+", "", str(value or "")).upper()
    return normalized if re.fullmatch(r"[A-F0-9]{40}", normalized) else ""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    from .remote import (
        _winrm_local_command,
        _winrm_pki_paths,
    )

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


def _validate_inventory_host_alias(host: str) -> str:
    """Auch historisch erlaubte Inventory-Aliase ohne Pfadzeichen validieren."""
    raw_host = str(host or "")
    if re.fullmatch(r"[A-Za-z0-9_.-]+", raw_host) is None:
        raise ValueError(
            "Der Inventory-Hostname darf nur ASCII-Buchstaben, Ziffern, Punkt, Unterstrich "
            "und Bindestrich enthalten."
        )
    return raw_host


def _validate_new_host_alias(host: str) -> str:
    """Die strengere, dateifreundliche Regel ausschließlich für neue Hosts anwenden."""
    raw_host = str(host or "")
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", raw_host) is None:
        raise ValueError(
            "PC-Name darf nur Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich enthalten "
            "und muss mit einem Buchstaben oder einer Ziffer beginnen und enden."
        )
    return raw_host


def _safe_host_token(host: str) -> str:
    """Inventory-Alias kollisionsarm und plattformneutral als Dateikomponente abbilden."""
    from .remote import (
        _validate_inventory_host_alias,
    )

    raw_host = _validate_inventory_host_alias(host)
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", raw_host):
        # Für bereits erzeugte Artefakte regulärer Hosts bleibt der Pfad stabil.
        return raw_host

    # Alte Inventories durften auch mit Punkt, Unterstrich oder Bindestrich
    # beginnen/enden. Solche Namen (insbesondere "." und "..") dürfen nie
    # direkt zu Pfadkomponenten werden. Das @ kann in keinem gültigen alten
    # Alias vorkommen und trennt den Hash-Namensraum daher von echten Aliasen.
    digest = hashlib.sha256(raw_host.encode("ascii")).hexdigest()
    return f"@mavi-legacy-host-{digest}"


def _host_artifact_tokens(host: str, *, include_legacy: bool = False) -> tuple[str, ...]:
    """Aktuellen und optional den historischen Artefakt-Namensraum liefern.

    Neue Dateien werden immer nur unter ``_safe_host_token`` geschrieben. Der
    zweite Token bildet ausschliesslich den bis v0.8.46 verwendeten
    ``strip('._-')``-Namensraum fuer die Migration beim Cleanup nach.
    """
    from .remote import (
        _safe_host_token,
        _validate_inventory_host_alias,
    )


    raw_host = _validate_inventory_host_alias(host)
    current_token = _safe_host_token(raw_host)
    tokens = [current_token]
    if include_legacy:
        legacy_token = raw_host.strip("._-") or "WINDOWS"
        if legacy_token != current_token:
            tokens.append(legacy_token)
    return tuple(tokens)


def _cleanup_host_artifact_tokens(
    host: str,
    *,
    known_hosts: Any = None,
) -> tuple[tuple[str, ...], list[str]]:
    """Legacy-Token nur ohne Kollision mit einem anderen Inventory-Host freigeben."""
    from .remote import (
        _host_artifact_tokens,
        _validate_inventory_host_alias,
    )


    raw_host = _validate_inventory_host_alias(host)
    tokens = _host_artifact_tokens(raw_host, include_legacy=True)
    if len(tokens) == 1:
        return tokens, []

    current_token, legacy_token = tokens
    if known_hosts is None:
        return (current_token,), [
            "Der historische Artefakt-Namensraum wurde ohne vollständige Inventory-Hostliste "
            f"nicht bereinigt: {legacy_token}"
        ]

    collisions: list[str] = []
    invalid_alias = False
    try:
        inventory_aliases = list(known_hosts)
    except TypeError:
        inventory_aliases = []
        invalid_alias = True

    for candidate in inventory_aliases:
        candidate_alias = str(candidate or "")
        if candidate_alias == raw_host:
            continue
        try:
            candidate_tokens = _host_artifact_tokens(candidate_alias, include_legacy=True)
        except ValueError:
            invalid_alias = True
            continue
        if any(token.casefold() == legacy_token.casefold() for token in candidate_tokens):
            collisions.append(candidate_alias)

    if invalid_alias or collisions:
        reason = (
            "mindestens ein Inventory-Alias ist ungültig"
            if invalid_alias
            else "der Namensraum auch zu " + ", ".join(sorted(collisions, key=str.casefold)) + " gehört"
        )
        return (current_token,), [
            "Der historische Artefakt-Namensraum wurde wegen einer möglichen Host-Kollision "
            f"nicht bereinigt ({legacy_token}: {reason})."
        ]
    return tokens, []


def _issue_winrm_server_certificate(
    project: Path,
    *,
    host: str,
    identity: dict[str, Any],
    csr_pem: bytes,
) -> dict[str, Any]:
    """Eine auf Windows erzeugte CSR prüfen und mit der Mavi-WinRM-CA signieren."""

    from .remote import (
        _ensure_winrm_ca,
        _safe_host_token,
        _winrm_leaf_openssl_config,
        _winrm_local_command,
    )

    from .openssh import (
        _atomic_write_bytes,
        _sha256_file,
    )

    paths = _ensure_winrm_ca(project)
    safe_host = _safe_host_token(host)
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
