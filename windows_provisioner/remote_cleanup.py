# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Hostgebundene Zertifikatsbereinigung.

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



def _remove_host_bootstrap_artifacts(
    project: Path,
    host: str,
    *,
    known_hosts: Any = None,
) -> tuple[int, list[str]]:
    """Ausschließlich den direkten, Mavi-eigenen Bootstrap-Ordner eines Hosts löschen."""

    from .remote import (
        _cleanup_host_artifact_tokens,
    )

    from .openssh import _bootstrap_settings
    from .reports import redact_sensitive_text

    removed = 0
    host_tokens, warnings = _cleanup_host_artifact_tokens(host, known_hosts=known_hosts)
    try:
        settings = _bootstrap_settings(project)
    except ValueError as exc:
        return removed, [
            "Hostbezogene Bootstrap-Dateien wurden nicht bereinigt, weil die Bootstrap-Konfiguration "
            f"nicht sicher gelesen werden konnte: {redact_sensitive_text(exc)}"
        ]

    webroot = Path(settings["local_dir"])
    host_dirs = [
        webroot / token
        for token in host_tokens
    ]
    try:
        if not webroot.exists():
            return removed, warnings
        if webroot.is_symlink():
            return removed, [f"Verknüpfter Bootstrap-Webroot wurde nicht bereinigt: {webroot}"]
        resolved_webroot = webroot.resolve(strict=True)
        for host_dir in host_dirs:
            if not host_dir.exists():
                continue
            if host_dir.is_symlink():
                warnings.append(
                    f"Verknüpfter Host-Bootstrap-Ordner wurde nicht bereinigt: {host_dir}"
                )
                continue
            resolved_host_dir = host_dir.resolve(strict=True)
            if resolved_host_dir.parent != resolved_webroot:
                warnings.append(
                    f"Unerwarteter Host-Bootstrap-Pfad wurde nicht bereinigt: {resolved_host_dir}"
                )
                continue
            # Diese Pfade werden ausschließlich durch den HTTPS-Bootstrap als
            # direkte Host-Unterordner angelegt. Der gemeinsame Webroot und die
            # Bootstrap-CA werden absichtlich nicht rekursiv berührt.
            removed += sum(1 for _ in resolved_host_dir.rglob("*")) + 1
            shutil.rmtree(resolved_host_dir)
    except OSError as exc:
        warnings.append(
            "Ein hostbezogener Bootstrap-Ordner konnte nicht entfernt werden: "
            f"{redact_sensitive_text(exc)}"
        )
    return removed, warnings


def _remove_host_winrm_certificate_artifacts(
    project: Path,
    host: str,
    *,
    keep_request_id: str = "",
    known_hosts: Any = None,
) -> tuple[int, list[str]]:
    """Nur die eindeutig diesem Host zugeordneten WinRM-PKI-Dateien löschen.

    Beim Zertifikatswechsel darf das gerade erfolgreiche Leaf auf dem Controller
    verbleiben. Beim vollständigen Rückbau wird ohne keep_request_id alles
    Hostbezogene entfernt; die gemeinsame WinRM-Root-CA bleibt immer erhalten.
    """
    from .remote import (
        _cleanup_host_artifact_tokens,
        _winrm_pki_paths,
    )


    from .reports import redact_sensitive_text
    paths = _winrm_pki_paths(project)
    host_tokens, warnings = _cleanup_host_artifact_tokens(host, known_hosts=known_hosts)
    retained_request = str(keep_request_id or "").strip().lower()
    if retained_request and not re.fullmatch(r"[a-f0-9]{24}", retained_request):
        raise ValueError("Die beizubehaltende Mavi-WinRM-Request-ID ist ungültig.")
    escaped_hosts = "|".join(re.escape(token) for token in host_tokens)
    file_patterns = {
        "requests": re.compile(rf"^(?:{escaped_hosts})-[a-f0-9]{{24}}\.csr\.pem$"),
        "profiles": re.compile(rf"^(?:{escaped_hosts})-[a-f0-9]{{24}}\.cnf$"),
        "certs": re.compile(
            rf"^(?:(?:{escaped_hosts})-[a-f0-9]{{24}}\.(?:cert\.pem|cer)|"
            rf"\.(?:{escaped_hosts})-[a-f0-9]{{24}}\.cert\.new)$"
        ),
    }
    removed = 0
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
            if retained_request and retained_request in candidate.name.lower():
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
