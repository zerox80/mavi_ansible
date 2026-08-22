# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Installerdatei-Inspektion.

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
    yaml,
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_binary_sample(path: Path, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    size = path.stat().st_size
    with path.open("rb") as f:
        if size <= max_bytes:
            return f.read()
        half = max_bytes // 2
        start = f.read(half)
        f.seek(max(0, size - half))
        end = f.read(half)
        return start + end



def _decode_binary_text(sample: bytes) -> str:
    chunks = []

    try:
        chunks.append(sample.decode("latin-1", errors="ignore"))
    except Exception:
        pass

    try:
        chunks.append(sample.decode("utf-16le", errors="ignore"))
    except Exception:
        pass

    return "\n".join(chunks).lower()


def _extract_execution_level(text_data: str) -> str | None:
    patterns = [
        r'requestedexecutionlevel.{0,300}?level\s*=\s*["\'](requireadministrator|highestavailable|asinvoker)["\']',
        r'level\s*=\s*["\'](requireadministrator|highestavailable|asinvoker)["\'].{0,300}?requestedexecutionlevel',
    ]

    compact = re.sub(r"\s+", " ", text_data, flags=re.MULTILINE)
    for pattern in patterns:
        match = re.search(pattern, compact, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None


def _inspect_msi_properties(path: Path) -> dict[str, str]:
    """
    Nutzt msiinfo aus dem Paket msitools, falls es auf dem Controller
    installiert ist. Ohne msiinfo funktioniert das Tool weiterhin.
    """
    exe = shutil.which("msiinfo")
    if not exe:
        return {}

    try:
        result = subprocess.run(
            [exe, "export", str(path), "Property"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        return {}

    if result.returncode != 0:
        return {}

    wanted = {
        "ProductName",
        "Manufacturer",
        "ProductVersion",
        "ProductCode",
        "ALLUSERS",
        "MSIINSTALLPERUSER",
    }
    props: dict[str, str] = {}

    for line in result.stdout.splitlines():
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) >= 2 and parts[0] in wanted:
            props[parts[0]] = parts[1]

    return props
