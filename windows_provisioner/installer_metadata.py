# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""PE- und Produktmetadaten.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    pefile,
    re,
    shutil,
    struct,
    subprocess,
    sys,
)




PE_VERSION_KEYS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "ProductVersion",
    "FileVersion",
    "OriginalFilename",
    "InternalName",
    "LegalCopyright",
)


def _clean_pe_text(value: Any) -> str:
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16le", "latin-1"):
            try:
                value = value.decode(encoding, errors="ignore")
                break
            except Exception:
                continue

    value = str(value or "")
    value = value.replace("\x00", "").strip()
    value = re.sub(r"\s+", " ", value)
    return value


def _pe_architecture_from_bytes(data: bytes) -> str:
    """
    Liest nur DOS/PE-Header. Keine Ausführung der EXE.
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return ""

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 > len(data):
            return ""

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return ""

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        return {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "arm64",
        }.get(machine, f"0x{machine:04x}")
    except (struct.error, IndexError):
        return ""


def _printable_pe_strings(data: bytes) -> list[tuple[int, str]]:
    """
    Extrahiert ASCII- und UTF-16LE-Strings inklusive Position.
    Das dient als Fallback, wenn python-pefile nicht installiert ist.
    """
    found: list[tuple[int, str]] = []

    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", data):
        try:
            value = match.group(0).decode("utf-16le", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        try:
            value = match.group(0).decode("latin-1", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    found.sort(key=lambda item: item[0])
    return found


def _versioninfo_from_strings(data: bytes) -> dict[str, str]:
    """
    Windows VERSIONINFO besteht häufig aus UTF-16LE-Schlüsseln wie
    CompanyName/ProductName und dem direkt folgenden Wert.
    """
    from .installer_analysis import (
        PE_VERSION_KEYS,
        _clean_pe_text,
        _printable_pe_strings,
    )

    strings = _printable_pe_strings(data)
    result: dict[str, str] = {}
    key_lookup = {key.lower(): key for key in PE_VERSION_KEYS}
    ignored_values = {
        "StringFileInfo",
        "VarFileInfo",
        "Translation",
        "VS_VERSION_INFO",
    }

    for idx, (offset, value) in enumerate(strings):
        canonical = key_lookup.get(value.lower())
        if not canonical or canonical in result:
            continue

        # Der Wert folgt im VERSIONINFO normalerweise kurz nach dem Schlüssel.
        for next_offset, candidate in strings[idx + 1: idx + 8]:
            if next_offset - offset > 2048:
                break

            candidate = _clean_pe_text(candidate)
            if not candidate:
                continue

            if candidate in ignored_values:
                continue

            if candidate.lower() in key_lookup:
                break

            # Binärrauschen und offensichtliche Struktur-Strings ignorieren.
            if len(candidate) > 300:
                continue
            if candidate.count("\\") > 8:
                continue

            result[canonical] = candidate
            break

    return result


def _versioninfo_with_pefile(path: Path) -> dict[str, str]:
    from .installer_analysis import (
        PE_VERSION_KEYS,
        _clean_pe_text,
    )

    if pefile is None:
        return {}

    result: dict[str, str] = {}

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
            ]
        )

        for block in getattr(pe, "FileInfo", []) or []:
            # pefile kann FileInfo als verschachtelte Listen liefern.
            entries = block if isinstance(block, list) else [block]

            for entry in entries:
                key = _clean_pe_text(getattr(entry, "Key", ""))

                if key != "StringFileInfo":
                    continue

                for table in getattr(entry, "StringTable", []) or []:
                    for raw_key, raw_value in (
                        getattr(table, "entries", {}) or {}
                    ).items():
                        k = _clean_pe_text(raw_key)
                        v = _clean_pe_text(raw_value)
                        if k in PE_VERSION_KEYS and v:
                            result[k] = v

        try:
            pe.close()
        except Exception:
            pass

    except Exception:
        return {}

    return result


def inspect_pe_metadata(path: Path, sample: bytes | None = None) -> dict[str, Any]:
    """
    Deep-Scan einer Windows-EXE, ohne sie auszuführen.

    Reihenfolge:
      1. PE-Header / Architektur
      2. python-pefile, falls vorhanden
      3. eigener VERSIONINFO-String-Fallback
      4. optional Authenticode-Info über osslsigncode, falls installiert
    """
    from .installer_analysis import (
        _clean_pe_text,
        _pe_architecture_from_bytes,
        _versioninfo_from_strings,
        _versioninfo_with_pefile,
    )

    from .environment import read_binary_sample

    metadata: dict[str, Any] = {}
    sources: list[str] = []

    try:
        if sample is None:
            sample = read_binary_sample(path)
    except OSError:
        sample = b""

    arch = _pe_architecture_from_bytes(sample or b"")
    if arch:
        metadata["PEArchitecture"] = arch
        sources.append("PE-Header")

    precise = _versioninfo_with_pefile(path)
    if precise:
        metadata.update(precise)
        sources.append("PE-VersionInfo (pefile)")

    fallback = _versioninfo_from_strings(sample or b"")
    for key, value in fallback.items():
        metadata.setdefault(key, value)
    if fallback:
        sources.append("PE-VersionInfo (String-Fallback)")

    # Optional: Signaturinformationen lesen, wenn osslsigncode vorhanden ist.
    # Fehlt das Tool, funktioniert der Scanner trotzdem vollständig weiter.
    osslsigncode = shutil.which("osslsigncode")
    if osslsigncode:
        try:
            proc = subprocess.run(
                [osslsigncode, "verify", "-in", str(path)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            subject_patterns = [
                r"Subject:\s*(.+)",
                r"Signer Certificate:\s*\n\s*Subject:\s*(.+)",
            ]
            for pattern in subject_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    subject = _clean_pe_text(match.group(1))
                    if subject:
                        metadata["SignatureSubject"] = subject
                        sources.append("Authenticode (osslsigncode)")
                        break
        except (OSError, subprocess.TimeoutExpired):
            pass

    if sources:
        metadata["ScanSources"] = list(dict.fromkeys(sources))

    return metadata


def _metadata_blob(path: Path, metadata: dict[str, Any]) -> str:
    values = [str(path)]
    for key in (
        "CompanyName",
        "ProductName",
        "FileDescription",
        "OriginalFilename",
        "InternalName",
        "SignatureSubject",
    ):
        value = metadata.get(key)
        if value:
            values.append(str(value))
    return "\n".join(values).lower()


def _citrix_detection_path(metadata: dict[str, Any]) -> str:
    """
    Native x64 Citrix Workspace landet systemweit unter Program Files.
    Für x86 verwenden wir Program Files (x86).
    """
    arch = str(metadata.get("PEArchitecture", "")).lower()

    if arch == "x64":
        return (
            r"C:\Program Files\Citrix\ICA Client"
            r"\SelfServicePlugin\SelfService.exe"
        )

    return (
        r"C:\Program Files (x86)\Citrix\ICA Client"
        r"\Receiver\receiver.exe"
    )


def _apply_known_exe_product_rule(
    path: Path,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> bool:
    """
    Produktregeln verwenden Dateiname UND PE-Metadaten.
    Rückgabe True bedeutet: sichere bekannte Regel, Analyse ist fertig.
    """
    from .installer_analysis import (
        _citrix_detection_path,
        _metadata_blob,
    )

    blob = _metadata_blob(path, metadata)

    # PASCOM
    if "pascom" in blob:
        result.update(
            type="exe",
            engine="PASCOM Windows App",
            arguments="/S",
            context="user_interactive",
            confidence="hoch",
            admin_requirement="nein",
            name_guess=metadata.get("ProductName") or "PASCOM",
            note=(
                "Bekannte PASCOM-Regel. Für den normalen Client wird der "
                "nicht erhöhte Benutzerkontext verwendet."
            ),
        )
        result["reasons"].extend([
            "PASCOM über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: Silent-Schalter /S.",
            "Bekannte Mavi-Regel: interaktive Installation im angemeldeten Benutzerkontext.",
        ])
        return True

    # FortiClient
    if "forticlient" in blob or "fortivpn" in blob:
        result.update(
            type="exe",
            engine="FortiClient VPN",
            arguments="/quiet /norestart",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "FortiClient VPN",
            note=(
                "FortiClient über Dateiname oder PE-Metadaten erkannt. "
                "Systemweite Installation wird als Machine/Admin behandelt."
            ),
        )
        result["reasons"].extend([
            "FortiClient/FortiVPN über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: /quiet /norestart.",
            "Systemweite VPN-Client-Installation.",
        ])
        return True

    # Citrix Workspace
    citrix_workspace = (
        "citrixworkspaceapp" in blob.replace(" ", "")
        or (
            "citrix" in blob
            and (
                "workspace" in blob
                or "receiver" in blob
            )
        )
    )

    if citrix_workspace:
        detection_path = _citrix_detection_path(metadata)
        result.update(
            type="exe",
            engine="Citrix Workspace",
            arguments="/silent /noreboot",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "Citrix Workspace",
            creates_path=detection_path,
            note=(
                "Citrix Workspace über Dateiname/PE-Metadaten erkannt. "
                "Für Mavi wird die systemweite unbeaufsichtigte Installation verwendet."
            ),
        )
        result["metadata"]["DetectedProduct"] = "Citrix Workspace"
        result["reasons"].extend([
            "Citrix Workspace über Dateiname oder PE-VersionInfo erkannt.",
            "Silent-Installation: /silent /noreboot.",
            "Mavi-Provisioner: systemweit als Machine/Admin.",
            f"Detection-Datei: {detection_path}",
        ])
        return True

    return False
