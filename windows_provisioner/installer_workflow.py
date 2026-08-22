# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Zusammengeführte Installeranalyse.

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





def analyze_installer(
    path: Path,
    project: Path | None = None,
    *,
    use_known_rules: bool = True,
    use_learned_rules: bool = False,
) -> dict[str, Any]:
    """
    v0.8: bewusst KEIN Deep-Scan mehr.

    Es werden nur noch:
      - Dateityp MSI/EXE,
      - feste, im Skript hinterlegte Produktregeln
    verwendet.

    Unbekannte EXE-Parameter werden immer vom Benutzer eingetragen.
    Keine Binary-String-Suche, keine Engine-Raterei, keine gelernten
    Regeln und keine automatische Silent-Erkennung.
    """
    from .installer_analysis import (
        _apply_known_exe_product_rule,
    )

    ext = path.suffix.lower()

    result: dict[str, Any] = {
        "type": ext.lstrip("."),
        "engine": "unbekannt",
        "arguments": "",
        "context": "machine",
        "confidence": "manuell",
        "admin_requirement": "unbekannt",
        "name_guess": path.stem,
        "creates_path": "",
        "note": "",
        "reasons": [],
        "metadata": {},
    }

    if ext == ".msi":
        result.update(
            type="msi",
            engine="MSI / Windows Installer",
            arguments="",
            context="machine",
            confidence="fest",
            admin_requirement="wahrscheinlich",
            note=(
                "MSI erkannt. Kein Deep-Scan und keine Silent-Parameter-"
                "Raterei. Ansible win_package behandelt MSI direkt."
            ),
        )
        result["reasons"].append("Dateiendung .msi erkannt.")
        return result

    if ext != ".exe":
        result["note"] = (
            "Nur MSI und EXE werden für normale Software unterstützt."
        )
        return result

    result.update(
        type="exe",
        engine="EXE / manuelle Parameter",
        context="machine",
        confidence="manuell",
        note=(
            "Deep-Scan ist deaktiviert. Für unbekannte EXE-Dateien werden "
            "Silent-Parameter ausschließlich manuell eingetragen."
        ),
    )

    if use_known_rules and _apply_known_exe_product_rule(
        path,
        result,
        {},
    ):
        result["reasons"].append(
            "Parameter stammen ausschließlich aus einer festen "
            "Produktregel im Python-Skript."
        )
        return result

    result["reasons"].append(
        "Keine feste Produktregel gefunden. Parameter werden manuell gesetzt."
    )
    return result
