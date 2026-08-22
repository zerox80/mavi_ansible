# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Softwareanalyse und Katalogbereinigung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    ET,
    Path,
    argparse,
    base64,
    getpass,
    json,
    os,
    re,
    subprocess,
    sys,
    tempfile,
    yaml,
)





def cmd_software_scan(args: argparse.Namespace) -> None:
    from .environment import (
        choose_installer_path,
        die,
        ensure_initialized,
        get_config,
        normalize_path,
        resolve_installer_path,
    )
    from .installer_analysis import (
        analyze_installer,
        print_silent_detection,
    )
    from .reports import redact_sensitive_text

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    if args.path:
        path = resolve_installer_path(
            normalize_path(args.path, config),
            config,
        )
    else:
        path = choose_installer_path(config)
        path = resolve_installer_path(path, config)

    if not path.exists() or not path.is_file():
        die(f"Installer nicht gefunden: {path}")

    mode = getattr(args, "mode", "full") or "full"

    use_known_rules = mode == "full"
    use_learned_rules = mode == "full"

    analysis = analyze_installer(
        path,
        args.project,
        use_known_rules=use_known_rules,
        use_learned_rules=use_learned_rules,
    )

    print()
    print("INSTALLER DEEP-SCAN")
    print("===================")
    print(f"Modus:      {mode}")
    if mode == "heuristic":
        print("Regeln:     feste Produktregeln AUS, gelernte Regeln AUS")
        print("            nur PE/VersionInfo + Engine + eingebettete CLI-Strings")
    else:
        print("Regeln:     volle Produktionserkennung")
    print(f"Pfad:       {path}")
    print(f"Typ:        {analysis.get('type', '')}")
    print(f"Produkt:    {analysis.get('name_guess', '')}")
    print(f"Engine:     {analysis.get('engine', 'unbekannt')}")
    print(f"Silent:     {redact_sensitive_text(analysis.get('arguments')) or '(nicht sicher erkannt)'}")
    print(f"Kontext:    {analysis.get('context', 'unbekannt')}")
    print(f"Admin:      {analysis.get('admin_requirement', 'unbekannt')}")
    print(f"Konfidenz:  {analysis.get('confidence', 'niedrig')}")

    metadata = analysis.get("metadata", {}) or {}
    for key, label in (
        ("CompanyName", "Hersteller"),
        ("ProductName", "ProductName"),
        ("FileDescription", "Beschreibung"),
        ("ProductVersion", "Version"),
        ("OriginalFilename", "Originaldatei"),
        ("PEArchitecture", "Architektur"),
        ("SignatureSubject", "Signatur"),
        ("LearnedRule", "Gelernte Regel"),
    ):
        if metadata.get(key):
            print(f"{label + ':':<12} {metadata[key]}")

    print_silent_detection(analysis)

    reasons = analysis.get("reasons", [])
    if reasons:
        print()
        print("Warum")
        print("=====")
        for reason in reasons:
            print(f"  • {reason}")

    if analysis.get("note"):
        print()
        print("Hinweis:")
        print("  " + str(analysis["note"]))




def _neutralize_jinja_literal(value: str) -> str:
    """
    Katalogwerte sind Daten, keine Templates.
    Zufällige Jinja-Startsequenzen aus Binär-/Metadaten werden neutralisiert,
    damit Ansible sie später nicht als Template interpretiert.
    """
    from .reports import VAULT_ARGUMENT_REFERENCE_RE

    # A single, deliberately narrow template form is supported for secrets:
    # {{ vault_name }} / {{ mavi_vault_name }}.  Filters, lookups, attributes
    # and expressions remain data and are neutralised.  This lets a catalog
    # reference an Ansible-Vault variable without ever storing its value.
    protected: list[tuple[str, str]] = []

    def protect(match: re.Match[str]) -> str:
        marker = f"__MAVI_ALLOWED_VAULT_REFERENCE_{len(protected)}__"
        while marker in value:
            marker = "_" + marker
        protected.append((marker, match.group(0)))
        return marker

    safe_value = VAULT_ARGUMENT_REFERENCE_RE.sub(protect, value)
    safe_value = (
        safe_value
        .replace("{{", "{ {")
        .replace("{%", "{ %")
        .replace("{#", "{ #")
    )
    for marker, reference in protected:
        safe_value = safe_value.replace(marker, reference)
    return safe_value


def sanitize_catalog_data(value: Any) -> Any:
    """
    Rekursiv literal-sichere Daten für YAML/Ansible erzeugen.
    """
    from .software import (
        _neutralize_jinja_literal,
    )

    if isinstance(value, str):
        return _neutralize_jinja_literal(value)

    if isinstance(value, list):
        return [
            sanitize_catalog_data(item)
            for item in value
        ]

    if isinstance(value, dict):
        return {
            sanitize_catalog_data(key): sanitize_catalog_data(val)
            for key, val in value.items()
        }

    return value


def compact_silent_detection_for_catalog(
    detection: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Roh-Kontexte aus Binary-Scans gehören NICHT in produktive Katalogdateien.

    Persistiert werden nur die für Nachvollziehbarkeit nützlichen,
    kontrollierten Zusammenfassungsfelder.
    """
    from .software import (
        sanitize_catalog_data,
    )

    detection = detection or {}

    allowed = (
        "arguments",
        "confidence",
        "method",
        "source_label",
        "reason",
    )

    return {
        key: sanitize_catalog_data(detection[key])
        for key in allowed
        if key in detection and detection[key] not in (None, "", [], {})
    }


def compact_analysis_for_catalog(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    """
    Nur kuratierte Analyseinformationen speichern.
    Keine candidate/context/rejected-Dumps aus Binärdateien.
    """
    from .software import (
        compact_silent_detection_for_catalog,
        sanitize_catalog_data,
    )

    from .settings import VERSION

    metadata = analysis.get("metadata", {}) or {}

    safe_metadata_keys = (
        "CompanyName",
        "ProductName",
        "FileDescription",
        "ProductVersion",
        "FileVersion",
        "OriginalFilename",
        "InternalName",
        "PEArchitecture",
        "SignatureSubject",
        "requestedExecutionLevel",
        "UACElevationRequestedByExe",
        "DetectedProduct",
        "LearnedRule",
        "ScanSources",
        "user_markers",
        "machine_markers",
    )

    safe_metadata = {
        key: sanitize_catalog_data(metadata[key])
        for key in safe_metadata_keys
        if key in metadata and metadata[key] not in (None, "", [], {})
    }

    return sanitize_catalog_data({
        "confidence": analysis.get("confidence", "niedrig"),
        "admin_requirement": analysis.get(
            "admin_requirement",
            "unbekannt",
        ),
        "metadata": safe_metadata,
        "silent_detection": compact_silent_detection_for_catalog(
            analysis.get("silent_detection")
        ),
        "scanner_version": VERSION,
        "reasons": analysis.get("reasons", []),
    })


def repair_catalog_jinja_noise(
    project: Path,
    catalog_name: str,
) -> tuple[int, Path]:
    """
    Repariert alte v0.7.x-Katalogeinträge:
    - entfernt rohe candidate/rejected_candidate Debugdaten
    - neutralisiert zufällige Jinja-Startsequenzen
    """
    from .software import (
        sanitize_catalog_data,
    )

    from .catalogs import (
        catalog_path,
        get_catalog,
        save_catalog,
    )
    from .settings import VERSION

    path = catalog_path(project, catalog_name)
    catalog = get_catalog(project, catalog_name)
    sw = catalog.get("software_catalog", {})

    changed_entries = 0

    for key, app in list(sw.items()):
        if not isinstance(app, dict):
            continue

        original = yaml.safe_dump(
            app,
            allow_unicode=True,
            sort_keys=False,
        )

        analysis = app.get("analysis")
        if isinstance(analysis, dict):
            detection = analysis.get("silent_detection")

            if isinstance(detection, dict):
                detection.pop("candidates", None)
                detection.pop("rejected_candidates", None)

            # Alte Analyse ebenfalls auf die sichere kompakte Form bringen.
            rebuilt_analysis = {
                "confidence": analysis.get(
                    "confidence",
                    "niedrig",
                ),
                "admin_requirement": analysis.get(
                    "admin_requirement",
                    "unbekannt",
                ),
                "metadata": analysis.get("metadata", {}),
                "silent_detection": analysis.get(
                    "silent_detection",
                    {},
                ),
                "scanner_version": analysis.get(
                    "scanner_version",
                    VERSION,
                ),
                "reasons": analysis.get("reasons", []),
            }

            app["analysis"] = sanitize_catalog_data(
                rebuilt_analysis
            )

        # Den gesamten Paketdatensatz als Literal behandeln.
        sw[key] = sanitize_catalog_data(app)

        updated = yaml.safe_dump(
            sw[key],
            allow_unicode=True,
            sort_keys=False,
        )

        if updated != original:
            changed_entries += 1

    if changed_entries:
        save_catalog(
            project,
            catalog,
            catalog_name,
        )

    return changed_entries, path


def cmd_catalog_repair(args: argparse.Namespace) -> None:
    from .software import (
        repair_catalog_jinja_noise,
    )

    from .catalogs import (
        list_catalog_names,
        resolve_catalog_name,
    )
    from .environment import ensure_initialized

    ensure_initialized(args.project, quiet=True)

    if getattr(args, "all", False):
        names = list_catalog_names(args.project)

        total = 0
        for name in names:
            changed, path = repair_catalog_jinja_noise(
                args.project,
                name,
            )
            total += changed
            print(
                f"{name}: {changed} Eintrag/Einträge repariert"
                f"  [{path}]"
            )

        print()
        print(
            f"✓ Reparatur abgeschlossen. Insgesamt {total} "
            f"Eintrag/Einträge geändert."
        )
        return

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )

    changed, path = repair_catalog_jinja_noise(
        args.project,
        catalog_name,
    )

    print()
    print(f"Katalog: {catalog_name}")
    print(f"Datei:   {path}")

    if changed:
        print(
            f"✓ {changed} Eintrag/Einträge wurden von "
            "rohen Scan-/Jinja-Daten bereinigt."
        )
    else:
        print("✓ Keine problematischen Scan-/Jinja-Daten gefunden.")
