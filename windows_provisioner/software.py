# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Office-, WinGet-, Store- und Softwareaufnahme-Workflows."""

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

def looks_like_office_candidate(path: Path) -> bool:
    name = path.name.lower()

    obvious_names = {
        "officesetup.exe",
        "office setup.exe",
    }

    if name in obvious_names:
        return True

    # Nicht blind im gesamten Pfad nach Teilzeichenfolgen suchen:
    # "mavi-provisioner" enthält beispielsweise selbst "visio".
    marker_pattern = re.compile(
        r"(?<![a-z0-9])(?:"
        r"microsoft[ _-]+office|"
        r"office[ _-]*365|"
        r"microsoft[ _-]*365|"
        r"m365|"
        r"project|"
        r"visio|"
        r"office[ _-]*deployment|"
        r"officedeployment|"
        r"odt"
        r")(?![a-z0-9])"
    )

    return any(marker_pattern.search(part.lower()) for part in path.parts)


def friendly_product_from_id(product_id: str) -> dict[str, Any] | None:
    from .catalogs import OFFICE_PRODUCTS

    for profile in OFFICE_PRODUCTS.values():
        if profile["product_id"].lower() == product_id.lower():
            return dict(profile)
    return None


def parse_office_xml(path: Path) -> dict[str, Any]:
    from .environment import die

    result: dict[str, Any] = {
        "product_id": "",
        "architecture": "",
        "channel": "",
        "languages": [],
    }

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        die(f"XML konnte nicht gelesen werden: {path}\n{exc}")

    add = root.find(".//Add")
    if add is not None:
        result["architecture"] = add.attrib.get("OfficeClientEdition", "")
        result["channel"] = add.attrib.get("Channel", "")

        product = add.find("Product")
        if product is not None:
            result["product_id"] = product.attrib.get("ID", "")
            result["languages"] = [
                lang.attrib.get("ID", "")
                for lang in product.findall("Language")
                if lang.attrib.get("ID")
            ]

    return result


def choose_office_profile() -> dict[str, Any]:
    from .catalogs import (
        OFFICE_PRODUCTS,
        prompt,
        select_from_list,
    )
    from .environment import die

    print()
    print("Microsoft-Produkt auswählen")
    print("===========================")
    print("  1) Planner / Project")
    print("  2) Microsoft 365 / Office 365")
    print("  3) Office 2024")
    print("  4) Visio")
    print("  5) Product-ID manuell eingeben")
    print()

    category = input("> ").strip()

    groups = {
        "1": [
            "project_plan3",
            "project_plan5",
            "project_pro_2024_retail",
            "project_std_2024_retail",
            "project_pro_2024_volume",
            "project_std_2024_volume",
        ],
        "2": [
            "m365_apps_enterprise",
            "m365_apps_business",
            "m365_business_standard",
            "m365_business_premium",
            "m365_e3_e5",
        ],
        "3": [
            "office_home_business_2024",
            "office_professional_2024",
            "office_proplus_2024_retail",
            "office_ltsc_proplus_2024",
            "office_ltsc_standard_2024",
        ],
        "4": [
            "visio_subscription",
            "visio_pro_2024_retail",
            "visio_std_2024_retail",
            "visio_pro_2024_volume",
            "visio_std_2024_volume",
        ],
    }

    if category == "5":
        product_id = prompt("ODT Product-ID")
        family_choice = select_from_list(
            "Produktart",
            [
                ("office", "Office"),
                ("project", "Project"),
                ("visio", "Visio"),
            ],
            default_key="office",
        )

        channel = prompt(
            "Optionaler Channel (Enter = keiner / vorhandenen Office-Kanal übernehmen)",
            "",
        )

        return {
            "name": product_id,
            "product_id": product_id,
            "family": family_choice,
            "channel": channel or None,
        }

    if category not in groups:
        die("Ungültige Microsoft-Produktkategorie.")

    keys = groups[category]
    selected = select_from_list(
        "Produkt/Lizenz auswählen",
        [
            (key, OFFICE_PRODUCTS[key]["name"])
            for key in keys
        ],
        allow_name=True,
    )

    return dict(OFFICE_PRODUCTS[selected])


def choose_office_architecture() -> str:
    from .catalogs import select_from_list

    return select_from_list(
        "Office-Architektur",
        [
            ("64", "64 Bit"),
            ("32", "32 Bit"),
        ],
        default_key="64",
    )


def choose_office_language() -> str:
    from .catalogs import (
        prompt,
        select_from_list,
    )

    choice = select_from_list(
        "Office-Sprache",
        [
            ("de-de", "Deutsch (de-de)"),
            ("MatchOS", "Windows-Sprache übernehmen (MatchOS)"),
            ("custom", "Andere Sprache eingeben"),
        ],
        default_key="de-de",
    )

    if choice == "custom":
        return prompt("Language ID, z. B. en-us")

    return choice


def office_default_creates_path(family: str, architecture: str) -> str:
    root = (
        r"C:\Program Files\Microsoft Office\root\Office16"
        if architecture == "64"
        else r"C:\Program Files (x86)\Microsoft Office\root\Office16"
    )

    exe = {
        "project": "WINPROJ.EXE",
        "visio": "VISIO.EXE",
        "office": "WINWORD.EXE",
    }.get(family, "WINWORD.EXE")

    return root + "\\" + exe


def generate_office_xml(
    path: Path,
    *,
    product_id: str,
    architecture: str,
    language: str,
    channel: str | None,
    remove_msi: bool,
) -> None:
    configuration = ET.Element("Configuration")

    add_attrs = {
        "OfficeClientEdition": architecture,
    }
    if channel:
        add_attrs["Channel"] = channel

    add = ET.SubElement(configuration, "Add", add_attrs)
    product = ET.SubElement(add, "Product", {"ID": product_id})
    ET.SubElement(product, "Language", {"ID": language})

    if remove_msi:
        ET.SubElement(configuration, "RemoveMSI")

    ET.SubElement(
        configuration,
        "Display",
        {
            "Level": "None",
            "AcceptEULA": "TRUE",
        },
    )

    try:
        ET.indent(configuration, space="  ")
    except AttributeError:
        pass

    tree = ET.ElementTree(configuration)
    path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(
        path,
        encoding="utf-8",
        xml_declaration=True,
    )


def choose_xml_file(
    config: dict[str, Any],
    *,
    preferred_dir: Path | None = None,
) -> Path:
    from .catalogs import (
        prompt,
        select_from_list,
    )
    from .environment import (
        _mavi_drive_label,
        _mavi_source_label,
        _mavi_source_root,
        browse_files,
        die,
        normalize_path,
    )

    local_root = _mavi_source_root(config)
    drive = _mavi_drive_label(
        (config.get("software_source", {}) or {}).get("drive")
    )

    # XML im selben Ordner zuerst anbieten.
    if preferred_dir and preferred_dir.exists():
        same_dir_xml = sorted(
            preferred_dir.glob("*.xml"),
            key=lambda p: p.name.lower(),
        )
        if same_dir_xml:
            print()
            print("XML-Dateien im gleichen Ordner gefunden:")
            selected = select_from_list(
                "XML auswählen",
                [
                    (str(path), path.name)
                    for path in same_dir_xml
                ],
            )
            return Path(selected)

    print()
    print("XML auswählen")
    print(f"  1) Durch {drive or _mavi_source_label(config)} browsen (Standard)")
    print("  2) Pfad eintippen")
    print()

    mode = input("> [1] ").strip() or "1"

    if mode == "1":
        if local_root is None:
            die(
                "Die Softwarequelle ist noch nicht eingerichtet. "
                "Bitte zuerst Mavi-Setup ausführen."
            )
        return browse_files(
            local_root,
            drive,
            extensions={".xml"},
            title="Office XML auswählen",
            start_dir=preferred_dir if preferred_dir else None,
        )

    if mode == "2":
        raw = prompt("XML-Pfad (Windows-Laufwerk, UNC oder Linux)")
        return normalize_path(raw, config)

    die("Ungültige XML-Auswahl.")


def choose_odt_setup(
    selected_installer: Path | None,
    config: dict[str, Any],
) -> Path:
    """
    Wählt die echte Office Deployment Tool setup.exe aus.

    OfficeSetup.exe aus dem Microsoft-Portal ist NICHT die ODT setup.exe
    und darf nicht für /configure verwendet werden.
    """
    from .catalogs import (
        prompt,
        yes_no,
    )
    from .environment import (
        _mavi_drive_label,
        _mavi_source_label,
        _mavi_source_root,
        browse_files,
        die,
        normalize_path,
    )

    print()
    print("Office Deployment Tool")
    print("======================")
    print("Für /configure wird die echte ODT-Datei 'setup.exe' benötigt.")
    print("Eine 'OfficeSetup.exe' aus dem Microsoft-Portal ist dafür NICHT geeignet.")

    if selected_installer is not None:
        print(f"Vorher ausgewählte EXE: {selected_installer}")

        if selected_installer.name.lower() == "setup.exe":
            if yes_no(
                "Ist diese setup.exe wirklich das Microsoft Office Deployment Tool?",
                True,
            ):
                return selected_installer
        elif selected_installer.name.lower() == "officesetup.exe":
            print()
            print("! OfficeSetup.exe erkannt.")
            print("  Diese Datei wird NICHT als ODT verwendet.")
            print("  Bitte jetzt die echte ODT setup.exe auswählen.")
        else:
            print()
            print(
                "! Die ausgewählte Datei heißt nicht 'setup.exe' und wird "
                "nicht als ODT akzeptiert."
            )

    local_root = _mavi_source_root(config)
    drive = _mavi_drive_label(
        (config.get("software_source", {}) or {}).get("drive")
    )

    while True:
        print()
        print("ODT setup.exe auswählen")
        print(f"  1) Durch {drive or _mavi_source_label(config)} browsen (Standard)")
        print("  2) Pfad eintippen")
        print()

        mode = input("> [1] ").strip() or "1"

        start_dir = (
            selected_installer.parent
            if selected_installer is not None
            else None
        )

        if mode == "1":
            if local_root is None:
                die(
                    "Die Softwarequelle ist noch nicht eingerichtet. "
                    "Bitte zuerst Mavi-Setup ausführen."
                )
            candidate = browse_files(
                local_root,
                drive,
                extensions={".exe"},
                title="ODT setup.exe auswählen",
                start_dir=start_dir,
            )
        elif mode == "2":
            raw = prompt("Pfad zur ODT setup.exe")
            candidate = normalize_path(raw, config)
        else:
            print("Ungültige Auswahl.")
            continue

        if not candidate.exists():
            print(f"ODT-Datei nicht gefunden: {candidate}")
            continue

        if not candidate.is_file() or candidate.suffix.lower() != ".exe":
            print("Bitte eine EXE-Datei auswählen.")
            continue

        if candidate.name.lower() == "officesetup.exe":
            print()
            print("! Das ist OfficeSetup.exe aus dem Portal, nicht die ODT setup.exe.")
            continue

        if candidate.name.lower() != "setup.exe":
            print()
            print(
                "! Für den ODT-Modus akzeptiere ich bewusst nur eine Datei "
                "mit dem Namen 'setup.exe'."
            )
            print(
                "  So landet nicht versehentlich wieder OfficeSetup.exe "
                "im /configure-Workflow."
            )
            continue

        if yes_no(
            "Diese setup.exe als Microsoft Office Deployment Tool verwenden?",
            True,
        ):
            return candidate



def cmd_add_office_odt(
    args: argparse.Namespace,
    selected_installer: Path | None,
    catalog_name: str,
    config: dict[str, Any],
) -> None:
    from .catalogs import (
        get_catalog,
        prompt,
        save_catalog,
        slugify,
        validate_software_key,
        yes_no,
    )
    from .environment import (
        die,
        normalize_path,
        project_paths,
        sha256_file,
    )
    from .reports import redact_sensitive_text

    print()
    print("MICROSOFT-PRODUKT")
    print("=================")
    print(f"Zielkatalog: {catalog_name}")
    print()
    print("Hinweis: Für die Installation wird später die echte ODT 'setup.exe'")
    print("verwendet, NICHT die Portal-Datei 'OfficeSetup.exe'.")
    print()

    # WICHTIG: Das Produkt wird bewusst vom Benutzer gewählt.
    # Eine generische setup.exe kann nicht zuverlässig sagen,
    # welche Microsoft-Lizenz bzw. welches Produkt bereitgestellt werden soll.
    profile = choose_office_profile()

    print()
    print("Gewählt:")
    print(f"  Produkt:     {profile['name']}")
    print(f"  Product ID:  {profile['product_id']}")

    use_existing_xml = yes_no(
        "Gibt es bereits eine passende .xml-Konfigurationsdatei?",
        False,
    )

    architecture = "64"
    language = "de-de"
    channel = profile.get("channel")
    xml_path: Path

    if use_existing_xml:
        preferred_dir = (
            selected_installer.parent
            if selected_installer is not None
            else None
        )

        xml_path = choose_xml_file(
            config,
            preferred_dir=preferred_dir,
        )

        if not xml_path.exists():
            die(f"XML-Datei nicht gefunden: {xml_path}")

        parsed = parse_office_xml(xml_path)
        xml_product_id = parsed.get("product_id", "")
        architecture = parsed.get("architecture", "") or "64"
        xml_channel = parsed.get("channel", "") or None
        languages = parsed.get("languages", [])
        language = languages[0] if languages else "unbekannt"

        print()
        print("Vorhandene XML erkannt:")
        print(f"  Product ID:   {xml_product_id or '(nicht erkannt)'}")
        print(f"  Architektur:  {architecture}")
        print(f"  Channel:      {xml_channel or '(nicht gesetzt)'}")
        print(
            f"  Sprache:      "
            f"{', '.join(languages) if languages else '(nicht erkannt)'}"
        )

        if (
            xml_product_id
            and xml_product_id.lower()
            != str(profile["product_id"]).lower()
        ):
            print()
            print("! ACHTUNG: Die XML passt nicht zur vorher gewählten Product-ID.")
            print(f"  Gewählt: {profile['product_id']}")
            print(f"  XML:     {xml_product_id}")

            if yes_no(
                "Die Product-ID aus der XML übernehmen?",
                False,
            ):
                detected = friendly_product_from_id(xml_product_id)
                if detected:
                    profile = detected
                else:
                    profile = {
                        "name": xml_product_id,
                        "product_id": xml_product_id,
                        "family": profile.get("family", "office"),
                        "channel": xml_channel,
                    }
            else:
                print("Vorhandene XML wird nicht verwendet.")
                use_existing_xml = False

        if use_existing_xml:
            channel = xml_channel or channel

            if not yes_no(
                "Diese XML unverändert mit /configure verwenden?",
                True,
            ):
                use_existing_xml = False

    if not use_existing_xml:
        print()
        print("Keine vorhandene XML wird verwendet.")
        print("Das Tool erzeugt eine neue ODT-Konfiguration.")

        architecture = choose_office_architecture()
        language = choose_office_language()
        channel = profile.get("channel")

        print()
        print("Neue ODT-Konfiguration:")
        print(f"  Produkt:       {profile['name']}")
        print(f"  Product ID:    {profile['product_id']}")
        print(f"  Architektur:   {architecture} Bit")
        print(f"  Sprache:       {language}")
        print(
            f"  Channel:       "
            f"{channel or '(nicht gesetzt / vorhandenen Office-Kanal verwenden)'}"
        )

        remove_msi = yes_no(
            "Alte MSI-basierte Office-Versionen per <RemoveMSI /> entfernen?",
            False,
        )
    else:
        remove_msi = False

    default_name = profile.get("name", "Microsoft Office")
    name = args.name or prompt("Anzeigename", default_name)
    key = validate_software_key(
        args.key or prompt("Katalog-Schlüssel", slugify(name))
    )

    if not use_existing_xml:
        xml_dir = (
            project_paths(args.project)["office_configs_dir"]
            / catalog_name
        )
        xml_path = xml_dir / f"{key}.xml"

        generate_office_xml(
            xml_path,
            product_id=str(profile["product_id"]),
            architecture=architecture,
            language=language,
            channel=channel,
            remove_msi=remove_msi,
        )

        print()
        print(f"✓ XML automatisch erzeugt: {xml_path}")

    # Erst nachdem Produkt und XML feststehen, wird ODT gewählt.
    odt_hint = selected_installer

    if getattr(args, "odt", None):
        odt_hint = normalize_path(args.odt, config)
        if not odt_hint.exists():
            die(f"Angegebene ODT-Datei existiert nicht: {odt_hint}")

    odt_setup = choose_odt_setup(
        odt_hint,
        config,
    )

    family = str(profile.get("family", "office"))
    default_creates = office_default_creates_path(
        family,
        architecture,
    )

    creates_path = prompt(
        "Erkennungspfad nach Installation",
        default_creates,
    )

    app = {
        "name": name,
        "installer": str(odt_setup),
        "type": "office_odt",
        "context": "machine",
        "installer_engine": "Microsoft Office Deployment Tool",
        "arguments": "/configure",
        "install_timeout_minutes": 30,
        "configuration_file": str(xml_path),
        "sha256": sha256_file(odt_setup),
        "creates_path": creates_path,
        "office": {
            "product_id": profile.get("product_id", "unbekannt"),
            "profile": profile.get("name", name),
            "family": family,
            "architecture": architecture,
            "language": language,
            "channel": channel or "",
            "xml_source": "existing" if use_existing_xml else "generated",
        },
        "analysis": {
            "confidence": "hoch",
            "admin_requirement": "ja",
            "reasons": [
                "Microsoft-Produkt wurde bewusst über den Microsoft-Assistenten gewählt.",
                "Installation erfolgt mit dem Office Deployment Tool und /configure.",
                f"Product ID: {profile.get('product_id', 'unbekannt')}",
            ],
        },
    }

    app = sanitize_catalog_data(app)

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]

    if key in sw and not yes_no(
        f"'{key}' existiert bereits in '{catalog_name}'. Überschreiben?",
        False,
    ):
        print("Abgebrochen.")
        return

    print()
    print("Wird gespeichert:")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {key: app},
                allow_unicode=True,
                sort_keys=False,
            ).rstrip()
        )
    )

    if not yes_no("Zum Katalog hinzufügen?", True):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(args.project, catalog, catalog_name)

    print()
    print(
        f"✓ '{key}' wurde als Microsoft-ODT-Paket "
        f"zum Katalog '{catalog_name}' hinzugefügt."
    )
    print(f"  Produkt: {profile.get('name', name)}")
    print(f"  XML:     {xml_path}")
    print(f"  ODT:     {odt_setup}")


def cmd_microsoft_add(args: argparse.Namespace) -> None:
    """
    Expliziter Microsoft-Wizard.
    Kein Raten anhand eines setup.exe-Dateinamens nötig.
    """
    from .catalogs import choose_catalog_interactive
    from .environment import (
        ensure_initialized,
        get_config,
        normalize_path,
    )

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    catalog_name = choose_catalog_interactive(
        args.project,
        getattr(args, "catalog", None),
        purpose="für das Microsoft-Produkt verwenden",
        ask_other=True,
    )

    selected_installer: Path | None = None
    if getattr(args, "odt", None):
        selected_installer = normalize_path(args.odt, config)

    cmd_add_office_odt(
        args,
        selected_installer,
        catalog_name,
        config,
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





WINGET_PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{1,200}$")
WINGET_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
WINGET_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+~-]{0,100}$")


def _is_msstore_app(app: dict[str, Any]) -> bool:
    """True für Mavi-WinGet-Einträge aus dem Microsoft Store (msstore)."""
    return (
        str(app.get("type", "")).lower() == "winget"
        and str(app.get("winget_source", "winget")).strip().lower() == "msstore"
    )


def _software_type_label(app: dict[str, Any]) -> str:
    """Menschenlesbarer Typ; Store bleibt intern kompatibel type=winget."""
    if _is_msstore_app(app):
        return "STORE"
    return str(app.get("type", "?") or "?").upper()


def _winget_validate_identifier(value: str, *, label: str = "Paket-ID") -> str:
    from .environment import die

    value = str(value or "").strip()
    if not WINGET_PACKAGE_ID_RE.fullmatch(value):
        die(
            f"Ungültige WinGet-{label}: {value!r}. "
            "Erlaubt sind Buchstaben, Zahlen sowie . _ + - ohne Leerzeichen."
        )
    return value


def _winget_validate_source(value: str) -> str:
    from .environment import die

    value = str(value or "winget").strip() or "winget"
    if not WINGET_SOURCE_RE.fullmatch(value):
        die(f"Ungültige WinGet-Quelle: {value!r}")
    return value


def _winget_validate_version(value: str) -> str:
    from .environment import die

    value = str(value or "").strip()
    if value and not WINGET_VERSION_RE.fullmatch(value):
        die(f"Ungültige WinGet-Version: {value!r}")
    return value


def _parse_winget_search_table(output: str) -> list[dict[str, str]]:
    """
    WinGet search liefert eine menschenlesbare Tabelle. Neuere Store-Ausgaben
    können die Spalten sehr kompakt mit nur EINEM Leerzeichen ausgeben, z. B.::

        Name      ID           Version
        ------------------------------
        OpenCloud 9PBX43HCMLDQ Unknown

    Daher wird zuerst anhand der Header-Spaltenpositionen (ID/Version) geparst.
    Falls das nicht möglich ist, greift ein defensiver Token-Fallback. "Unknown"
    ist bei msstore eine gültige Versionsanzeige und darf den Treffer nicht
    verwerfen.
    """
    from .execution import strip_ansi

    lines = [strip_ansi(line.rstrip("\r")) for line in str(output or "").splitlines()]
    separator_index = None

    for index, line in enumerate(lines):
        compact = line.strip()
        if len(compact) >= 8 and set(compact) <= {"-", " "} and "-" in compact:
            separator_index = index
            break

    if separator_index is None:
        return []

    header = ""
    for index in range(separator_index - 1, -1, -1):
        if lines[index].strip():
            header = lines[index]
            break

    # ID und Version sind in der WinGet-Ausgabe sprachstabil genug, um ihre
    # Startpositionen als primäre Spaltengrenzen zu verwenden. Zusätzliche
    # Spalten rechts (Match/Source) werden nur best-effort übernommen.
    id_match = re.search(r"(?<!\S)ID(?!\S)", header, flags=re.IGNORECASE)
    version_match = re.search(r"(?<!\S)Version(?!\S)", header, flags=re.IGNORECASE)
    header_tokens = list(re.finditer(r"\S+", header))
    trailing_starts: list[int] = []
    if version_match:
        trailing_starts = [m.start() for m in header_tokens if m.start() > version_match.start()]

    def add_row(rows: list[dict[str, str]], *, name: str, package_id: str,
                version: str, source: str = "") -> None:
        name = name.strip()
        package_id = package_id.strip()
        version = version.strip()
        source = source.strip()
        if not package_id or " " in package_id:
            return
        if not WINGET_PACKAGE_ID_RE.fullmatch(package_id):
            return
        rows.append({
            "name": name or package_id,
            "id": package_id,
            "version": version or "Unknown",
            "source": source,
        })

    rows: list[dict[str, str]] = []
    for raw in lines[separator_index + 1:]:
        if not raw.strip():
            if rows:
                break
            continue

        parsed = False
        if id_match and version_match and id_match.start() < version_match.start():
            id_start = id_match.start()
            version_start = version_match.start()
            next_start = trailing_starts[0] if trailing_starts else None

            name = raw[:id_start].strip()
            package_id = raw[id_start:version_start].strip()
            if next_start is None:
                version = raw[version_start:].strip()
                source = ""
            else:
                version = raw[version_start:next_start].strip()
                tail = raw[next_start:].strip()
                source = tail.split()[-1] if tail else ""

            before = len(rows)
            add_row(rows, name=name, package_id=package_id, version=version, source=source)
            parsed = len(rows) > before

        if parsed:
            continue

        # Fallback für ungewöhnliche/lokalisierte Header. Wir suchen von rechts
        # nach einem Versions-Token und nehmen das direkt davorstehende Token als
        # Paket-ID. So funktioniert auch "OpenCloud 9PBX43HCMLDQ Unknown".
        tokens = raw.strip().split()
        if len(tokens) < 3:
            continue

        version_index = None
        for idx in range(len(tokens) - 1, 0, -1):
            token = tokens[idx]
            folded = token.casefold()
            if (
                folded in {"unknown", "unbekannt", "latest", "aktuell"}
                or re.fullmatch(r"[vV]?\d[0-9A-Za-z_.+~<>:=/-]*", token)
            ):
                if idx >= 1 and WINGET_PACKAGE_ID_RE.fullmatch(tokens[idx - 1]):
                    version_index = idx
                    break

        if version_index is None:
            continue

        package_id = tokens[version_index - 1]
        name = " ".join(tokens[:version_index - 1])
        version = tokens[version_index]
        source = tokens[-1] if version_index < len(tokens) - 1 and tokens[-1].casefold() in {"winget", "msstore"} else ""
        add_row(rows, name=name, package_id=package_id, version=version, source=source)

    unique: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        folded = row["id"].casefold()
        if folded in seen:
            continue
        seen.add(folded)
        unique.append(row)
    return unique

def _run_winget_search_remote(
    *,
    project: Path,
    host: str,
    query: str,
    source: str,
    interactive_user: bool = False,
) -> dict[str, Any]:
    """
    WinGet-Suche auf einem vorhandenen Windows-Referenzhost ausführen.

    Für Microsoft Store (msstore) wird die Suche bewusst über einen temporären
    Scheduled Task mit LogonType=Interactive/RunLevel=Limited im aktuell
    angemeldeten Benutzer ausgeführt. Damit werden WinGet/App-Installer und die
    Store-Quelle aus genau demselben USER-Kontext verwendet wie später bei der
    Installation. Normale WinGet-Suchen können weiterhin direkt im
    Provisioning-Kontext laufen.
    """
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )
    from .execution import (
        create_temporary_vault_password_file,
        strip_ansi,
    )

    powershell = r"""
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Query,
    [Parameter(Mandatory=$true)][string]$Source,
    [bool]$UseInteractiveUser = $false
)
$ErrorActionPreference = 'Stop'

function Invoke-MaviWingetSearch {
    param(
        [Parameter(Mandatory=$true)][string]$SearchQuery,
        [Parameter(Mandatory=$true)][string]$SearchSource
    )

    function Resolve-MaviWinget {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return [string]$cmd.Source }

        $aliasPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
        if (Test-Path -LiteralPath $aliasPath) { return $aliasPath }

        $pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending |
            Select-Object -First 1
        if ($pkg -and $pkg.InstallLocation) {
            $candidate = Join-Path $pkg.InstallLocation 'winget.exe'
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }

        throw 'winget.exe wurde für diesen Windows-Benutzer nicht gefunden. App Installer/WinGet prüfen.'
    }

    $winget = Resolve-MaviWinget
    $wingetVersion = (& $winget --version 2>&1 | Out-String).Trim()
    $wingetArgs = @(
        'search', '--query', $SearchQuery,
        '--source', $SearchSource,
        '--count', '25',
        '--accept-source-agreements',
        '--disable-interactivity',
        '--nowarn'
    )
    $output = (& $winget @wingetArgs 2>&1 | Out-String)
    $rc = [int64]$LASTEXITCODE

    return [ordered]@{
        Rc = $rc
        Output = $output
        WingetPath = $winget
        WingetVersion = $wingetVersion
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

if (-not $UseInteractiveUser) {
    $payload = Invoke-MaviWingetSearch -SearchQuery $Query -SearchSource $Source
}
else {
    $currentUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $currentUser) {
        throw 'Kein interaktiv angemeldeter Benutzer gefunden. Microsoft-Store-Suche benötigt eine angemeldete Benutzersitzung.'
    }

    $account = New-Object Security.Principal.NTAccount($currentUser)
    $sid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
    $profilePath = [Environment]::ExpandEnvironmentVariables([string]$profilePath)
    $userTemp = Join-Path $profilePath 'AppData\Local\Temp'
    if (-not (Test-Path -LiteralPath $userTemp)) {
        throw "TEMP-Verzeichnis des angemeldeten Benutzers nicht gefunden: $userTemp"
    }

    $guid = [Guid]::NewGuid().ToString('N')
    $taskName = "Mavi_WinGet_Search_$guid"
    $resultFile = Join-Path $userTemp "Mavi-WinGet-Search-$guid.json"

    $queryB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query))
    $sourceB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Source))
    $resultB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resultFile))

    $childScript = @"
`$ErrorActionPreference = 'Stop'
function Resolve-MaviWinget {
    `$cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (`$cmd -and `$cmd.Source) { return [string]`$cmd.Source }
    `$aliasPath = Join-Path `$env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (Test-Path -LiteralPath `$aliasPath) { return `$aliasPath }
    `$pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if (`$pkg -and `$pkg.InstallLocation) {
        `$candidate = Join-Path `$pkg.InstallLocation 'winget.exe'
        if (Test-Path -LiteralPath `$candidate) { return `$candidate }
    }
    throw 'winget.exe wurde fuer den angemeldeten Benutzer nicht gefunden. App Installer/WinGet pruefen.'
}
`$Query = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$queryB64'))
`$Source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$sourceB64'))
`$ResultFile = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$resultB64'))
try {
    `$winget = Resolve-MaviWinget
    `$wingetVersion = (& `$winget --version 2>&1 | Out-String).Trim()
    `$args = @('search','--query',`$Query,'--source',`$Source,'--count','25','--accept-source-agreements','--disable-interactivity','--nowarn')
    `$output = (& `$winget @args 2>&1 | Out-String)
    `$rc = [int64]`$LASTEXITCODE
    `$payload = [ordered]@{
        Rc = `$rc
        Output = `$output
        WingetPath = `$winget
        WingetVersion = `$wingetVersion
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}
catch {
    `$payload = [ordered]@{
        Rc = -1
        Output = (`$_ | Out-String)
        WingetPath = ''
        WingetVersion = ''
        ExecutionUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Error = `$_.Exception.Message
    }
}
`$payload | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath `$ResultFile -Encoding UTF8 -Force
"@

    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    )
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    try {
        $before = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(75)
        $started = $false
        do {
            Start-Sleep -Milliseconds 500
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
            if ($info.LastRunTime -gt $before) { $started = $true }
            if (Test-Path -LiteralPath $resultFile) { break }
            if ($started -and $task.State -ne 'Running') { break }
        } while ((Get-Date) -lt $deadline)

        if (-not $started) {
            throw "Microsoft-Store-Suchtask fuer '$currentUser' wurde nicht gestartet."
        }
        if (-not (Test-Path -LiteralPath $resultFile)) {
            $last = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue).LastTaskResult
            throw "Microsoft-Store-Suche im Benutzerkontext lieferte keine Ergebnisdatei. Task-Code=$last"
        }

        $payload = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        if (-not $payload.ExecutionUser) {
            $payload | Add-Member -NotePropertyName ExecutionUser -NotePropertyValue $currentUser -Force
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $resultFile -Force -ErrorAction SilentlyContinue
    }
}

$json = $payload | ConvertTo-Json -Compress -Depth 5
$marker = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
$Ansible.Result = @{ Marker = $marker }
$Ansible.Changed = $false
"""

    play = [{
        "name": "Mavi WinGet Suche",
        "hosts": "windows",
        "gather_facts": False,
        "tasks": [
            {
                "name": "WinGet Paket suchen",
                "ansible.windows.win_powershell": {
                    "error_action": "stop",
                    "script": powershell,
                    "parameters": {
                        "Query": query,
                        "Source": source,
                        "UseInteractiveUser": bool(interactive_user),
                    },
                },
                "register": "mavi_winget_search",
            },
            {
                "name": "Mavi WinGet Suchmarker",
                "ansible.builtin.debug": {
                    "msg": "Mavi_WINGET_SEARCH_B64={{ mavi_winget_search.result.Marker }}"
                },
            },
        ],
    }]

    fd, raw_playbook = tempfile.mkstemp(prefix=".mavi-winget-search-", suffix=".yml")
    os.close(fd)
    playbook_path = Path(raw_playbook)
    vault_password_file: Path | None = None

    try:
        atomic_write_yaml(playbook_path, play)
        vault_password = getpass.getpass("Vault password: ")
        vault_password_file = create_temporary_vault_password_file(vault_password)
        cmd = [
            "ansible-playbook", "-i", str(project_paths(project)["inventory"]),
            str(playbook_path), "--limit", host,
            "--vault-password-file", str(vault_password_file),
        ]
        result = subprocess.run(
            cmd, cwd=str(project), capture_output=True, text=True, timeout=110,
        )
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(r"Mavi_WINGET_SEARCH_B64=([A-Za-z0-9+/=]+)", combined)
        if result.returncode != 0 or not match:
            lines = [line.strip() for line in strip_ansi(combined).splitlines() if line.strip()]
            detail = " | ".join(lines[-10:])
            raise RuntimeError(detail or f"Ansible-Code {result.returncode}")

        decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
        payload = json.loads(decoded)
        if not isinstance(payload, dict):
            raise RuntimeError("WinGet-Suche lieferte unerwartete Daten.")
        return payload
    finally:
        playbook_path.unlink(missing_ok=True)
        if vault_password_file is not None:
            vault_password_file.unlink(missing_ok=True)

def cmd_winget_add(args: argparse.Namespace) -> None:
    from .catalogs import (
        backup_parameter_profile,
        choose_catalog_interactive,
        choose_host_interactive,
        get_catalog,
        prompt,
        prompt_choice,
        save_catalog,
        select_from_list,
        slugify,
        validate_software_key,
        yes_no,
    )
    from .environment import (
        die,
        ensure_initialized,
    )
    from .reports import redact_sensitive_text
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)

    source = _winget_validate_source(getattr(args, "source", None) or "winget")
    is_store = source.lower() == "msstore"
    package_id = str(getattr(args, "package_id", None) or "").strip()
    selected_name = ""
    selected_version = ""

    if not package_id:
        host = getattr(args, "host", None) or choose_host_interactive(args.project)
        query = str(getattr(args, "query", None) or "").strip()
        if not query:
            query = prompt("WinGet-Suche, z. B. vlc")
        if not query:
            die("Kein WinGet-Suchbegriff angegeben.")

        print()
        print("Mavi MICROSOFT STORE-SUCHE" if is_store else "Mavi WINGET-SUCHE")
        print("==========================" if is_store else "=================")
        print(f"Referenz-PC: {host}")
        print(f"Suche:       {query}")
        print(f"Quelle:      {source}")
        print()

        try:
            payload = _run_winget_search_remote(
                project=args.project, host=host, query=query, source=source,
                interactive_user=is_store,
            )
        except Exception as exc:
            print(f"! WinGet-Suche fehlgeschlagen: {exc}")
            print("  Du kannst die exakte Paket-ID trotzdem manuell eingeben.")
            package_id = prompt(
                "Exakte Microsoft-Store-ID, z. B. XP9KHM4BK9FZ7Q"
                if is_store else
                "Exakte WinGet-Paket-ID, z. B. VideoLAN.VLC"
            )
        else:
            rc = int(payload.get("Rc", 1) or 0)
            output = str(payload.get("Output") or "")
            print(
                f"WinGet:      {payload.get('WingetVersion', '?')} "
                f"[{payload.get('WingetPath', '?')}]"
            )
            if payload.get("ExecutionUser"):
                print(f"Benutzer:    {payload.get('ExecutionUser')}")
            rows = _parse_winget_search_table(output)

            if rc != 0 or not rows:
                print()
                print("! Keine automatisch auswählbaren Treffer gefunden.")
                if output.strip():
                    print("WinGet-Ausgabe:")
                    print(output.strip())
                package_id = prompt(
                    "Exakte Microsoft-Store-ID" if is_store else "Exakte WinGet-Paket-ID"
                )
            else:
                print()
                print("Gefundene Microsoft-Store-Apps:" if is_store else "Gefundene Pakete:")
                items: list[tuple[str, str]] = []
                row_by_key: dict[str, dict[str, str]] = {}
                for index, row in enumerate(rows, 1):
                    k = str(index)
                    shown_version = row.get("version") or "?"
                    if is_store and shown_version.casefold() in {"unknown", "unbekannt", "?"}:
                        shown_version = "Store-aktuell"
                    label = f"{row['name']} | {row['id']} | {shown_version}"
                    items.append((k, label))
                    row_by_key[k] = row
                selected = select_from_list(
                    "Microsoft-Store-App auswählen" if is_store else "WinGet-Paket auswählen",
                    items, allow_name=False,
                )
                row = row_by_key[selected]
                package_id = row["id"]
                selected_name = row["name"]
                selected_version = row.get("version", "")

    package_id = _winget_validate_identifier(package_id)
    version = _winget_validate_version(getattr(args, "version", None) or "")

    scope = str(getattr(args, "scope", None) or "").strip().lower()
    if is_store:
        if scope and scope != "user":
            die(
                "Microsoft-Store-Apps werden in Mavi bewusst im USER-Kontext installiert. "
                "Für echtes geräteweites AppX/MSIX-Provisioning wäre ein separater Provisioning-Weg nötig."
            )
        scope = "user"
        version = ""
        if sys.stdin.isatty():
            print()
            print("Installationsbereich: USER / aktuell angemeldeter Benutzer")
            print("Mavi erzwingt für Microsoft-Store-Apps keinen SYSTEM/MACHINE-Scope.")
    else:
        if not scope:
            picked = prompt_choice(
                "WinGet-Installationsbereich:",
                [
                    ("1", "MACHINE / für den ganzen PC"),
                    ("2", "USER / für den aktuell angemeldeten Benutzer"),
                ],
                "1",
            )
            scope = "machine" if picked == "1" else "user"
        if scope not in {"machine", "user"}:
            die("WinGet-Scope muss 'machine' oder 'user' sein.")

        if not version and sys.stdin.isatty():
            print()
            if selected_version:
                print(f"Aktuell gefundene Version: {selected_version}")
            version = _winget_validate_version(
                prompt("Feste Version (Enter = immer aktuelle Version)", "")
            )

    catalog_name = choose_catalog_interactive(
        args.project, getattr(args, "catalog", None), purpose="verwenden", ask_other=True,
    )
    print(f"Zielkatalog: {catalog_name}")

    default_name = selected_name or package_id
    name = getattr(args, "name", None) or prompt("Anzeigename", default_name)
    key = validate_software_key(
        getattr(args, "key", None) or prompt("Katalog-Schlüssel", slugify(name))
    )
    context = "machine" if scope == "machine" else "user_interactive"

    install_timeout_minutes = 30
    if scope == "user":
        while True:
            raw_timeout = prompt("Timeout für USER-WinGet in Minuten", "30")
            try:
                install_timeout_minutes = int(raw_timeout)
            except ValueError:
                print("Bitte eine ganze Zahl in Minuten eingeben.")
                continue
            if install_timeout_minutes < 1:
                print("Timeout muss mindestens 1 Minute sein.")
                continue
            break

    app: dict[str, Any] = {
        "name": name,
        "installer": f"msstore://{package_id}" if is_store else f"winget://{package_id}",
        "type": "winget",
        "context": context,
        "winget_id": package_id,
        "winget_source": source,
        "winget_scope": scope,
        "analysis": {
            "mode": "microsoft_store_catalog" if is_store else "winget_catalog",
            "scanner_version": VERSION,
            "reasons": [
                "Microsoft-Store-ID explizit gespeichert; Installation über WinGet-Quelle msstore im USER-Kontext."
                if is_store else
                "WinGet-Paket-ID explizit gespeichert; Installation mit --id --exact."
            ],
        },
    }
    if is_store:
        app["package_kind"] = "microsoft_store"
    if version:
        app["winget_version"] = version
    if scope == "user":
        app["install_timeout_minutes"] = install_timeout_minutes

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]
    existing = sw.get(key)
    if isinstance(existing, dict):
        print()
        print(f"! '{key}' existiert bereits.")
        if not yes_no("Vorhandenen Katalogeintrag überschreiben?", False):
            print("Abgebrochen.")
            return
        backup_parameter_profile(args.project, catalog_name, key, existing)
        print("✓ Vorhandener Eintrag vorher gesichert.")

    app = sanitize_catalog_data(app)
    print()
    print("Wird gespeichert:")
    print(redact_sensitive_text(yaml.safe_dump({key: app}, allow_unicode=True, sort_keys=False).rstrip()))
    if not yes_no("Zum Katalog hinzufügen?", True):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(args.project, catalog, catalog_name)
    backup_parameter_profile(args.project, catalog_name, key, app)
    print()
    if is_store:
        print(f"✓ Microsoft-Store-App '{package_id}' als '{key}' gespeichert.")
        print("  Backend: WinGet | Quelle: msstore | Scope: USER | Version: Store-aktuell")
    else:
        print(f"✓ WinGet-Paket '{package_id}' als '{key}' gespeichert.")
        print(f"  Scope: {scope.upper()} | Quelle: {source} | Version: {version or 'aktuell'}")


def cmd_store_add(args: argparse.Namespace) -> None:
    """Microsoft-Store-App über den bestehenden WinGet-Unterbau hinzufügen."""
    args.source = "msstore"
    args.scope = "user"
    args.version = None
    cmd_winget_add(args)


def cmd_software_add(args: argparse.Namespace) -> None:
    from .catalogs import (
        backup_parameter_profile,
        choose_catalog_interactive,
        get_catalog,
        prompt,
        prompt_choice,
        prompt_install_context,
        save_catalog,
        slugify,
        validate_software_key,
        yes_no,
    )
    from .environment import (
        _mavi_drive_label,
        _mavi_source_root,
        browse_installer,
        choose_installer_path,
        die,
        ensure_initialized,
        get_config,
        normalize_path,
        resolve_installer_path,
        sha256_file,
    )
    from .installer_analysis import analyze_installer
    from .reports import (
        redact_sensitive_text,
        validate_installer_arguments,
    )
    from .settings import VERSION

    ensure_initialized(args.project, quiet=True)
    config = get_config(args.project)

    if args.path:
        path = normalize_path(args.path, config)
        if path.exists() and path.is_dir() and sys.stdin.isatty():
            path = browse_installer(
                path,
                _mavi_drive_label(
                    (config.get("software_source", {}) or {}).get("drive")
                ),
            )
    else:
        path = choose_installer_path(config)

    path = resolve_installer_path(path, config)

    if not path.exists():
        local_root = _mavi_source_root(config)
        die(
            f"Installer nicht gefunden: {path}\n"
            f"Bekannte Softwarequelle: {local_root or '(nicht eingerichtet)'}"
        )

    if not path.is_file():
        die(f"Pfad ist keine Datei: {path}")

    catalog_name = choose_catalog_interactive(
        args.project,
        getattr(args, "catalog", None),
        purpose="verwenden",
        ask_other=True,
    )
    print(f"Zielkatalog: {catalog_name}")

    if looks_like_office_candidate(path):
        print()
        print(
            "! Microsoft Office / Project / Visio erkannt."
        )
        if yes_no(
            "Zum Microsoft-Assistenten wechseln?",
            True,
        ):
            cmd_add_office_odt(
                args,
                path,
                catalog_name,
                config,
            )
            return

    analysis = analyze_installer(
        path,
        args.project,
        use_known_rules=True,
        use_learned_rules=False,
    )

    # Microsoft TeamsBootstrapper ist absichtlich eine headless CLI.
    # Für die Bereitstellung ist -p der normale Provisioning-Schalter.
    if path.name.lower() == "teamsbootstrapper.exe":
        analysis["arguments"] = analysis.get("arguments") or "-p"
        analysis["context"] = "machine"
        reasons = list(analysis.get("reasons", []) or [])
        reasons.append("Microsoft TeamsBootstrapper erkannt: Provisioning mit -p vorgeschlagen.")
        analysis["reasons"] = reasons
        print()
        print("✓ Microsoft TeamsBootstrapper erkannt.")
        print("  Empfehlung: Machine + Parameter -p (headless Provisioning).")
        print("  Falls der Aufruf im Benutzerkontext erhöhte Rechte verlangt,")
        print("  kann der Kontext 'USER → UAC FALLBACK' automatisch sichtbar nach UAC wechseln.")

    print()
    print("Installer-Grunddaten")
    print("====================")
    print(f"Pfad:    {path}")
    print(f"Typ:     {analysis['type']}")
    print(f"Regel:   {analysis['engine']}")
    print(
        "Flags:   "
        + (
            redact_sensitive_text(analysis["arguments"])
            or "(manuell / keine)"
        )
    )
    print()
    print(
        "Deep-Scan: AUS. Es werden keine Silent-Flags "
        "aus Binärdaten geraten."
    )

    name = args.name or prompt(
        "Anzeigename",
        analysis["name_guess"],
    )
    key = validate_software_key(
        args.key or prompt(
            "Katalog-Schlüssel",
            slugify(name),
        )
    )

    typ = analysis["type"]
    if typ not in {"msi", "exe"}:
        typ = prompt_choice(
            "Installer-Typ:",
            [("msi", "MSI"), ("exe", "EXE")],
            "exe",
        )

    catalog = get_catalog(args.project, catalog_name)
    sw = catalog["software_catalog"]
    existing = sw.get(key)
    preserve_existing = False

    if isinstance(existing, dict):
        print()
        print(f"! '{key}' existiert bereits.")
        print(
            f"  Aktueller Installer: "
            f"{existing.get('installer', '')}"
        )
        print(
            f"  Gespeicherte Flags:  "
            f"{redact_sensitive_text(existing.get('arguments')) or '(keine)'}"
        )
        print(
            f"  Kontext:             "
            f"{existing.get('context', 'machine')}"
        )

        if not yes_no(
            "Mit neuer Installer-Datei überschreiben?",
            False,
        ):
            print("Abgebrochen.")
            return

        # Vor JEDEM Versionswechsel automatisch sichern.
        backup_parameter_profile(
            args.project,
            catalog_name,
            key,
            existing,
        )
        print(
            "✓ Vorhandene Parameter automatisch gesichert."
        )

        same_type = (
            str(existing.get("type", "")).lower()
            == typ.lower()
        )

        if not same_type:
            print(
                "! Installer-Typ hat sich geändert. Alte Flags "
                "werden nicht blind übernommen."
            )
        else:
            preserve_existing = yes_no(
                "Vorhandene Parameter/Flags für die neue "
                "Version übernehmen?",
                True,
            )

    known_arguments = str(
        analysis.get("arguments", "")
    )

    if preserve_existing:
        arguments = str(
            existing.get("arguments", "")
        )
        context = str(
            existing.get("context", "machine")
        )
        creates_path = str(
            existing.get("creates_path", "")
        )
        desktop_shortcut = existing.get(
            "desktop_shortcut"
        )
        install_timeout_minutes = int(
            existing.get("install_timeout_minutes", 30)
            or 30
        )
        print()
        print("Übernommen:")
        print(
            f"  Flags:   {redact_sensitive_text(arguments) or '(keine)'}"
        )
        print(f"  Kontext: {context}")
        print(
            f"  Detect:  "
            f"{creates_path or '(keiner)'}"
        )
    else:
        if typ == "exe":
            if known_arguments:
                print()
                print(
                    "Feste Produktregel im Skript:"
                )
                print(f"  {redact_sensitive_text(known_arguments)}")
                if yes_no(
                    "Diese Parameter übernehmen?",
                    True,
                ):
                    arguments = known_arguments
                else:
                    arguments = prompt(
                        "Silent-Parameter "
                        "(Enter = keine)",
                        "",
                    )
            else:
                print()
                print(
                    "Keine feste Produktregel vorhanden."
                )
                arguments = prompt(
                    "Silent-Parameter "
                    "(Enter = keine)",
                    "",
                )
        else:
            arguments = ""

        recommended = str(
            analysis.get("context", "machine")
        )

        context = prompt_install_context(
            args.project,
            recommended,
        )

        install_timeout_minutes = 30
        if context in {
            "machine_detached",
            "machine_interactive",
            "user_interactive",
            "user_uac",
        }:
            timeout_label = (
                "DETACHED"
                if context == "machine_detached"
                else "INTERAKTIV"
            )
            while True:
                timeout_raw = prompt(
                    f"Timeout für {timeout_label}-Installation in Minuten",
                    "30",
                )

                try:
                    install_timeout_minutes = int(timeout_raw)
                except ValueError:
                    print("Bitte eine ganze Zahl in Minuten eingeben.")
                    continue

                if install_timeout_minutes < 1:
                    print("Timeout muss mindestens 1 Minute sein.")
                    continue

                break

        creates_path = prompt(
            "Optionaler Erkennungspfad nach Installation "
            "(Enter = keiner)",
            str(analysis.get("creates_path", "")),
        )

        is_forticlient = (
            analysis["engine"] == "FortiClient VPN"
        )
        shortcut_default_target = (
            r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
            if is_forticlient
            else ""
        )

        create_shortcut = yes_no(
            "Desktop-Verknüpfung für ALLE Benutzer "
            "sicherstellen?",
            is_forticlient,
        )

        desktop_shortcut = None
        if create_shortcut:
            shortcut_name = prompt(
                "Name der Desktop-Verknüpfung",
                name,
            )
            shortcut_target = prompt(
                "Ziel-EXE der Desktop-Verknüpfung",
                shortcut_default_target,
            )
            if shortcut_target:
                desktop_shortcut = {
                    "enabled": True,
                    "name": shortcut_name,
                    "target": shortcut_target,
                }

    app = {
        "name": name,
        "installer": str(path),
        "type": typ,
        "context": context,
        "installer_engine": analysis["engine"],
        "analysis": {
            "mode": "manual_parameters",
            "scanner_version": VERSION,
            "reasons": analysis.get("reasons", []),
        },
    }

    if arguments:
        app["arguments"] = validate_installer_arguments(
            arguments,
            context=f"Katalogeintrag '{key}'",
        )

    if creates_path:
        app["creates_path"] = creates_path

    if desktop_shortcut:
        app["desktop_shortcut"] = desktop_shortcut

    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
    }:
        app["install_timeout_minutes"] = int(
            install_timeout_minutes
        )

    if bool(getattr(args, "allow_unsafe_missing_sha256", False)):
        print(
            "! UNSICHERE AUSNAHME: Dieser Eintrag wird ausdrücklich ohne "
            "gebundenen Installer-Hash gespeichert."
        )
        app["allow_unsafe_missing_sha256"] = True
    else:
        print("Berechne verpflichtenden SHA-256 ...")
        app["sha256"] = sha256_file(path)

    app = sanitize_catalog_data(app)

    print()
    print("Wird gespeichert:")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {key: app},
                allow_unicode=True,
                sort_keys=False,
            ).rstrip()
        )
    )

    if not yes_no(
        "Zum Katalog hinzufügen?",
        True,
    ):
        print("Abgebrochen.")
        return

    sw[key] = app
    save_catalog(
        args.project,
        catalog,
        catalog_name,
    )

    # Nach erfolgreichem Speichern direkt aktuellen Stand sichern.
    backup_parameter_profile(
        args.project,
        catalog_name,
        key,
        app,
    )

    print(
        f"\n✓ '{key}' wurde zum Katalog "
        f"'{catalog_name}' hinzugefügt."
    )
    print(
        "✓ Parameter-Profil wurde ebenfalls aktualisiert."
    )

__all__ = (
    "looks_like_office_candidate",
    "friendly_product_from_id",
    "parse_office_xml",
    "choose_office_profile",
    "choose_office_architecture",
    "choose_office_language",
    "office_default_creates_path",
    "generate_office_xml",
    "choose_xml_file",
    "choose_odt_setup",
    "cmd_add_office_odt",
    "cmd_microsoft_add",
    "cmd_software_scan",
    "_neutralize_jinja_literal",
    "sanitize_catalog_data",
    "compact_silent_detection_for_catalog",
    "compact_analysis_for_catalog",
    "repair_catalog_jinja_noise",
    "cmd_catalog_repair",
    "WINGET_PACKAGE_ID_RE",
    "WINGET_SOURCE_RE",
    "WINGET_VERSION_RE",
    "_is_msstore_app",
    "_software_type_label",
    "_winget_validate_identifier",
    "_winget_validate_source",
    "_winget_validate_version",
    "_parse_winget_search_table",
    "_run_winget_search_remote",
    "cmd_winget_add",
    "cmd_store_add",
    "cmd_software_add",
)
