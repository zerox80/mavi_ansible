# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Microsoft-Office- und ODT-Workflows.

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
    from .software import (
        choose_odt_setup,
        choose_office_architecture,
        choose_office_language,
        choose_office_profile,
        choose_xml_file,
        friendly_product_from_id,
        generate_office_xml,
        office_default_creates_path,
        parse_office_xml,
        sanitize_catalog_data,
    )

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
    from .software import (
        cmd_add_office_odt,
    )

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
