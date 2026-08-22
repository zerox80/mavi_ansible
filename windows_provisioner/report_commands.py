# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Berichts- und Katalogausgabebefehle.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    html,
    ipaddress,
    os,
    re,
    shutil,
    socket,
    subprocess,
    sys,
    time,
    urllib,
    yaml,
)



def _print_catalog_summary(catalog: dict[str, Any]) -> None:
    from .reports import (
        _software_mode_meta,
    )

    from .software import _software_type_label

    type_counts: dict[str, int] = {}
    scope_counts = {"PC": 0, "SYSTEM": 0, "USER": 0, "?": 0}
    for raw_app in catalog.values():
        app = raw_app if isinstance(raw_app, dict) else {}
        app_type = _software_type_label(app)
        type_counts[app_type] = type_counts.get(app_type, 0) + 1
        scope = _software_mode_meta(app)["scope"]
        scope_counts[scope if scope in scope_counts else "?"] += 1
    types = " · ".join(f"{name}: {count}" for name, count in sorted(type_counts.items()))
    print(f"Programme: {len(catalog)}  |  PC: {scope_counts['PC']}  |  SYSTEM: {scope_counts['SYSTEM']}  |  USER: {scope_counts['USER']}")
    print(f"Typen:     {types}")


def cmd_software_list(args: argparse.Namespace) -> None:

    from .reports import (
        REPORT_HTTP_DEFAULT_TTL,
    )
    from .reports import (
        REPORT_HTTP_PORT,
        _ensure_catalog_report_server,
        _generate_catalog_html_report,
        _print_catalog_summary,
        _render_catalog_terminal_table,
    )

    from .catalogs import (
        get_catalog,
        get_default_catalog_name,
        resolve_catalog_name,
    )

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]
    default_name = get_default_catalog_name(args.project)

    suffix = " [DEFAULT]" if catalog_name == default_name else ""
    print()
    print(f"SOFTWARE-KATALOG · {catalog_name}{suffix}")
    print("=" * min(78, max(32, len(catalog_name) + 22)))

    if not catalog:
        print("Katalog ist leer.")
        return

    print()
    _render_catalog_terminal_table(catalog)
    print()
    _print_catalog_summary(catalog)

    try:
        report_path = _generate_catalog_html_report(
            args.project,
            catalog_name,
            catalog,
            default_name,
        )
        environment_opt_in = str(
            os.environ.get("MAVI_REPORT_HTTP", "") or ""
        ).strip().lower() in {"1", "true", "yes", "on"}
        serve_report = bool(
            getattr(args, "serve_report", False) or environment_opt_in
        )
        report_url: str | None = None
        server_error: str | None = None
        if serve_report:
            report_url, server_error = _ensure_catalog_report_server(
                args.project,
                report_path,
                bind=str(getattr(args, "report_bind", "loopback") or "loopback"),
                port=int(getattr(args, "report_port", REPORT_HTTP_PORT)),
                ttl=int(getattr(args, "report_ttl", REPORT_HTTP_DEFAULT_TTL)),
            )
        print()
        print("HTML-DASHBOARD")
        print("--------------")
        if report_url:
            print(f"Browser-Link: {report_url}")
            print(
                "Hinweis:      Der tokenisierte HTTP-Link ist nur kurzzeitig "
                "verfügbar; HTTP im LAN ist nicht verschlüsselt."
            )
        else:
            print(f"Datei-Link:   {report_path.resolve().as_uri()}")
            if server_error:
                print(f"Hinweis:      {server_error}")
            elif not serve_report:
                print(
                    "Hinweis:      HTTP ist standardmäßig aus. Optional bewusst "
                    "mit --serve-report aktivieren."
                )
        print(f"HTML-Datei:   {report_path}")
    except OSError as exc:
        print()
        print(f"! HTML-Report konnte nicht erzeugt werden: {exc}")


def cmd_software_show(args: argparse.Namespace) -> None:
    from .reports import (
        redact_sensitive_text,
    )

    from .catalogs import (
        get_catalog,
        resolve_catalog_name,
    )
    from .environment import die

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)["software_catalog"]
    if args.key not in catalog:
        die(f"'{args.key}' ist nicht im Katalog '{catalog_name}'.")

    print(f"Katalog: {catalog_name}\n")
    print(
        redact_sensitive_text(
            yaml.safe_dump(
                {args.key: catalog[args.key]},
                allow_unicode=True,
                sort_keys=False,
            )
        )
    )


def cmd_software_remove(args: argparse.Namespace) -> None:
    from .catalogs import (
        get_catalog,
        resolve_catalog_name,
        save_catalog,
        yes_no,
    )
    from .environment import die

    catalog_name = resolve_catalog_name(
        args.project,
        getattr(args, "catalog", None),
    )
    catalog = get_catalog(args.project, catalog_name)

    if args.key not in catalog["software_catalog"]:
        die(f"'{args.key}' ist nicht im Katalog '{catalog_name}'.")

    app = catalog["software_catalog"][args.key]
    label = app.get("name", args.key)

    print()
    print(f"Programm: {label} ({args.key})")
    print(f"Katalog:  {catalog_name}")
    print()
    print(
        "Hinweis: Dadurch wird NUR der Katalogeintrag entfernt. "
        "Auf bereits provisionierten PCs wird nichts deinstalliert."
    )

    if not args.yes and not yes_no(
        f"'{label}' wirklich aus dem Katalog entfernen?",
        False,
    ):
        print("Abgebrochen.")
        return

    del catalog["software_catalog"][args.key]
    save_catalog(args.project, catalog, catalog_name)
    print(
        f"✓ '{label}' ({args.key}) wurde aus "
        f"'{catalog_name}' entfernt."
    )
