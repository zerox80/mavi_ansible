# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Mavi Provisioner contributors
"""Katalogdarstellung, Berichte und redigierte Ausgaben."""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    html,
    ipaddress,
    os,
    re,
    secrets,
    shutil,
    socket,
    subprocess,
    sys,
    time,
    urllib,
    yaml,
)

REPORT_HTTP_PORT = 8765
REPORT_SERVER_MARKER = "Mavi-PROVISION-REPORT-SERVER-v1"
REPORT_HTTP_DEFAULT_TTL = 300


def _clip_cell(value: Any, width: int) -> str:
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ").strip()
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return "…"
    return text[: width - 1].rstrip() + "…"


def _software_mode_meta(app: dict[str, Any]) -> dict[str, str]:
    from .catalogs import (
        _context_label,
        _normalize_context_value,
    )
    from .software import _is_msstore_app

    context = _normalize_context_value(str(app.get("context", "machine")))
    mapping = {
        "machine": ("Machine/Admin", "PC", "Direkt"),
        "system": ("SYSTEM", "SYSTEM", "Direkt"),
        "user_interactive": ("User interaktiv", "USER", "GUI"),
        "machine_detached": ("SYSTEM detached", "SYSTEM", "Task"),
        "machine_interactive": ("User + Highest", "USER", "GUI/Admin"),
        "user_uac": ("User → UAC Fallback", "USER", "GUI/User→UAC"),
    }
    mode, scope, execution = mapping.get(context, (context, "?", "?"))
    app_type = str(app.get("type", "")).lower()
    if app_type == "office_odt":
        # Der ODT-Pfad im Playbook läuft unabhängig vom historischen Kontextfeld
        # immer als SYSTEM über einen detached Scheduled Task.
        mode = "ODT SYSTEM detached"
        scope = "SYSTEM"
        execution = "Task/ODT"
    elif app_type == "winget":
        winget_scope = str(app.get("winget_scope", scope)).lower()
        scope = "USER" if winget_scope == "user" else "PC"
        if _is_msstore_app(app):
            mode = "Microsoft Store USER"
            scope = "USER"
            execution = "WinGet/msstore"
        else:
            mode = f"WinGet {scope}"
            execution = "WinGet"
    return {
        "context": context,
        "mode": mode,
        "scope": scope,
        "execution": execution,
        "long": _context_label(context),
    }


def _software_installer_display(app: dict[str, Any]) -> str:
    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        return str(app.get("winget_id") or app.get("installer") or "(WinGet-ID fehlt)")
    installer = str(app.get("installer", "") or "")
    if not installer:
        return "(kein Installer)"
    normalized = installer.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1] or installer


def _software_parameters_display(app: dict[str, Any]) -> str:
    from .software import _is_msstore_app

    app_type = str(app.get("type", "?")).lower()
    if app_type == "winget":
        if _is_msstore_app(app):
            return "source=msstore | scope=user"
        parts = [f"scope={app.get('winget_scope', 'machine')}"]
        if app.get("winget_version"):
            parts.append(f"v={app.get('winget_version')}")
        return " | ".join(parts)
    args = redact_sensitive_text(app.get("arguments", "")).strip()
    return args or "(keine)"


def _software_detection_display(app: dict[str, Any]) -> str:
    from .software import _is_msstore_app

    if str(app.get("type", "")).lower() == "winget":
        return "WinGet list · msstore" if _is_msstore_app(app) else "WinGet list"
    creates = str(app.get("creates_path", "") or "").strip()
    if creates:
        return creates
    return "Auto-Scan"


def _software_timeout_display(app: dict[str, Any]) -> str:
    from .catalogs import _normalize_context_value

    context = _normalize_context_value(str(app.get("context", "machine")))
    if context in {
        "machine_detached",
        "machine_interactive",
        "user_interactive",
        "user_uac",
    } or (str(app.get("type", "")).lower() == "winget" and str(app.get("winget_scope", "machine")) == "user"):
        return f"{int(app.get('install_timeout_minutes', 30) or 30)}m"
    return "-"


def _render_catalog_terminal_table(catalog: dict[str, Any]) -> None:
    from .software import _software_type_label

    terminal_width = shutil.get_terminal_size((160, 30)).columns
    terminal_width = max(78, min(terminal_width, 220))

    rows: list[dict[str, str]] = []
    for index, (key, raw_app) in enumerate(catalog.items(), start=1):
        app = raw_app if isinstance(raw_app, dict) else {}
        meta = _software_mode_meta(app)
        rows.append({
            "nr": str(index),
            "key": str(key),
            "name": str(app.get("name", key)),
            "type": _software_type_label(app),
            "mode": meta["mode"],
            "scope": meta["scope"],
            "installer": _software_installer_display(app),
            "params": _software_parameters_display(app),
            "detect": _software_detection_display(app),
            "timeout": _software_timeout_display(app),
        })

    if terminal_width < 105:
        for row in rows:
            print(f"[{row['nr']}] {row['name']}  ({row['type']})")
            print(f"    Schlüssel: {row['key']}")
            print(f"    Modus:     {row['mode']} | Ziel: {row['scope']} | Timeout: {row['timeout']}")
            print(f"    Installer: {row['installer']}")
            print(f"    Parameter: {row['params']}")
            print(f"    Erkennung: {row['detect']}")
            print()
        return

    columns: list[tuple[str, str, int]] = [
        ("nr", "#", 3),
        ("name", "NAME", 25),
        ("type", "TYP", 8),
        ("mode", "INSTALL-MODUS", 18),
        ("scope", "ZIEL", 7),
        ("installer", "INSTALLER / ID", 25),
    ]
    if terminal_width >= 125:
        columns.insert(1, ("key", "SCHLÜSSEL", 20))
    if terminal_width >= 165:
        columns.append(("params", "PARAMETER", 23))
    if terminal_width >= 195:
        columns.append(("detect", "ERKENNUNG", 20))
        columns.append(("timeout", "TIMEOUT", 7))

    def table_width(cols: list[tuple[str, str, int]]) -> int:
        return sum(width for _, _, width in cols) + (3 * (len(cols) - 1)) + 4

    while table_width(columns) > terminal_width and len(columns) > 5:
        removable = next(
            (i for i, col in reversed(list(enumerate(columns))) if col[0] in {"detect", "params", "timeout", "key"}),
            None,
        )
        if removable is None:
            break
        columns.pop(removable)

    top = "┌" + "┬".join("─" * (width + 2) for _, _, width in columns) + "┐"
    mid = "├" + "┼".join("─" * (width + 2) for _, _, width in columns) + "┤"
    bottom = "└" + "┴".join("─" * (width + 2) for _, _, width in columns) + "┘"

    print(top)
    print("│" + "│".join(f" {_clip_cell(header, width):<{width}} " for _, header, width in columns) + "│")
    print(mid)
    for row in rows:
        print("│" + "│".join(f" {_clip_cell(row.get(field, ''), width):<{width}} " for field, _, width in columns) + "│")
    print(bottom)


_SENSITIVE_ARGUMENT_NAME = (
    r"(?:password|passwd|pass|passphrase|pwd|pin|token|access[-_]?token|"
    r"refresh[-_]?token|session[-_]?(?:id|token)|jwt|cookie|set[-_]?cookie|"
    r"secret|client[-_]?(?:secret|key)|consumer[-_]?secret|api[-_]?key|apikey|"
    r"aws[-_]?secret[-_]?access[-_]?key|aws[-_]?access[-_]?key[-_]?id|"
    r"vault[-_]?password(?:[-_]?file)?|connection[-_]?string|"
    r"license[-_]?key|licensekey|product[-_]?key|serial(?:number)?|"
    r"authorization|credential|private[-_]?key)"
)
_SENSITIVE_ARGUMENT_VALUE = (
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;]+)'
)
_SENSITIVE_ARGUMENT_PATTERNS = (
    re.compile(
        r"(?i)(?P<prefix>\b(?:Proxy-)?Authorization\s*[:=]\s*)"
        r"(?P<secret>[^\r\n,]+)"
    ),
    re.compile(
        rf"(?i)(?P<prefix>\bBearer\s+)(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        rf"(?i)(?P<prefix>(?<![A-Za-z0-9_])[\"']?"
        rf"{_SENSITIVE_ARGUMENT_NAME}[\"']?\s*(?:=|:)\s*)"
        rf"(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        rf"(?i)(?P<prefix>(?<!\S)(?:(?:--?|/)"
        rf"{_SENSITIVE_ARGUMENT_NAME}|-p)\s+)"
        rf"(?P<secret>{_SENSITIVE_ARGUMENT_VALUE})"
    ),
    re.compile(
        r"(?i)(?P<prefix>://[^/\s:@]+:)(?P<secret>[^@/\s]+)(?=@)"
    ),
)

# Catalogs may reference only a plain, allow-listed Vault variable.  Complex
# Jinja expressions and lookups are deliberately not executable catalog data.
VAULT_ARGUMENT_REFERENCE_RE = re.compile(
    r"\{\{\s*(?:vault|mavi_vault)_[A-Za-z][A-Za-z0-9_]{0,127}\s*\}\}"
)


def _unquote_argument_value(value: str) -> str:
    value = str(value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def _literal_secret_argument_names(value: Any) -> list[str]:
    """Return sensitive option names whose value is not a strict Vault ref."""
    text_value = str(value or "")
    findings: list[str] = []
    for pattern in _SENSITIVE_ARGUMENT_PATTERNS:
        for match in pattern.finditer(text_value):
            secret_value = _unquote_argument_value(match.groupdict().get("secret", ""))
            if VAULT_ARGUMENT_REFERENCE_RE.fullmatch(secret_value):
                continue
            prefix = str(match.groupdict().get("prefix", "Geheimwert")).strip()
            prefix = redact_sensitive_text(prefix).strip(" :=") or "Geheimwert"
            if prefix not in findings:
                findings.append(prefix)
    return findings


def validate_installer_arguments(value: Any, *, context: str = "Installer-Parameter") -> str:
    """Reject literal credentials while permitting strict Ansible-Vault refs."""
    from .environment import die

    arguments = str(value or "")
    if any(ord(char) < 32 and char not in {"\t"} for char in arguments):
        die(f"{context}: Steuerzeichen und Zeilenumbrüche sind nicht erlaubt.")
    if "***REDACTED***" in arguments or "<REDACTED" in arguments.upper():
        die(f"{context}: Ein geschwärzter Platzhalter ist kein ausführbarer Geheimwert.")

    findings = _literal_secret_argument_names(arguments)
    if findings:
        die(
            f"{context}: Klartext-Geheimwerte in Installer-Argumenten sind verboten "
            f"({', '.join(findings)}). Lege den Wert mit 'credentials setup' in "
            "Ansible Vault ab und verwende eine streng einfache Referenz, z. B. "
            "--token \"{{ vault_example_token }}\"."
        )
    return arguments


def redact_sensitive_text(value: Any) -> str:
    """Zentrale Schwärzung für Pläne, Live-Ausgaben, Reports und Fehlertexte."""
    text_value = str(value or "")

    for pattern in _SENSITIVE_ARGUMENT_PATTERNS:
        text_value = pattern.sub(
            lambda match: match.group("prefix") + "***REDACTED***",
            text_value,
        )

    # Nach den quotierten Formen auch unquotierte Connection-String-Werte
    # mit Leerzeichen bis zum Semikolon vollständig abdecken.
    connection_pattern = re.compile(
        rf"(?i)(?P<prefix>\b{_SENSITIVE_ARGUMENT_NAME}\s*=\s*)"
        r"(?P<secret>[^;\r\n]+)(?=;)"
    )
    text_value = connection_pattern.sub(
        lambda match: match.group("prefix") + "***REDACTED***",
        text_value,
    )

    return text_value


def _report_safe_arguments(value: str) -> str:
    return redact_sensitive_text(value)


def _html_badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge {html.escape(kind)}">{html.escape(str(text))}</span>'


def _generate_catalog_html_report(project: Path, catalog_name: str, catalog: dict[str, Any], default_name: str) -> Path:
    from .environment import project_paths
    from .settings import VERSION
    from .software import _is_msstore_app

    reports_dir = project_paths(project)["reports_dir"]
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", catalog_name).strip("-.") or "catalog"
    report_path = reports_dir / f"software-catalog-{safe_name}.html"

    type_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    table_rows: list[str] = []

    for index, (key, raw_app) in enumerate(catalog.items(), start=1):
        app = raw_app if isinstance(raw_app, dict) else {}
        raw_app_type = str(app.get("type", "?")).lower()
        app_type = "store" if _is_msstore_app(app) else raw_app_type
        type_counts[app_type] = type_counts.get(app_type, 0) + 1
        meta = _software_mode_meta(app)
        mode_counts[meta["mode"]] = mode_counts.get(meta["mode"], 0) + 1
        scope_counts[meta["scope"]] = scope_counts.get(meta["scope"], 0) + 1

        installer_short = _software_installer_display(app)
        params = _report_safe_arguments(_software_parameters_display(app))
        detection = _software_detection_display(app)
        timeout = _software_timeout_display(app)
        engine = str(app.get("installer_engine", "") or "-")
        sha256 = str(app.get("sha256", "") or "-")
        raw_config_file = str(app.get("configuration_file", "") or "").strip()
        config_file = (
            re.split(r"[\\/]", raw_config_file)[-1]
            if raw_config_file
            else "-"
        )
        source = str(app.get("winget_source", "") or "-") if raw_app_type == "winget" else "lokale Ablage"
        version = (
            "Store-aktuell" if _is_msstore_app(app) else str(app.get("winget_version", "") or "aktuell")
        ) if raw_app_type == "winget" else "-"
        shortcut = app.get("desktop_shortcut")
        if isinstance(shortcut, dict) and shortcut.get("enabled"):
            shortcut_text = f"{shortcut.get('name', app.get('name', key))} → {shortcut.get('target', '?')}"
        else:
            shortcut_text = "-"

        type_kind = "store" if app_type == "store" else "winget" if app_type == "winget" else "office" if app_type == "office_odt" else "package"
        mode_kind = "user" if meta["scope"] == "USER" else "system" if meta["scope"] == "SYSTEM" else "machine"
        search_blob = " ".join([
            str(key), str(app.get("name", key)), app_type, meta["mode"], meta["scope"],
            installer_short, params, detection,
        ]).casefold()

        details = (
            f"<div class='detail-grid'>"
            f"<div><span>Interner Kontext</span><strong>{html.escape(meta['context'])}</strong></div>"
            f"<div><span>Ausführung</span><strong>{html.escape(meta['execution'])}</strong></div>"
            f"<div><span>Installer</span><strong>{html.escape(installer_short or '-')}</strong></div>"
            f"<div><span>Engine</span><strong>{html.escape(engine)}</strong></div>"
            f"<div><span>Quelle</span><strong>{html.escape(source)}</strong></div>"
            f"<div><span>Version</span><strong>{html.escape(version)}</strong></div>"
            f"<div><span>SHA-256</span><strong class='mono'>{html.escape(sha256)}</strong></div>"
            f"<div><span>Konfiguration</span><strong>{html.escape(config_file)}</strong></div>"
            f"<div><span>Desktop-Shortcut</span><strong>{html.escape(shortcut_text)}</strong></div>"
            f"</div>"
        )

        table_rows.append(
            f"<tr class='app-row' data-search='{html.escape(search_blob, quote=True)}' "
            f"data-type='{html.escape(app_type, quote=True)}' data-mode='{html.escape(meta['mode'], quote=True)}' data-scope='{html.escape(meta['scope'], quote=True)}'>"
            f"<td class='num'>{index}</td>"
            f"<td><div class='app-name'>{html.escape(str(app.get('name', key)))}</div><div class='sub mono'>{html.escape(str(key))}</div></td>"
            f"<td>{_html_badge(app_type.upper(), type_kind)}</td>"
            f"<td>{_html_badge(meta['mode'], mode_kind)}<div class='sub'>{html.escape(meta['long'])}</div></td>"
            f"<td>{_html_badge(meta['scope'], mode_kind)}</td>"
            f"<td><div class='mono'>{html.escape(installer_short)}</div></td>"
            f"<td><div class='mono wrap'>{html.escape(params)}</div></td>"
            f"<td><div class='mono wrap'>{html.escape(detection)}</div></td>"
            f"<td>{html.escape(timeout)}</td>"
            f"<td><details><summary>Details</summary>{details}</details></td>"
            f"</tr>"
        )

    generated = time.strftime("%d.%m.%Y %H:%M:%S")
    default_suffix = " · DEFAULT" if catalog_name == default_name else ""
    types_summary = "".join(
        f"<span class='mini-stat'><b>{count}</b> {html.escape(kind.upper())}</span>"
        for kind, count in sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
    ) or "<span class='mini-stat'>leer</span>"
    modes_options = "".join(
        f"<option value='{html.escape(mode, quote=True)}'>{html.escape(mode)} ({count})</option>"
        for mode, count in sorted(mode_counts.items())
    )
    type_options = "".join(
        f"<option value='{html.escape(kind, quote=True)}'>{html.escape(kind.upper())} ({count})</option>"
        for kind, count in sorted(type_counts.items())
    )
    scope_options = "".join(
        f"<option value='{html.escape(scope, quote=True)}'>{html.escape(scope)} ({count})</option>"
        for scope, count in sorted(scope_counts.items())
    )

    document = f'''<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mavi Software-Katalog · {html.escape(catalog_name)}</title>
<style>
:root{{--bg:#080b10;--panel:#10151d;--panel2:#151c26;--line:#273244;--text:#edf4ff;--muted:#8fa0b8;--accent:#76a9ff;--good:#6ee7b7;--warn:#fbbf24;--violet:#c4b5fd;--shadow:0 18px 55px rgba(0,0,0,.28)}}
*{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(circle at 15% -10%,#172944 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.45 Inter,Segoe UI,Arial,sans-serif}} .wrap-page{{max-width:1800px;margin:auto;padding:34px 28px 60px}} h1{{font-size:32px;margin:0 0 4px;letter-spacing:-.03em}} .eyebrow{{color:var(--accent);font-weight:800;letter-spacing:.16em;font-size:11px}} .muted,.sub{{color:var(--muted)}} .sub{{font-size:12px;margin-top:3px}} .hero{{display:flex;justify-content:space-between;gap:25px;align-items:flex-end;margin-bottom:24px}} .hero-right{{text-align:right}} .stats{{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:12px;margin:18px 0 20px}} .stat{{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow)}} .stat b{{font-size:25px;display:block}} .stat span{{color:var(--muted);font-size:12px}} .type-line{{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}} .mini-stat{{padding:7px 10px;background:#0d1219;border:1px solid var(--line);border-radius:10px;color:var(--muted)}} .mini-stat b{{color:var(--text)}} .toolbar{{position:sticky;top:0;z-index:4;display:grid;grid-template-columns:minmax(260px,1.5fr) repeat(3,minmax(150px,.55fr));gap:10px;background:rgba(8,11,16,.88);backdrop-filter:blur(12px);padding:12px 0}} input,select{{width:100%;background:#0e141d;color:var(--text);border:1px solid var(--line);border-radius:11px;padding:11px 12px;outline:none}} input:focus,select:focus{{border-color:var(--accent)}} .table-shell{{overflow:auto;border:1px solid var(--line);border-radius:16px;background:var(--panel);box-shadow:var(--shadow)}} table{{width:100%;border-collapse:separate;border-spacing:0;min-width:1450px}} th{{position:sticky;top:68px;z-index:3;background:#141b25;color:#aebbd0;text-align:left;font-size:11px;letter-spacing:.08em;padding:13px 12px;border-bottom:1px solid var(--line)}} td{{padding:13px 12px;border-bottom:1px solid #1e2836;vertical-align:top}} tr:hover td{{background:#131a24}} .num{{color:#61718a;width:50px}} .app-name{{font-weight:750;font-size:15px}} .mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}} .wrap{{max-width:330px;word-break:break-word}} .badge{{display:inline-flex;align-items:center;padding:4px 8px;border-radius:999px;border:1px solid #334157;background:#1b2533;color:#dce8f9;font-size:11px;font-weight:800;white-space:nowrap}} .badge.machine{{background:#102a24;border-color:#1d5949;color:#8ff0cd}} .badge.system{{background:#30240e;border-color:#624918;color:#ffd978}} .badge.user{{background:#241b38;border-color:#4a376d;color:#d8c7ff}} .badge.winget{{background:#10263a;border-color:#1c4f79;color:#8dcbff}} .badge.store{{background:#102f23;border-color:#246b4d;color:#8ff0c2}} .badge.office{{background:#2b1728;border-color:#623255;color:#f5a8dd}} details{{min-width:110px}} summary{{cursor:pointer;color:var(--accent);font-weight:700}} .detail-grid{{display:grid;grid-template-columns:repeat(2,minmax(250px,1fr));gap:8px;margin-top:12px;min-width:620px;padding:12px;background:#0b1017;border:1px solid var(--line);border-radius:12px}} .detail-grid div{{display:flex;flex-direction:column;gap:2px}} .detail-grid span{{color:var(--muted);font-size:11px}} .detail-grid strong{{font-weight:600;word-break:break-all}} .empty{{display:none;text-align:center;padding:35px;color:var(--muted)}} footer{{margin-top:18px;color:var(--muted);font-size:12px}} @media(max-width:900px){{.stats{{grid-template-columns:repeat(2,1fr)}}.toolbar{{grid-template-columns:1fr 1fr;position:static}}th{{top:0}}.hero{{display:block}}.hero-right{{text-align:left;margin-top:10px}}}}
</style>
</head>
<body><div class="wrap-page">
<div class="hero"><div><div class="eyebrow">Mavi PROVISIONING · SOFTWARE INVENTORY</div><h1>{html.escape(catalog_name)}{html.escape(default_suffix)}</h1><div class="muted">Installationsquellen, Modi, Scope, Parameter und Erkennungslogik auf einen Blick.</div></div><div class="hero-right"><div class="muted">Erzeugt am</div><b>{generated}</b><div class="sub">Mavi Provisioner {VERSION}</div></div></div>
<div class="stats"><div class="stat"><b>{len(catalog)}</b><span>Programme gesamt</span></div><div class="stat"><b>{scope_counts.get('PC',0)}</b><span>PC / Machine</span></div><div class="stat"><b>{scope_counts.get('SYSTEM',0)}</b><span>LocalSystem</span></div><div class="stat"><b>{scope_counts.get('USER',0)}</b><span>User-Kontext</span></div></div>
<div class="type-line">{types_summary}</div>
<div class="toolbar"><input id="search" placeholder="Suchen: Name, Schlüssel, Installer, Parameter …"><select id="type"><option value="">Alle Typen</option>{type_options}</select><select id="mode"><option value="">Alle Install-Modi</option>{modes_options}</select><select id="scope"><option value="">Alle Ziele</option>{scope_options}</select></div>
<div class="table-shell"><table><thead><tr><th>#</th><th>PROGRAMM / SCHLÜSSEL</th><th>TYP</th><th>INSTALL-MODUS</th><th>ZIEL</th><th>INSTALLER / PAKET-ID</th><th>PARAMETER</th><th>ERKENNUNG</th><th>TIMEOUT</th><th>MEHR</th></tr></thead><tbody id="rows">{''.join(table_rows)}</tbody></table><div class="empty" id="empty">Keine Programme passen zu den Filtern.</div></div>
<footer>Der HTML-Bericht ist rein lesend. Häufige Secret-Parameter werden nur im Browser-Report geschwärzt; der Katalog selbst wird nicht verändert.</footer>
</div>
<script>
const q=id=>document.getElementById(id), rows=[...document.querySelectorAll('.app-row')];
function filterRows(){{let visible=0;const s=q('search').value.toLocaleLowerCase(),t=q('type').value,m=q('mode').value,sc=q('scope').value;for(const r of rows){{const ok=(!s||r.dataset.search.includes(s))&&(!t||r.dataset.type===t)&&(!m||r.dataset.mode===m)&&(!sc||r.dataset.scope===sc);r.style.display=ok?'':'none';if(ok)visible++}}q('empty').style.display=visible?'none':'block'}}
['search','type','mode','scope'].forEach(id=>q(id).addEventListener(id==='search'?'input':'change',filterRows));
</script></body></html>'''
    report_path.write_text(document, encoding="utf-8")
    return report_path


def _local_ipv4_for_target(target: str) -> str:
    """
    Die lokale IPv4 bestimmen, die das Betriebssystem für ein Ziel routen
    würde. Ein UDP-connect sendet dabei keine Nutzdaten. Kann keine Route
    bestimmt werden, bleibt der sichere Loopback-Fallback erhalten.
    """
    destination = str(target or "").strip() or "198.51.100.1"
    try:
        addresses = socket.getaddrinfo(
            destination,
            9,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
    except OSError:
        addresses = []

    for address in addresses:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(address[4])
            local_ip = str(probe.getsockname()[0] or "").strip()
            parsed = ipaddress.ip_address(local_ip)
            if parsed.version == 4 and not parsed.is_unspecified:
                return str(parsed)
        except (OSError, ValueError):
            continue
        finally:
            probe.close()
    return "127.0.0.1"


def _port_available_for_http(port: int, bind_ip: str = "127.0.0.1") -> bool:
    """Read-only Vorprüfung, ob die gewünschte TCP-Adresse gebunden werden kann."""
    try:
        parsed_port = int(port)
        parsed_ip = ipaddress.ip_address(str(bind_ip).strip())
    except (TypeError, ValueError):
        return False
    if not 1 <= parsed_port <= 65535 or parsed_ip.version != 4:
        return False

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((str(parsed_ip), parsed_port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _report_bind_ip(project: Path) -> str:
    from .execution import (
        ensure_windows_tree,
        load_inventory,
    )

    try:
        inventory = load_inventory(project)
        windows = ensure_windows_tree(inventory)
        for host_data in (windows.get("hosts", {}) or {}).values():
            if isinstance(host_data, dict) and host_data.get("ansible_host"):
                return _local_ipv4_for_target(str(host_data.get("ansible_host")))
    except Exception:
        pass
    return _local_ipv4_for_target("")


def _report_server_is_ours(health_url: str) -> bool:
    try:
        with urllib.request.urlopen(
            health_url,
            timeout=0.6,
        ) as response:
            body = response.read(1024).decode("utf-8", errors="replace").strip()
        return body == REPORT_SERVER_MARKER
    except Exception:
        return False


def _catalog_report_bind_ip(project: Path, requested: str) -> str:
    """
    HTTP-Berichte binden standardmäßig ausschließlich an Loopback. Eine
    private LAN-Adresse erfordert die explizite Auswahl ``lan`` oder die
    Angabe einer konkreten privaten Adresse. Wildcard/public binds werden
    auch bei Opt-in abgelehnt.
    """
    value = str(requested or "loopback").strip().lower()
    if value in {"loopback", "localhost", "local"}:
        return "127.0.0.1"
    if value == "lan":
        value = _report_bind_ip(project)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Report-Bind muss 'loopback', 'lan' oder eine private IPv4 sein.") from exc
    if parsed.version != 4 or parsed.is_unspecified or parsed.is_multicast:
        raise ValueError("Wildcard-, Multicast- und IPv6-Binds sind für den HTTP-Report nicht erlaubt.")
    if not (parsed.is_loopback or parsed.is_private):
        raise ValueError("Der HTTP-Report darf nur an Loopback oder eine private IPv4 gebunden werden.")
    return str(parsed)


def _catalog_report_ttl(value: Any) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        ttl = REPORT_HTTP_DEFAULT_TTL
    return max(30, min(ttl, 3600))


def _ensure_catalog_report_server(
    project: Path,
    report_path: Path,
    *,
    bind: str = "loopback",
    port: int = REPORT_HTTP_PORT,
    ttl: int = REPORT_HTTP_DEFAULT_TTL,
) -> tuple[str | None, str | None]:
    try:
        bind_ip = _catalog_report_bind_ip(project, bind)
        parsed_port = int(port)
    except (TypeError, ValueError) as exc:
        return None, str(exc)
    if not 1024 <= parsed_port <= 65535:
        return None, "Report-Port muss zwischen 1024 und 65535 liegen"
    if not _port_available_for_http(parsed_port, bind_ip):
        return None, f"Port {port} ist bereits durch einen anderen Dienst belegt"

    token = secrets.token_urlsafe(24)
    encoded_token = urllib.parse.quote(token, safe="")
    encoded_name = urllib.parse.quote(report_path.name, safe="")
    health_url = f"http://{bind_ip}:{parsed_port}/health/{encoded_token}"
    report_url = f"http://{bind_ip}:{parsed_port}/report/{encoded_token}/{encoded_name}"
    server_environment = os.environ.copy()
    server_environment["MAVI_REPORT_SERVER_TOKEN"] = token
    try:
        subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "_report-serve",
                "--file",
                str(report_path.resolve()),
                "--bind",
                bind_ip,
                "--port",
                str(parsed_port),
                "--ttl",
                str(_catalog_report_ttl(ttl)),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=server_environment,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        return None, f"Reportserver konnte nicht gestartet werden: {exc}"

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if _report_server_is_ours(health_url):
            return report_url, None
        time.sleep(0.1)

    return None, "Reportserver antwortet nach dem Start nicht"


def cmd_internal_report_serve(args: argparse.Namespace) -> None:
    """Interner, zeitlich begrenzter Einzeldatei-Server ohne Verzeichnislisting."""
    import http.server

    report_path = Path(args.file).resolve()
    bind_ip = _catalog_report_bind_ip(Path.cwd(), str(args.bind))
    port = int(args.port)
    ttl = _catalog_report_ttl(args.ttl)
    token = str(os.environ.pop("MAVI_REPORT_SERVER_TOKEN", "") or "")
    if not token or not report_path.is_file():
        raise SystemExit(2)

    encoded_token = urllib.parse.quote(token, safe="")
    report_route = (
        f"/report/{encoded_token}/"
        f"{urllib.parse.quote(report_path.name, safe='')}"
    )
    health_route = f"/health/{encoded_token}"

    class ReportHandler(http.server.BaseHTTPRequestHandler):
        server_version = "MaviReport/1"

        def _send_body(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _handle(self) -> None:
            route = urllib.parse.urlsplit(self.path).path
            if route == health_route:
                self._send_body(200, REPORT_SERVER_MARKER.encode("ascii"), "text/plain; charset=utf-8")
                return
            if route == report_route:
                try:
                    body = report_path.read_bytes()
                except OSError:
                    self._send_body(404, b"Not found", "text/plain; charset=utf-8")
                    return
                self._send_body(200, body, "text/html; charset=utf-8")
                return
            self._send_body(404, b"Not found", "text/plain; charset=utf-8")

        def do_GET(self) -> None:
            self._handle()

        def do_HEAD(self) -> None:
            self._handle()

        def log_message(self, _format: str, *args: Any) -> None:
            del args

    server = http.server.ThreadingHTTPServer((bind_ip, port), ReportHandler)
    server.timeout = 0.5
    deadline = time.monotonic() + ttl
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()


def _print_catalog_summary(catalog: dict[str, Any]) -> None:
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

__all__ = (
    "REPORT_HTTP_PORT",
    "REPORT_SERVER_MARKER",
    "REPORT_HTTP_DEFAULT_TTL",
    "_clip_cell",
    "_software_mode_meta",
    "_software_installer_display",
    "_software_parameters_display",
    "_software_detection_display",
    "_software_timeout_display",
    "_render_catalog_terminal_table",
    "_SENSITIVE_ARGUMENT_NAME",
    "_SENSITIVE_ARGUMENT_VALUE",
    "_SENSITIVE_ARGUMENT_PATTERNS",
    "VAULT_ARGUMENT_REFERENCE_RE",
    "_unquote_argument_value",
    "_literal_secret_argument_names",
    "validate_installer_arguments",
    "redact_sensitive_text",
    "_report_safe_arguments",
    "_html_badge",
    "_generate_catalog_html_report",
    "_local_ipv4_for_target",
    "_port_available_for_http",
    "_report_bind_ip",
    "_report_server_is_ours",
    "_catalog_report_bind_ip",
    "_catalog_report_ttl",
    "_ensure_catalog_report_server",
    "cmd_internal_report_serve",
    "_print_catalog_summary",
    "cmd_software_list",
    "cmd_software_show",
    "cmd_software_remove",
)
