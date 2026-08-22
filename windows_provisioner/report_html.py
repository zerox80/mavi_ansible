# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""HTML-Berichte und lokaler Berichtsserver.

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
    secrets,
    shutil,
    socket,
    subprocess,
    sys,
    time,
    urllib,
    yaml,
)

from .report_security import REPORT_HTTP_DEFAULT_TTL


REPORT_HTTP_PORT = 8765
REPORT_SERVER_MARKER = "Mavi-PROVISION-REPORT-SERVER-v1"


def _html_badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge {html.escape(kind)}">{html.escape(str(text))}</span>'


def _generate_catalog_html_report(project: Path, catalog_name: str, catalog: dict[str, Any], default_name: str) -> Path:
    from .reports import (
        _html_badge,
        _report_safe_arguments,
        _software_detection_display,
        _software_installer_display,
        _software_mode_meta,
        _software_parameters_display,
        _software_timeout_display,
    )

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
    from .reports import (
        _local_ipv4_for_target,
    )

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


def _ensure_catalog_report_server(
    project: Path,
    report_path: Path,
    *,
    bind: str = "loopback",
    port: int = REPORT_HTTP_PORT,
    ttl: int = REPORT_HTTP_DEFAULT_TTL,
) -> tuple[str | None, str | None]:


    from .reports import (
        _catalog_report_bind_ip,
        _catalog_report_ttl,
        _port_available_for_http,
        _report_server_is_ours,
    )

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
                "-m",
                "windows_provisioner",
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
