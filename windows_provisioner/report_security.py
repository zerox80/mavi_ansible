# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Sicherer Reportserver und Schutz sensibler Argumente."""

from __future__ import annotations


from ._dependencies import (
    Any,
    Path,
    argparse,
    ipaddress,
    os,
    re,
    time,
    urllib,
)


REPORT_HTTP_DEFAULT_TTL = 300


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

    from .reports import (
        _SENSITIVE_ARGUMENT_PATTERNS,
        redact_sensitive_text,
    )
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


def _catalog_report_bind_ip(project: Path, requested: str) -> str:
    """
    HTTP-Berichte binden standardmäßig ausschließlich an Loopback. Eine
    private LAN-Adresse erfordert die explizite Auswahl ``lan`` oder die
    Angabe einer konkreten privaten Adresse. Wildcard/public binds werden
    auch bei Opt-in abgelehnt.
    """

    from .reports import (
        _report_bind_ip,
    )
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


def cmd_internal_report_serve(args: argparse.Namespace) -> None:
    """Interner, zeitlich begrenzter Einzeldatei-Server ohne Verzeichnislisting."""

    from .reports import (
        REPORT_SERVER_MARKER,
    )
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
