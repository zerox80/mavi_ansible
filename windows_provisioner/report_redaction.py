# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Redaktion sensibler Ausgaben.

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


def redact_sensitive_text(value: Any) -> str:
    """Zentrale Schwärzung für Pläne, Live-Ausgaben, Reports und Fehlertexte."""
    from .reports import (
        _SENSITIVE_ARGUMENT_NAME,
        _SENSITIVE_ARGUMENT_PATTERNS,
    )

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
    from .reports import (
        redact_sensitive_text,
    )

    return redact_sensitive_text(value)
