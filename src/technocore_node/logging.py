"""Structured JSON logging, with a redaction filter that fails safe.

The node handles a private key passphrase and reads world-writable strangers' text. Both
are reasons to keep the log line shape boring: one JSON object per line, no interpolation
of untrusted values into the message field, and a filter that blanks anything shaped like
a secret before it reaches a handler.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

#: Patterns that must never reach a log line, however they got into the record.
_REDACT_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    # Order matters. The scheme-plus-token rules run before the generic key/value rule,
    # because the generic one stops at whitespace: matched first, it would blank the words
    # `Authorization: Bearer` and leave the token itself sitting in the log line.
    re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/-]{8,}=*"),
    re.compile(r"(?i)[\"']?\bauthorization\b[\"']?\s*[=:]\s*[\"']?[^\"',}\]\n]+"),
    # `"token": "..."` as well as `token=...`: the optional quote around the key name is
    # what makes the JSON-encoded form match. Without it a credential inside a serialised
    # object passes straight through, which is the shape most likely to be logged.
    re.compile(
        r"(?i)[\"']?\b(pass(phrase|word)?|secret|token|api[_-]?key|access[_-]?token"
        r"|client[_-]?secret|refresh[_-]?token)\b[\"']?\s*[=:]\s*[\"']?[^\s\"',}\]]+[\"']?"
    ),
]
_REDACTED = "[redacted]"


#: Field names whose value is blanked outright, whatever it looks like.
_SECRET_KEYS = re.compile(r"(?i)(pass(phrase|word)?|secret|token|api[_-]?key|private[_-]?key)")


def redact(text: str) -> str:
    """Blank anything shaped like a credential in `text`."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


def redact_value(value: Any) -> Any:
    """Redact a structure in place of its serialised form.

    Redacting the *encoded* JSON would be the obvious shortcut and is wrong: the patterns
    match greedily to the next whitespace, so blanking a value inside an encoded document
    swallows its closing quote and produces a log line that no longer parses. Walking the
    structure keeps the record machine-readable, which is the only reason it is JSON.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            k: (_REDACTED if isinstance(k, str) and _SECRET_KEYS.search(k) else redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact_value(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload["fields"] = redact_value(extra)
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure(level: str = "INFO") -> None:
    """Install the JSON formatter on the root logger. Idempotent."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
