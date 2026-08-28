"""Runtime configuration, read once from the environment at startup.

Two rules shape this module. Secrets are read from files rather than inline environment
values wherever a file will do, so a passphrase never appears in ``/proc/<pid>/environ``
or in a systemd unit that anyone can read. And the upstream origin is validated against a
compiled-in allowlist rather than trusted from the environment, so no configuration
mistake — and no compromise of the environment — can point this node's outbound traffic
at a host it was never meant to reach.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: The only origins this node will ever make an outbound request to. Compiled in on
#: purpose: an SSRF guard that reads its own allowlist from attacker-influenced input is
#: not a guard. `TCN_TECHNOCORE_ORIGIN` may *choose* among these, never extend them.
ALLOWED_ORIGINS = frozenset(
    {
        "https://technocore.chat",
        "http://127.0.0.1:8080",  # a locally self-hosted instance, for development
    }
)

DEFAULT_ORIGIN = "https://technocore.chat"

#: Origins the protocol watcher may additionally read, for provenance only. Listed here
#: rather than hardcoded at the call site so that "everything this node can reach" is one
#: readable set — a containment guarantee split across two files is one nobody can check.
WATCHER_ORIGINS = frozenset({"https://api.github.com"})

#: Every origin this process may contact, from anywhere.
ALL_ALLOWED_ORIGINS = ALLOWED_ORIGINS | WATCHER_ORIGINS


def assert_allowed_origin(url: str, permitted: frozenset[str] | None = None) -> None:
    """Raise unless `url` sits under an allowlisted origin.

    Matching is on the parsed scheme/host/port, never on a prefix: `https://technocore.chat`
    is a prefix of `https://technocore.chat.attacker.example`, and a startswith check would
    wave that through.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if origin not in (permitted if permitted is not None else ALL_ALLOWED_ORIGINS):
        raise ConfigError(f"outbound request to {origin!r} is not allowlisted")


#: Addresses the service may bind. The documentation says loopback-only and this is what
#: makes that true: the node runs beside unrelated services on a shared host, and its API
#: is meant to be reached through a reverse proxy, never directly. A promise enforced only
#: by a default is not enforced.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class ConfigError(ValueError):
    """Configuration that cannot be honoured safely."""


def _public_url(raw: str) -> str:
    """The advertised public URL, or empty when there genuinely is not one.

    Stripped before it is judged, because a safety gate asks `if not public_url` and a
    value of `"   "` is true. Configuration that is *almost* blank must read as blank, or
    a whitespace typo silently opens a gate that was written to stay shut.

    A non-empty value must be an https:// origin: a requester who cannot fetch the
    receipt back over a channel they can trust has no way to verify it, so http:// or a
    bare hostname is refused rather than advertised.
    """
    url = raw.strip().rstrip("/")
    if not url:
        return ""
    if not url.startswith("https://") or len(url) <= len("https://"):
        raise ConfigError(
            f"TCN_PUBLIC_URL={raw!r} is not an https:// URL. Leave it empty if there is "
            "no public endpoint yet; the node reports that honestly and declines work."
        )
    return url


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, *, minimum: int = 1, maximum: int = 10**9) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    identity_path: Path
    identity_passphrase_file: Path | None
    state_dir: Path
    db_path: Path
    bind_host: str
    bind_port: int
    public_url: str
    origin: str
    mailbox_enabled: bool
    watcher_enabled: bool
    max_concurrent_jobs: int
    job_timeout_seconds: int
    requester_jobs_per_hour: int
    flop_testnet_enabled: bool

    def passphrase(self) -> bytes | None:
        """The key passphrase, read from disk at the moment it is needed.

        Returned as bytes and never cached on the instance: the caller decrypts with it
        and drops it. `TCN_IDENTITY_PASSPHRASE` is honoured as a fallback for containers
        that have no writable path for a file, and is documented as the weaker option.
        """
        if self.identity_passphrase_file is not None:
            return self.identity_passphrase_file.read_bytes().strip() or None
        inline = os.environ.get("TCN_IDENTITY_PASSPHRASE")
        return inline.encode("utf-8") if inline else None


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Build :class:`Settings` from the process environment (or `env`, for tests)."""
    source = os.environ if env is None else env
    if env is not None:
        os.environ.update(env)

    origin = source.get("TCN_TECHNOCORE_ORIGIN", DEFAULT_ORIGIN).rstrip("/")
    if origin not in ALLOWED_ORIGINS:
        raise ConfigError(
            f"TCN_TECHNOCORE_ORIGIN={origin!r} is not in this build's allowlist. "
            "Outbound requests are restricted to a compiled-in set of origins."
        )

    bind_host = source.get("TCN_BIND_HOST", "127.0.0.1")
    if bind_host not in LOOPBACK_HOSTS:
        raise ConfigError(
            f"TCN_BIND_HOST={bind_host!r} is not a loopback address. This service binds "
            "loopback only and is exposed through a reverse proxy; see "
            "deploy/Caddyfile.example."
        )

    state_dir = Path(source.get("TCN_STATE_DIR", "/var/lib/technocore-agent"))
    passfile = source.get("TCN_IDENTITY_PASSPHRASE_FILE", "").strip()

    return Settings(
        identity_path=Path(source.get("TCN_IDENTITY_PATH", "/etc/technocore-agent/identity.pem")),
        identity_passphrase_file=Path(passfile) if passfile else None,
        state_dir=state_dir,
        db_path=Path(source.get("TCN_DB_PATH", str(state_dir / "state.db"))),
        bind_host=bind_host,
        bind_port=_int("TCN_BIND_PORT", 3020, minimum=1, maximum=65535),
        public_url=_public_url(source.get("TCN_PUBLIC_URL", "")),
        origin=origin,
        mailbox_enabled=_flag("TCN_MAILBOX_ENABLED", True),
        watcher_enabled=_flag("TCN_WATCHER_ENABLED", True),
        max_concurrent_jobs=_int("TCN_MAX_CONCURRENT_JOBS", 2, minimum=1, maximum=32),
        job_timeout_seconds=_int("TCN_JOB_TIMEOUT_SECONDS", 15, minimum=1, maximum=120),
        requester_jobs_per_hour=_int("TCN_REQUESTER_JOBS_PER_HOUR", 60, minimum=1, maximum=10000),
        flop_testnet_enabled=_flag("FLOP_TESTNET_ENABLED", False),
    )
