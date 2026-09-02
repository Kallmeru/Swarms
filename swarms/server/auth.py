"""API key authentication.

Keys come from the environment (`SWARMS_API_KEYS`, comma separated) or a keys
file, and are compared with a constant-time function so a timing side channel
cannot be used to recover one a character at a time.

With no keys configured the gateway runs open, which is right for a laptop
and wrong for anything else, so it warns loudly at startup, reports
`auth: disabled` on /api/health, and **refuses to start** when
`SWARMS_ENV=production`. A security control that quietly ships without
authentication is worse than none, because it is trusted.
"""
from __future__ import annotations

import hmac
import logging
import os
import secrets
from dataclasses import dataclass

from fastapi import Header, HTTPException, Request

log = logging.getLogger("swarms.auth")

ROLE_ADMIN = "admin"
ROLE_SERVICE = "service"
ROLE_VIEWER = "viewer"


@dataclass(frozen=True)
class ApiKey:
    key: str
    name: str
    role: str = ROLE_SERVICE

    @property
    def can_write(self) -> bool:
        return self.role in (ROLE_ADMIN, ROLE_SERVICE)

    @property
    def can_admin(self) -> bool:
        return self.role == ROLE_ADMIN


class KeyRing:
    def __init__(self, keys: list[ApiKey] | None = None):
        self.keys = list(keys or [])

    @property
    def enabled(self) -> bool:
        return bool(self.keys)

    @classmethod
    def from_env(cls) -> "KeyRing":
        """`SWARMS_API_KEYS=secret1:alice:admin,secret2:svc:service`

        The name and role are optional; a bare key gets the service role,
        which can decide and record but cannot resolve approvals or reload
        policy.
        """
        raw = os.environ.get("SWARMS_API_KEYS", "").strip()
        keys: list[ApiKey] = []
        for entry in (e.strip() for e in raw.split(",")):
            if not entry:
                continue
            parts = entry.split(":")
            secret = parts[0].strip()
            if not secret:
                continue
            name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "unnamed"
            role = parts[2].strip() if len(parts) > 2 and parts[2].strip() else ROLE_SERVICE
            if role not in (ROLE_ADMIN, ROLE_SERVICE, ROLE_VIEWER):
                raise ValueError(f"SWARMS_API_KEYS: unknown role {role!r} for key '{name}'")
            keys.append(ApiKey(key=secret, name=name, role=role))
        return cls(keys)

    def match(self, presented: str | None) -> ApiKey | None:
        if not presented:
            return None
        # Every key is compared even after a match, so the time taken does not
        # reveal the position of the matching key in the ring.
        found: ApiKey | None = None
        for candidate in self.keys:
            if hmac.compare_digest(candidate.key, presented):
                found = candidate
        return found


def generate_key() -> str:
    return "swk_" + secrets.token_urlsafe(32)


def startup_check(ring: KeyRing) -> None:
    if ring.enabled:
        log.info("API authentication enabled (%d key(s))", len(ring.keys))
        return
    if os.environ.get("SWARMS_ENV", "").lower() in ("production", "prod"):
        raise RuntimeError(
            "SWARMS_ENV=production but no API keys are configured. Set SWARMS_API_KEYS "
            "(generate one with: swarms keygen), or unset SWARMS_ENV for local use."
        )
    log.warning(
        "No API keys configured: every endpoint is open. Fine on a laptop, not anywhere else. "
        "Set SWARMS_API_KEYS before exposing this."
    )


def _extract(authorization: str | None, x_api_key: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return x_api_key


def make_dependencies(ring: KeyRing):
    """Build the auth dependencies against one key ring.

    A factory rather than module-level functions so tests and embedded uses
    can supply their own ring instead of mutating the environment.
    """

    def principal(
        request: Request,
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ) -> ApiKey:
        if not ring.enabled:
            return ApiKey(key="", name="anonymous", role=ROLE_ADMIN)
        matched = ring.match(_extract(authorization, x_api_key))
        if matched is None:
            raise HTTPException(
                401, "missing or invalid API key: send it as 'Authorization: Bearer <key>'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        request.state.api_key_name = matched.name
        return matched

    def writer(key: ApiKey = None) -> ApiKey:  # type: ignore[assignment]
        if not key.can_write:
            raise HTTPException(403, f"key '{key.name}' has role '{key.role}', which is read-only")
        return key

    def admin(key: ApiKey = None) -> ApiKey:  # type: ignore[assignment]
        if not key.can_admin:
            raise HTTPException(403, f"key '{key.name}' has role '{key.role}', admin required")
        return key

    return principal, writer, admin
