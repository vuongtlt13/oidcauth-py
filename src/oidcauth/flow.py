"""The encrypted login flow cookie."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config
from .errors import InvalidStateError

_NONCE_SIZE = 12


@dataclass
class Cookie:
    """A cookie for the web framework to set, e.g. the flow cookie of
    Client.start. Framework adapters copy it onto their response."""

    name: str
    value: str
    path: str = "/"
    # Seconds; negative deletes the cookie.
    max_age: int = 0
    http_only: bool = True
    secure: bool = True
    # "lax", "strict" or "none".
    same_site: str = "lax"
    # Unix time of an Expires attribute, if any.
    expires: int | None = None


@dataclass
class Flow:
    """Per-login state kept in the browser between start and finish. It is
    sealed with AES-256-GCM (confidential + tamper-proof) and bound to the state
    value as additional data, so a cookie cannot be replayed for another
    state."""

    state: str
    nonce: str
    verifier: str
    return_to: str = ""
    # Space-separated scope sent, the fallback for the granted scope when the
    # token response omits it (RFC 6749, section 5.1).
    scope: str = ""
    # When the login started (unix); max_age is measured from it.
    issued_at: int = 0
    # max_age sent, in seconds; auth_time is then required.
    max_age: int | None = None
    # acr_values the ID token acr must match (Config.require_acr).
    acr: list[str] = field(default_factory=list)
    expires_at: int = 0

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"s": self.state, "n": self.nonce, "v": self.verifier}
        if self.return_to:
            out["r"] = self.return_to
        if self.scope:
            out["sc"] = self.scope
        out["i"] = self.issued_at
        if self.max_age is not None:
            out["m"] = self.max_age
        if self.acr:
            out["a"] = self.acr
        out["e"] = self.expires_at
        return out

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Flow:
        m = d.get("m")
        return cls(
            state=str(d["s"]),
            nonce=str(d["n"]),
            verifier=str(d["v"]),
            return_to=str(d.get("r", "")),
            scope=str(d.get("sc", "")),
            issued_at=int(d.get("i", 0)),
            max_age=None if m is None else int(m),
            acr=[str(a) for a in d.get("a") or []],
            expires_at=int(d["e"]),
        )


class FlowCodec:
    def __init__(self, cfg: Config, now: Callable[[], float] = time.time) -> None:
        key = hashlib.sha256(
            b"oidcauth/flow/v1\x00" + cfg.cookie_secret.encode()
        ).digest()
        self._aead = AESGCM(key)
        self._prefix = cfg.cookie_name
        self._path = cfg.cookie_path
        self._insecure = cfg.cookie_insecure
        assert cfg.flow_ttl is not None
        self._ttl = int(cfg.flow_ttl.total_seconds())
        self.now = now

    def name(self, state: str) -> str:
        """Per-state cookie name, so parallel logins in several tabs do not
        overwrite each other."""
        return self._prefix + "_" + hashlib.sha256(state.encode()).digest()[:6].hex()

    def encode(self, f: Flow, cross_site_post: bool = False) -> Cookie:
        """Seals f. cross_site_post marks a form_post login: the provider POSTs
        the callback cross-site, which a SameSite=Lax cookie does not
        survive."""
        f.expires_at = int(self.now()) + self._ttl
        plain = json.dumps(f.to_json(), separators=(",", ":")).encode()
        nonce = os.urandom(_NONCE_SIZE)
        sealed = nonce + self._aead.encrypt(nonce, plain, f.state.encode())
        ck = self._cookie(self.name(f.state), _b64encode(sealed), self._ttl)
        if cross_site_post:
            ck.same_site = "none"
            ck.secure = True  # browsers drop SameSite=None cookies without Secure
        return ck

    def decode(self, state: str, value: str) -> Flow:
        try:
            sealed = _b64decode(value.strip())
            if len(sealed) < _NONCE_SIZE:
                raise ValueError("short")
            plain = self._aead.decrypt(
                sealed[:_NONCE_SIZE], sealed[_NONCE_SIZE:], state.encode()
            )
            f = Flow.from_json(json.loads(plain))
        except (ValueError, KeyError, TypeError, InvalidTag, binascii.Error):
            raise InvalidStateError() from None
        if not hmac.compare_digest(f.state.encode(), state.encode()):
            raise InvalidStateError()
        if int(self.now()) > f.expires_at:
            raise InvalidStateError()
        return f

    def clear(self, state: str) -> Cookie:
        ck = self._cookie(self.name(state), "", -1)
        ck.expires = 0
        return ck

    def _cookie(self, name: str, value: str, max_age: int) -> Cookie:
        # HttpOnly and SameSite=Lax: Lax (not Strict) is required because the
        # callback is a top-level cross-site navigation from the provider back
        # to the app.
        return Cookie(
            name=name,
            value=value,
            path=self._path,
            max_age=max_age,
            http_only=True,
            secure=not self._insecure,
            same_site="lax",
        )


def random_token() -> str:
    return secrets.token_urlsafe(32)


def _b64encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64decode(s: str) -> bytes:
    if not s or any(c in s for c in "=+/"):
        raise ValueError("not raw base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
