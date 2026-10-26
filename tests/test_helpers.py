from __future__ import annotations

from datetime import datetime, timedelta, timezone

import fakeredis
import pytest
from conftest import COOKIE_SECRET

from oidcauth import (
    Config,
    InvalidStateError,
    MemoryTicketStore,
    RedisTicketStore,
    TicketNotFoundError,
    default_role_extractor,
    safe_return_to,
)
from oidcauth.flow import Flow, FlowCodec
from oidcauth.identity import identity_from_claims


@pytest.mark.parametrize(
    "raw,want",
    [
        ("/jobs", "/jobs"),
        ("/jobs?x=1#top", "/jobs?x=1#top"),
        ("", "/"),
        (None, "/"),
        ("jobs", "/"),
        ("//evil.com", "/"),
        ("/\\evil.com", "/"),
        ("https://evil.com/", "/"),
        ("/ok\r\nSet-Cookie: a=b", "/"),
        ("javascript:alert(1)", "/"),
    ],
)
def test_safe_return_to(raw: str | None, want: str) -> None:
    assert safe_return_to(raw) == want


async def test_memory_ticket_store() -> None:
    s = MemoryTicketStore()
    ticket = await s.put("token-1", timedelta(minutes=1))
    assert await s.take(ticket) == "token-1"
    with pytest.raises(TicketNotFoundError):
        await s.take(ticket)

    now = 1_000_000.0
    s.now = lambda: now
    ticket = await s.put("token-2", 1)
    s.now = lambda: now + 2
    with pytest.raises(TicketNotFoundError):
        await s.take(ticket)


async def test_redis_ticket_store() -> None:
    s = RedisTicketStore(fakeredis.FakeAsyncRedis(), prefix="t:")
    ticket = await s.put("token-1", timedelta(minutes=1))
    assert await s.take(ticket) == "token-1"
    with pytest.raises(TicketNotFoundError):
        await s.take(ticket)
    with pytest.raises(TicketNotFoundError):
        await s.take("")


def test_default_role_extractor() -> None:
    got = default_role_extractor(
        {
            "urn:zitadel:iam:org:project:roles": {"admin": {}},
            "urn:zitadel:iam:org:project:123:roles": {"viewer": {}, "admin": {}},
            "roles": ["ignored-when-zitadel-present"],
        }
    )
    assert got == ["admin", "viewer"]
    got = default_role_extractor({"roles": ["b", "a"], "groups": ["a", "c"]})
    assert got == ["a", "b", "c"]
    assert default_role_extractor({}) == []


def test_flow_cookie_expires() -> None:
    cfg = Config(cookie_secret=COOKIE_SECRET).with_defaults()
    now = 1_000_000.0
    codec = FlowCodec(cfg, lambda: now)
    ck = codec.encode(Flow(state="s", nonce="n", verifier="v"))
    assert codec.decode("s", ck.value).nonce == "n"
    with pytest.raises(InvalidStateError):
        codec.decode("other", ck.value)
    assert cfg.flow_ttl is not None
    codec.now = lambda: now + cfg.flow_ttl.total_seconds() + 1  # type: ignore[union-attr]
    with pytest.raises(InvalidStateError):
        codec.decode("s", ck.value)
    clear = codec.clear("s")
    assert clear.name == ck.name and clear.max_age < 0 and clear.value == ""


def test_flow_cookie_form_post_is_same_site_none() -> None:
    cfg = Config(cookie_secret=COOKIE_SECRET, cookie_insecure=True).with_defaults()
    ck = FlowCodec(cfg).encode(
        Flow(state="s", nonce="n", verifier="v"), cross_site_post=True
    )
    assert ck.same_site == "none" and ck.secure


def test_identity_email_verified_string() -> None:
    id = identity_from_claims(
        {"sub": "1", "email_verified": "true"}, default_role_extractor
    )
    assert id.email_verified
    assert id.display_name() == "1"


def test_identity_standard_claims() -> None:
    claims = {
        "sub": "1",
        "middle_name": "M",
        "nickname": "nick",
        "profile": "https://p",
        "website": "https://w",
        "gender": "female",
        "birthdate": "1990-01-02",
        "zoneinfo": "Asia/Ho_Chi_Minh",
        "locale": "vi-VN",
        "updated_at": 1700000000.0,
        "phone_number": "+84 900000000",
        "phone_number_verified": True,
        "address": {"locality": "Ha Noi", "country": "VN"},
        "auth_time": 1700000100,
        "acr": "urn:mfa",
        "amr": ["pwd", "otp"],
        "sid": "sess-1",
    }
    id = identity_from_claims(claims, default_role_extractor)
    assert (id.middle_name, id.nickname, id.profile, id.website) == (
        "M",
        "nick",
        "https://p",
        "https://w",
    )
    assert (id.gender, id.birthdate, id.zoneinfo, id.locale) == (
        "female",
        "1990-01-02",
        "Asia/Ho_Chi_Minh",
        "vi-VN",
    )
    assert id.updated_at == datetime.fromtimestamp(1700000000, tz=timezone.utc)
    assert id.auth_time == datetime.fromtimestamp(1700000100, tz=timezone.utc)
    assert id.phone_number == "+84 900000000" and id.phone_number_verified
    assert id.address is not None
    assert (id.address.locality, id.address.country) == ("Ha Noi", "VN")
    assert (id.acr, id.amr, id.session_id) == ("urn:mfa", ["pwd", "otp"], "sess-1")
    assert id.display_name() == "nick"

    a = identity_from_claims({"address": "12 Pho Hue"}, default_role_extractor).address
    assert a is not None and a.formatted == "12 Pho Hue"
    assert identity_from_claims({"address": {}}, default_role_extractor).address is None
