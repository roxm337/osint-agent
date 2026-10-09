"""Tests for modules/business_logic.py.

Proof is differential — the total moved in the attacker's favour —
never 'the parameter exists'. Every probe is restored and the
restore verified; a silent server stays silent.
"""

import asyncio
import json
import tempfile

import modules.business_logic as logic_module
from modules.business_logic import BusinessLogic
from state.manager import StateManager


class FakeIdentity:
    def __init__(self, name="alice"):
        self.name = name
        self.cookies = {"session": "abc"}
        self.verified = True


class FakeShop:
    """Scripted carts keyed by endpoint. totals move only when told to."""

    def __init__(self, record=None, carts=None, accept=None):
        self.record = record if record is not None else {"name": "alice"}
        self.carts = carts if carts is not None else {}
        self.accept = accept if accept is not None else {}
        self.requests = []

    async def request(self, identity, url, method="GET", headers=None,
                      data=None):
        self.requests.append((method, url, data))
        if method == "GET" and url.endswith("/api/me"):
            return {"status": 200, "body": json.dumps(self.record)}
        if url in self.carts:
            cart = self.carts[url]
            if method == "GET":
                return {"status": 200, "body": json.dumps(cart)}
            try:
                payload = json.loads(data or "{}")
            except (TypeError, ValueError):
                payload = {}
            for field, hostile in payload.items():
                if field in self.accept.get(url, {}):
                    cart[field] = hostile
                    if field == "quantity":
                        cart["total"] = round(
                            cart.get("price", 10.0) * hostile, 2)
                    if field in ("price", "amount", "total"):
                        cart["total"] = hostile
            if payload == {"quantity": 1} or payload == {"items": []}:
                cart.update({"quantity": 1, "total": cart.get("price", 10.0),
                             "items": []})
            return {"status": 200, "body": json.dumps(cart)}
        if method == "GET":
            return {"status": 404, "body": ""}
        return {"status": 404, "body": ""}


class FakeHarness:
    def __init__(self, shop, identities):
        self._shop = shop
        self._identities = identities

    def adopt_discovered(self, state, log=None):
        return 0

    async def establish_all(self, base_url):
        return list(self._identities)

    async def request(self, identity, url, **kwargs):
        return await self._shop.request(identity, url, **kwargs)


def _run(monkeypatch, shop=None, identities=None, logic_cfg=None):
    tmpdir = tempfile.mkdtemp()
    state = StateManager(f"{tmpdir}/run/example.com")
    shop = shop if shop is not None else FakeShop()
    identities = identities if identities is not None else [FakeIdentity()]
    config = {"target": {"domain": "example.com",
                         "base_url": "https://example.com"},
              "modules": {"business_logic": dict(logic_cfg or {})}}
    monkeypatch.setattr(logic_module, "AuthHarness",
                        lambda config: FakeHarness(shop, identities))
    result = asyncio.run(BusinessLogic(state, config).run())
    return result, state, shop


def test_surface_lists_privilege_fields(monkeypatch):
    shop = FakeShop(record={"name": "alice", "role": "user",
                            "credits": 100})
    result, state, _ = _run(monkeypatch, shop=shop)

    assert result == "done"
    notes = [f for f in state.findings["findings"]
             if f["title"].startswith("Mass-assignment surface")]
    assert len(notes) == 1
    assert notes[0]["severity"] == "INFO"
    assert "role" in notes[0]["description"]
    assert "credits" in notes[0]["description"]


def test_surface_without_fields_files_nothing(monkeypatch):
    result, state, _ = _run(monkeypatch)

    assert result == "done"
    assert state.findings["findings"] == []
    assets = state.get_assets_by_type("logic_surface")
    assert assets and assets[0]["attrs"]["privilege_fields"] == []


def test_negative_quantity_accepted(monkeypatch):
    cart_url = "https://example.com/api/cart"
    shop = FakeShop(carts={cart_url: {"items": [{"sku": "a"}],
                                          "quantity": 1, "price": 10.0,
                                          "total": 10.0}},
                    accept={cart_url: {"quantity"}})
    result, state, shop = _run(monkeypatch, shop=shop)

    assert result == "done"
    flaws = [f for f in state.findings["findings"]
             if f["title"].startswith("Cart logic flaw")]
    labels = {f["title"] for f in flaws}
    # Zero and negative quantities collapse the total; bulk scales it,
    # so bulk is correctly not flagged.
    assert any("zero-quantity" in t for t in labels)
    assert any("negative-quantity" in t for t in labels)
    assert not any("bulk-quantity" in t for t in labels)
    for flaw in flaws:
        assert flaw["severity"] == "HIGH"
        assert flaw["confidence"] == "CONFIRMED"
        assert flaw["verified"] is True
    # Restored afterwards: quantity back to 1, total back to price.
    assert shop.carts[cart_url]["quantity"] == 1
    assert shop.carts[cart_url]["total"] == 10.0


def test_rejected_tamper_stays_silent(monkeypatch):
    cart_url = "https://example.com/api/cart"
    shop = FakeShop(carts={cart_url: {"items": [{"sku": "a"}],
                                          "quantity": 1, "price": 10.0,
                                          "total": 10.0}},
                    accept={})
    result, state, _ = _run(monkeypatch, shop=shop)

    assert result == "done"
    assert [f for f in state.findings["findings"]
            if f["title"].startswith("Cart logic flaw")] == []


def test_leftover_introduced_key_fails_restore_openly(monkeypatch):
    """A probe key the baseline never had (amount) that survives the
    replay is residue a later item could inherit — the restore must
    report unverified so the account is checked by hand."""

    cart_url = "https://example.com/api/cart"
    # The server keeps the introduced amount key forever: the replay
    # restores baseline fields but cannot delete what the API has no
    # delete for.
    shop = FakeShop(carts={cart_url: {"quantity": 1, "price": 10.0,
                                      "total": 10.0}},
                    accept={cart_url: {"quantity": -1, "amount": 0.01}})
    result, state, shop = _run(monkeypatch, shop=shop,
                               logic_cfg={"max_probes": 6})

    flaws = [f for f in state.findings["findings"]
             if f["title"].startswith("Cart logic flaw")]
    assert flaws, "expected at least one tamper finding"
    assert any("could NOT be restored" in f["description"] for f in flaws), \
        "residue must be disclosed, not reported clean"
    assert result == "done"


def test_max_probes_caps_volume(monkeypatch):
    cart_url = "https://example.com/api/cart"
    shop = FakeShop(carts={cart_url: {"quantity": 1, "price": 10.0,
                                      "total": 10.0}},
                    accept={cart_url: {"quantity"}})
    result, state, shop = _run(monkeypatch, shop=shop,
                               logic_cfg={"max_probes": 2})

    posts = [r for r in shop.requests if r[0] == "POST"]
    assert len(posts) <= 6, \
        "restore traffic must stay proportional to the probe cap"
    assert result == "done"


def test_no_identity_skips(monkeypatch):
    result, state, _ = _run(monkeypatch, identities=[])

    assert result == "skipped"
    assert state.findings["findings"] == []


def test_disabled_by_config(monkeypatch):
    result, state, _ = _run(monkeypatch, logic_cfg={"enabled": False})

    assert result == "skipped"
