"""Tests for how `-c` layers a file over `config.yaml`.

`-c` used to *replace* the whole configuration. The file an operator writes
for a scoped run carries only what differs — two identities, a rate limit —
and passing it deleted every wordlist, threshold and module switch in the
product. Measured consequences on the benchmark target: `misconfig_probes`
logged "Checking 0 of 0 paths" and `content_discovery` skipped its wordlist,
both as green completions, because the config no longer held the lists they
read. The suite stayed green because nothing asserts that a module was given
any work.

These tests load configs directly rather than running the pipeline: the
behaviour under test is in `_load_config`, and a green pipeline run proved
nothing about it.
"""

import yaml

from orchestrator import Orchestrator, _deep_merge


def _loader():
    """A loader with no orchestrator wired up around it.

    `__init__` builds state directories and normalises the target; none of
    that is what these tests are about.
    """
    return object.__new__(Orchestrator)


def _write(tmp_path, payload, name="override.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(payload))
    return str(p)


def test_a_partial_config_keeps_the_product_wordlists(tmp_path):
    """The defect itself: identities in, wordlists must not go out."""
    path = _write(tmp_path, {
        "target": {"domain": "localhost"},
        "auth": {"identities": [{"name": "alice", "bearer_token": "t"}]},
    })
    cfg = _loader()._load_config(path)
    assert cfg["auth"]["identities"][0]["name"] == "alice"
    assert cfg["wordlists"]["misconfig_paths"], \
        "a partial config must not delete the wordlists it never mentions"
    assert cfg["wordlists"]["high_risk_ports"], \
        "port_scan reads the same list; it should not lose it either"


def test_the_override_wins_where_it_speaks(tmp_path):
    """Merging must not average: a list of identities is taken whole."""
    path = _write(tmp_path, {
        "auth": {"identities": [{"name": "bob"}]},
        "rate_limits": {"http": {"per_minute": 3000}},
    })
    cfg = _loader()._load_config(path)
    assert cfg["auth"]["identities"] == [{"name": "bob"}], \
        "an identity list must be replaced, not unioned with config.yaml's"
    assert cfg["rate_limits"]["http"]["per_minute"] == 3000
    assert cfg["rate_limits"]["http"]["concurrent"], \
        "keys the override does not touch still come from config.yaml"


def test_the_default_config_is_not_merged_with_itself(tmp_path, monkeypatch):
    """`-c config.yaml` is the default invocation; merging it onto itself has
    to be a no-op rather than a recursion or a doubling."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"target": {"domain": "example.test"},
                        "wordlists": {"misconfig_paths": ["/.env"]}}))
    cfg = _loader()._load_config("config.yaml")
    assert cfg["wordlists"]["misconfig_paths"] == ["/.env"]
    assert cfg["target"]["domain"] == "example.test"


def test_an_absent_config_file_falls_back_to_config_yaml(tmp_path, monkeypatch):
    """A typo in `-c` used to fall through to the five-key hard-coded default,
    which is how a run silently loses its wordlists too."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"target": {"domain": "example.test"},
                        "wordlists": {"misconfig_paths": ["/.env"]}}))
    cfg = _loader()._load_config(str(tmp_path / "nope.yaml"))
    assert cfg["wordlists"]["misconfig_paths"] == ["/.env"]


def test_deep_merge_takes_scalars_and_lists_from_the_override():
    base = {"a": {"b": 1, "c": [1, 2]}, "d": "keep"}
    out = _deep_merge(base, {"a": {"b": 9, "c": [3]}})
    assert out == {"a": {"b": 9, "c": [3]}, "d": "keep"}
    assert base == {"a": {"b": 1, "c": [1, 2]}, "d": "keep"}, \
        "merging must not mutate the config it merged over"
