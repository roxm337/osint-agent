"""Target knowledge packs: lab facts live here, never in module code.

A module's hardcoded paths must be generic conventions ("/login",
"/admin", ".bak") that hold on any target. Anything known about ONE
specific application — Juice Shop's REST paths, its backup filenames,
its default credentials — belongs in a pack YAML under knowledge/,
loaded explicitly for lab/benchmark runs and invisible otherwise.

Packs merge into the standard module-config namespaces, so modules
need no pack-aware code: they already read
`config["modules"][id]` / `config["misconfig"]` style keys, and the
pack just adds `extra_*` entries beside operator config.
"""

from pathlib import Path

PACK_DIR = Path(__file__).resolve().parent


def load_pack(name: str) -> dict:
    """Load a knowledge pack by name (without .yaml)."""
    import yaml
    path = PACK_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"unknown knowledge pack: {name} ({path})")
    with open(path) as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"knowledge pack {name} must be a mapping")
    return data


def apply_pack(config: dict, pack: dict) -> dict:
    """Merge a pack's `modules` section into a config dict, in place.

    Lists concatenate (pack entries appended after operator entries),
    scalars and mappings in the pack fill only keys the operator did
    not set. Returns the same config object.
    """
    modules = pack.get("modules") or {}
    if not isinstance(modules, dict):
        return config
    for module_id, values in modules.items():
        if not isinstance(values, dict):
            continue
        # Top-level module namespaces (misconfig:, xss:, ...) vs the
        # generic modules: {id:} namespace — mirror both.
        targets = []
        if module_id in config and isinstance(config[module_id], dict):
            targets.append(config[module_id])
        modules_cfg = config.setdefault("modules", {})
        if isinstance(modules_cfg, dict):
            targets.append(modules_cfg.setdefault(module_id, {}))
        for target in targets:
            for key, value in values.items():
                if isinstance(value, list):
                    existing = target.get(key)
                    if not isinstance(existing, list):
                        target[key] = list(value)
                    else:
                        target[key] = existing + [
                            item for item in value if item not in existing]
                elif key not in target:
                    target[key] = value
    # Wordlists merge the same way: pack words append to the operator's.
    wordlists = pack.get("wordlists") or {}
    if isinstance(wordlists, dict):
        dest = config.setdefault("wordlists", {})
        if isinstance(dest, dict):
            for key, value in wordlists.items():
                if isinstance(value, list):
                    existing = dest.get(key)
                    if not isinstance(existing, list):
                        dest[key] = list(value)
                    else:
                        dest[key] = existing + [
                            item for item in value if item not in existing]
    return config


def list_packs() -> list:
    """Names of available packs."""
    return sorted(path.stem for path in PACK_DIR.glob("*.yaml")
                  if path.is_file())
