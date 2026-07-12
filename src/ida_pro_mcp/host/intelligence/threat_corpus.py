"""
Threat corpus assembly — BRON-style normalization of CWE, MITRE ATT&CK, and
signature-base YARA data into a single JSON for the intelligence layer.

Sources:
  - CWE catalog (cwec_v4.x.xml, MITRE)
  - MITRE ATT&CK STIX bundles (enterprise / ics / mobile, JSON)
  - Florian Roth signature-base YARA rules (signature-base/yara/*.yar)

The parsed corpus is cached as a single JSON file under
CACHE_DIR/threat_corpus_v1.json. Lazy-loaded on first use; can be rebuilt
on demand via the ``intelligence(action="load_threat_taxonomy", rebuild=True)``
action or the ``download-bron-corpus`` installer subcommand.

The corpus is consumed by:
  - ``taint`` module signature patterns
  - ``intelligence(classify_threat)`` action
  - ``SecBertStaticEmbedder`` corpus selection (Phase 3)
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from ..config import CACHE_DIR

# ── Auto-download configuration ──────────────────────────────────────────────

_CWE_URL = os.environ.get(
    "IDA_MCP_CWE_URL",
    "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
)
_ATTACK_URLS = [
    os.environ.get(
        "IDA_MCP_ATTACK_ENTERPRISE_URL",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    ),
    os.environ.get(
        "IDA_MCP_ATTACK_ICS_URL",
        "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    ),
    os.environ.get(
        "IDA_MCP_ATTACK_MOBILE_URL",
        "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    ),
]
_YARA_URL = os.environ.get(
    "IDA_MCP_YARA_URL",
    "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
)
_YARA_SUBPATH = "signature-base-master/yara"

_DOWNLOAD_TIMEOUT = int(os.environ.get("IDA_MCP_DOWNLOAD_TIMEOUT", "120"))
_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024  # 256 MB

__all__ = [
    "ThreatCorpus",
    "CORPUS_VERSION",
    "CORPUS_CACHE_FILENAME",
    "CORPUS_CACHE_DIR",
    "MANIFEST_PATH",
    "corpus_cache_path",
    "load_corpus",
    "save_corpus",
    "delete_corpus_cache",
    "ensure_corpus_loaded",
    "build_corpus_from_sources",
    "download_corpus_sources",
    "invalidate_corpus_cache",
    "parse_cwe_xml",
    "parse_attack_stix",
    "parse_yara_dir",
    "compute_source_fingerprint",
    "_download_url",
]

CORPUS_VERSION = 1
CORPUS_CACHE_FILENAME = f"threat_corpus_v{CORPUS_VERSION}.json"
_CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

_CWE_DESCRIPTION_MAX = 1500
_CWE_BACKGROUND_MAX = 1000
_CWE_PLATFORMS_MAX = 24
_CWE_LANGUAGES_MAX = 16
_CWE_TECHNOLOGIES_MAX = 16
_YARA_STRING_MAX = 256
_YARA_RULE_FILE_MAX_BYTES = 1_000_000
_YARA_RULE_DIR_MAX_RULES = 4000
_CORPUS_CACHE_SAVE_MAX_BYTES = 64 * 1024 * 1024

_MAX_FIELD_LEN = 4000
_TRUNC_SUFFIX = "..."

_YARA_RULE_RE = re.compile(
    r"^\s*(?:private|global\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{",
    re.MULTILINE,
)
_YARA_META_KV_RE = re.compile(
    r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$',
    re.MULTILINE,
)
_YARA_STRINGS_SECTION_RE = re.compile(
    r"\bstrings\s*:\s*(.*?)\bcondition\s*:",
    re.DOTALL | re.IGNORECASE,
)
_YARA_STRING_LINE_RE = re.compile(
    r"\$\s*([A-Za-z0-9_]+)\s*(?:=\s*)?(.*?)$",
    re.MULTILINE,
)
_YARA_STRING_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

_ATTACK_OBJECT_TYPES = (
    "attack-pattern",
    "malware",
    "intrusion-set",
    "tool",
    "course-of-action",
)


def _clip(value: Any, max_len: int = _MAX_FIELD_LEN) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - len(_TRUNC_SUFFIX)] + _TRUNC_SUFFIX


def _coerce_str_list(value: Any, max_items: int = 32, item_max: int = 200) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    seen = set()
    for item in value:
        if item is None:
            continue
        s = str(item).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        if len(s) > item_max:
            s = s[:item_max]
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_cwe_xml(path: str) -> list[dict[str, Any]]:
    """Parse a CWE catalog XML file and return a list of normalized CWE entries."""
    if not path or not os.path.isfile(path):
        return []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return []
    root = tree.getroot()
    weaknesses = root.findall(".//cwe:Weakness", _CWE_NS)
    out: list[dict[str, Any]] = []
    for w in weaknesses:
        wid = w.get("ID")
        if not wid:
            continue
        if (w.get("Status") or "").strip().lower() in {"deprecated", "withdrawn"}:
            continue
        name_attr = (w.get("Name") or "").strip()
        name_el = w.find("cwe:Name", _CWE_NS)
        name_child = (name_el.text or "").strip() if name_el is not None and name_el.text else ""
        desc_el = w.find("cwe:Description", _CWE_NS)
        bg_el = w.find("cwe:Background_Details", _CWE_NS)
        abstraction = w.get("Abstraction") or ""
        structure = w.get("Structure") or ""
        description = _clip(desc_el.text if desc_el is not None and desc_el.text else "", _CWE_DESCRIPTION_MAX)
        background_parts: list[str] = []
        if bg_el is not None:
            for bgd in bg_el.findall("cwe:Background_Detail", _CWE_NS):
                if bgd.text:
                    background_parts.append(bgd.text.strip())
        background = _clip(" ".join(background_parts), _CWE_BACKGROUND_MAX)
        languages: list[str] = []
        technologies: list[str] = []
        platforms_el = w.find("cwe:Applicable_Platforms", _CWE_NS)
        if platforms_el is not None:
            for lang in platforms_el.findall("cwe:Language", _CWE_NS):
                if not lang.attrib:
                    name = lang.text.strip() if lang.text else ""
                else:
                    name = (
                        lang.attrib.get("Name")
                        or lang.attrib.get("Class")
                        or (lang.text or "").strip()
                    )
                if name and name.lower() not in {"not language-specific", "not technology-specific"}:
                    languages.append(name.strip())
                if len(languages) >= _CWE_LANGUAGES_MAX:
                    break
            for tech in platforms_el.findall("cwe:Technology", _CWE_NS):
                if not tech.attrib:
                    name = (tech.text or "").strip()
                else:
                    name = (
                        tech.attrib.get("Name")
                        or tech.attrib.get("Class")
                        or (tech.text or "").strip()
                    )
                if name and name.lower() not in {"not technology-specific"}:
                    technologies.append(name.strip())
                if len(technologies) >= _CWE_TECHNOLOGIES_MAX:
                    break
        scopes: list[str] = []
        cc_el = w.find("cwe:Common_Consequences", _CWE_NS)
        if cc_el is not None:
            for scope in cc_el.iter():
                local = _local_name(scope.tag)
                if local not in {"Scope", "Consequence_Scope", "Technical_Impact_Scope"}:
                    continue
                if scope.text:
                    s = scope.text.strip()
                    if s and s not in scopes:
                        scopes.append(s)
        entry = {
            "id": f"CWE-{wid}",
            "name": _clip(name_attr or name_child, 256),
            "abstraction": _clip(abstraction, 32),
            "structure": _clip(structure, 32),
            "description": description,
            "background": background,
            "languages": languages[:_CWE_LANGUAGES_MAX],
            "technologies": technologies[:_CWE_TECHNOLOGIES_MAX],
            "scopes": scopes[:12],
            "source": "cwe",
        }
        out.append(entry)
    return out


def _attack_external_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        if (ref.get("source_name") or "").lower() == "mitre-attack":
            eid = ref.get("external_id")
            if eid:
                return str(eid)
    return ""


def _attack_phases(obj: dict[str, Any]) -> list[str]:
    phases = obj.get("kill_chain_phases") or []
    out: list[str] = []
    for phase in phases:
        if isinstance(phase, dict):
            name = phase.get("phase_name")
            if name:
                out.append(str(name))
    return out



def parse_attack_stix(path: str) -> dict[str, list[dict[str, Any]]]:
    """Parse a MITRE ATT&CK STIX bundle and return normalized entries by type.

    Returns a dict with keys: attack_pattern, malware, intrusion_set, tool,
    course_of_action, plus a 'techniques_by_id' index for sub-technique
    traversal.
    """
    out: dict[str, list[dict[str, Any]]] = {
        "attack_pattern": [],
        "malware": [],
        "intrusion_set": [],
        "tool": [],
        "course_of_action": [],
    }
    if not path or not os.path.isfile(path):
        return out
    try:
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, json.JSONDecodeError):
        return out
    if not isinstance(bundle, dict):
        return out
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return out
    bundle_index: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if isinstance(obj, dict) and obj.get("id"):
            bundle_index[obj["id"]] = obj
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type")
        if otype not in _ATTACK_OBJECT_TYPES:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = _attack_external_id(obj)
        if not external_id:
            continue
        name = _clip(obj.get("name") or "", 256)
        description = _clip(obj.get("description") or "", _CWE_DESCRIPTION_MAX)
        detection = _clip(obj.get("x_mitre_detection") or "", 1500)
        platforms = _coerce_str_list(obj.get("x_mitre_platforms"), max_items=16)
        aliases = _coerce_str_list(obj.get("x_mitre_aliases"), max_items=16, item_max=128)
        tactics = _coerce_str_list(_attack_phases(obj), max_items=8)
        is_subtechnique = bool(obj.get("x_mitre_is_subtechnique"))
        domains = _coerce_str_list(obj.get("x_mitre_domains"), max_items=8)
        entry = {
            "id": external_id,
            "name": name,
            "description": description,
            "detection": detection,
            "platforms": platforms,
            "aliases": aliases,
            "tactics": tactics,
            "is_subtechnique": is_subtechnique,
            "domains": domains,
            "source": "mitre_attack",
        }
        if otype == "attack-pattern":
            out["attack_pattern"].append(entry)
        elif otype == "malware":
            entry["family"] = bool(obj.get("is_family"))
            out["malware"].append(entry)
        elif otype == "intrusion-set":
            out["intrusion_set"].append(entry)
        elif otype == "tool":
            out["tool"].append(entry)
        elif otype == "course-of-action":
            entry["id"] = external_id
            out["course_of_action"].append(entry)
    return out


def _parse_yara_rule_text(text: str, source_path: str) -> dict[str, Any] | None:
    rule_match = _YARA_RULE_RE.search(text)
    if not rule_match:
        return None
    name = rule_match.group(1)
    meta: dict[str, str] = {}
    meta_block_re = re.compile(
        r"\bmeta\s*:\s*(.*?)\b(?:strings|condition)\s*:",
        re.DOTALL | re.IGNORECASE,
    )
    meta_match = meta_block_re.search(text)
    if meta_match:
        for kv in _YARA_META_KV_RE.finditer(meta_match.group(1)):
            key = kv.group(1)
            raw_value = kv.group(2) or ""
            meta[key] = raw_value
    strings: list[str] = []
    strings_match = _YARA_STRINGS_SECTION_RE.search(text)
    if strings_match:
        block = strings_match.group(1)
        for line_match in _YARA_STRING_LINE_RE.finditer(block):
            content = line_match.group(2)
            for sm in _YARA_STRING_QUOTED_RE.finditer(content):
                s = sm.group(1)
                if not s or len(s) > _YARA_STRING_MAX:
                    continue
                if s in strings:
                    continue
                strings.append(s)
                if len(strings) >= 96:
                    break
            if len(strings) >= 96:
                break
    return {
        "name": name,
        "description": meta.get("description", "").strip(),
        "author": meta.get("author", "").strip(),
        "reference": meta.get("reference", "").strip(),
        "strings": strings,
        "source": "signature_base",
        "file": os.path.relpath(source_path, start=os.path.dirname(source_path)) if source_path else "",
    }


def parse_yara_dir(yara_dir: str) -> list[dict[str, Any]]:
    """Parse all .yar/.yara files under a directory and return a list of rules.

    Lightweight, regex-based — does not require a YARA library. Skips rules
    with empty descriptions, no strings, or whose file exceeds
    ``_YARA_RULE_FILE_MAX_BYTES``. Hard-capped at
    ``_YARA_RULE_DIR_MAX_RULES`` rules total.
    """
    if not yara_dir or not os.path.isdir(yara_dir):
        return []
    out: list[dict[str, Any]] = []
    seen_names = set()
    for root_dir, _dirs, files in os.walk(yara_dir):
        for fname in sorted(files):
            if not (fname.endswith((".yar", ".yara"))):
                continue
            full = os.path.join(root_dir, fname)
            try:
                if os.path.getsize(full) > _YARA_RULE_FILE_MAX_BYTES:
                    continue
            except OSError:
                continue
            try:
                with open(full, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            rules = list(_YARA_RULE_RE.finditer(text))
            for rule_match in rules:
                if len(out) >= _YARA_RULE_DIR_MAX_RULES:
                    return out
                start = rule_match.start()
                brace = text.find("{", start)
                if brace < 0:
                    continue
                depth = 0
                end = brace
                for i in range(brace, len(text)):
                    ch = text[i]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                else:
                    continue
                rule_text = text[start:end]
                parsed = _parse_yara_rule_text(rule_text, full)
                if not parsed:
                    continue
                if not parsed["description"] and not parsed["strings"]:
                    continue
                if parsed["name"] in seen_names:
                    continue
                seen_names.add(parsed["name"])
                out.append(parsed)
    return out


def compute_source_fingerprint(
    cwe_path: str | None,
    attack_paths: Iterable[str],
    yara_dir: str | None,
) -> str:
    """SHA-256 over (paths, sizes, mtimes) — detects corpus source changes."""
    h = hashlib.sha256()
    if cwe_path and os.path.isfile(cwe_path):
        try:
            h.update(b"CWE")
            h.update(str(os.path.getsize(cwe_path)).encode("utf-8"))
            h.update(str(int(os.path.getmtime(cwe_path))).encode("utf-8"))
        except OSError:
            h.update(b"CWE-MISSING")
    else:
        h.update(b"CWE-MISSING")
    for ap in sorted(p for p in attack_paths if p):
        try:
            if not os.path.isfile(ap):
                h.update(b"ATT-MISSING")
                continue
            h.update(ap.encode("utf-8"))
            h.update(str(os.path.getsize(ap)).encode("utf-8"))
            h.update(str(int(os.path.getmtime(ap))).encode("utf-8"))
        except OSError:
            h.update(b"ATT-MISSING")
    if yara_dir and os.path.isdir(yara_dir):
        try:
            h.update(b"YARA")
            count = 0
            for root_dir, _dirs, files in os.walk(yara_dir):
                for fname in sorted(files):
                    if not (fname.endswith((".yar", ".yara"))):
                        continue
                    full = os.path.join(root_dir, fname)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    h.update(fname.encode("utf-8"))
                    h.update(str(st.st_size).encode("utf-8"))
                    h.update(str(int(st.st_mtime)).encode("utf-8"))
                    count += 1
                    if count >= 1000:
                        break
                if count >= 1000:
                    break
            h.update(str(count).encode("utf-8"))
        except OSError:
            h.update(b"YARA-MISSING")
    else:
        h.update(b"YARA-MISSING")
    return h.hexdigest()[:32]


class ThreatCorpus:
    """In-memory holder for the parsed threat corpus — modular edition.

    Storage:
        entries: dict[str, list[dict]] — keyed by source name
        _indexes: dict[str, dict[str, Any]] — per-source id→entry indexes

    Backward compatibility:
        Properties like .cwe, .yara_rules, .attack_patterns resolve to
        entries[<source_name>] transparently.
    """

    CORPUS_VERSION = 2

    def __init__(
        self,
        entries: dict[str, list[dict[str, Any]]] | None = None,
        source_fingerprints: dict[str, str] | None = None,
        built_at: str = "",
    ) -> None:
        self.entries: dict[str, list[dict[str, Any]]] = entries or {}
        self.source_fingerprints: dict[str, str] = source_fingerprints or {}
        self.built_at: str = built_at or datetime.now(UTC).isoformat()
        self._indexes: dict[str, dict[str, Any]] = {}
        self._yara_string_to_rules: dict[str, list[str]] = {}
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        self._indexes.clear()
        self._yara_string_to_rules.clear()
        for source_name, entries in self.entries.items():
            idx: dict[str, Any] = {}
            for e in entries:
                eid = e.get("id")
                if eid:
                    idx[eid] = e
                for alias in e.get("aliases") or []:
                    key = str(alias).lower()
                    if key and key not in idx:
                        idx[key] = e
            self._indexes[source_name] = idx
            if source_name in ("yara_rules", "yara_rules_extra"):
                for r in entries:
                    if r.get("name"):
                        self._indexes[source_name][r["name"]] = r
                    for s in r.get("strings") or []:
                        key = s.lower()
                        if key:
                            self._yara_string_to_rules.setdefault(key, []).append(r.get("name", ""))

    # ── Backward-compatible properties ────────────────────────────────

    @property
    def cwe(self) -> list[dict[str, Any]]:
        return self.entries.get("cwe", [])

    @property
    def attack_patterns(self) -> list[dict[str, Any]]:
        return self.entries.get("attack_patterns", [])

    @property
    def malware(self) -> list[dict[str, Any]]:
        return self.entries.get("malware", [])

    @property
    def intrusion_sets(self) -> list[dict[str, Any]]:
        return self.entries.get("intrusion_sets", [])

    @property
    def tools(self) -> list[dict[str, Any]]:
        return self.entries.get("tools", [])

    @property
    def mitigations(self) -> list[dict[str, Any]]:
        return self.entries.get("mitigations", [])

    @property
    def yara_rules(self) -> list[dict[str, Any]]:
        return self.entries.get("yara_rules", [])

    @property
    def source_fingerprint(self) -> str:
        parts = [f"{k}:{v}" for k, v in sorted(self.source_fingerprints.items())]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    # ── Backward-compatible search methods ────────────────────────────

    def find_cwe(self, cwe_id: str) -> dict[str, Any] | None:
        if not cwe_id:
            return None
        key = cwe_id.strip().upper()
        if not key.startswith("CWE-"):
            key = f"CWE-{key}"
        return self._indexes.get("cwe", {}).get(key)

    def find_technique(self, attack_id: str) -> dict[str, Any] | None:
        if not attack_id:
            return None
        return self._indexes.get("attack_patterns", {}).get(attack_id.strip().upper())

    def find_malware(self, name_or_id: str) -> dict[str, Any] | None:
        if not name_or_id:
            return None
        return self._indexes.get("malware", {}).get(name_or_id.strip().lower())

    def search_yara_strings(self, needle: str, limit: int = 25) -> list[dict[str, Any]]:
        if not needle:
            return []
        key = needle.lower()
        matches: list[dict[str, Any]] = []
        rule_names = self._yara_string_to_rules.get(key) or []
        yara_idx: dict[str, Any] = {}
        yara_idx.update(self._indexes.get("yara_rules", {}))
        yara_idx.update(self._indexes.get("yara_rules_extra", {}))
        for rname in rule_names[:limit]:
            rule = yara_idx.get(rname)
            if rule is not None:
                matches.append(rule)
        if not matches:
            sub = key[: max(3, len(key) // 2)]
            seen: set[str] = set()
            for skey, rules in self._yara_string_to_rules.items():
                if sub not in skey:
                    continue
                for rname in rules:
                    if rname in seen:
                        continue
                    seen.add(rname)
                    rule = yara_idx.get(rname)
                    if rule is not None:
                        matches.append(rule)
                        if len(matches) >= limit:
                            return matches
        return matches

    def all_yara_strings(self, min_len: int = 4, max_count: int = 200_000) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for source in ("yara_rules", "yara_rules_extra"):
            for rule in self.entries.get(source, []):
                for s in rule.get("strings") or []:
                    if not s or len(s) < min_len:
                        continue
                    key = s.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(s)
                    if len(out) >= max_count:
                        return out
        return out

    # ── Generic access ────────────────────────────────────────────────

    def get_source_entries(self, source_name: str) -> list[dict[str, Any]]:
        return self.entries.get(source_name, [])

    def search(self, source: str, query: str, limit: int = 25) -> list[dict[str, Any]]:
        q = query.lower()
        if not q:
            return []
        results: list[dict[str, Any]] = []
        for e in self.entries.get(source, []):
            text = " ".join(str(v) for v in e.values() if isinstance(v, str)).lower()
            if q in text:
                results.append(e)
                if len(results) >= limit:
                    break
        return results

    def get_by_id(self, source: str, entry_id: str) -> dict[str, Any] | None:
        return self._indexes.get(source, {}).get(entry_id)

    # ── Serialization ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.CORPUS_VERSION,
            "built_at": self.built_at,
            "source_fingerprints": self.source_fingerprints,
            "entries": self.entries,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ThreatCorpus:
        if not isinstance(d, dict):
            return cls()
        version = int(d.get("version") or 0)
        if version >= 2:
            return cls(
                entries=dict(d.get("entries") or {}),
                source_fingerprints=dict(d.get("source_fingerprints") or {}),
                built_at=str(d.get("built_at") or ""),
            )
        return cls._from_v1_dict(d)

    @classmethod
    def _from_v1_dict(cls, d: dict[str, Any]) -> ThreatCorpus:
        """Migrate a V1 monolithic dict to the modular format."""
        entries: dict[str, list[dict[str, Any]]] = {
            "cwe": list(d.get("cwe") or []),
            "attack_patterns": list(d.get("attack_patterns") or []),
            "malware": list(d.get("malware") or []),
            "intrusion_sets": list(d.get("intrusion_sets") or []),
            "tools": list(d.get("tools") or []),
            "mitigations": list(d.get("mitigations") or []),
            "yara_rules": list(d.get("yara_rules") or []),
        }
        return cls(
            entries=entries,
            source_fingerprints={"combined": str(d.get("source_fingerprint") or "")},
            built_at=str(d.get("built_at") or ""),
        )

    # ── Utility ───────────────────────────────────────────────────────

    def count_by_type(self) -> dict[str, int]:
        return {name: len(entries) for name, entries in self.entries.items() if entries}

    def is_empty(self) -> bool:
        return not any(self.entries.values())

    def available_sources(self) -> list[str]:
        return sorted(self.entries.keys())


# ── Cache: per-source files + manifest ─────────────────────────────────────

CORPUS_CACHE_DIR = os.path.join(CACHE_DIR, "corpus")
MANIFEST_PATH = os.path.join(CORPUS_CACHE_DIR, "manifest.json")


def _source_cache_path(source_name: str) -> str:
    return os.path.join(CORPUS_CACHE_DIR, f"{source_name}.json")


def corpus_cache_path() -> str:
    """Return the legacy per-user cache path. Kept for backward compat."""
    return os.path.join(CACHE_DIR, CORPUS_CACHE_FILENAME)


def _atomic_write_json(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
    os.replace(tmp, path)


def _load_manifest() -> dict[str, Any] | None:
    if not os.path.isfile(MANIFEST_PATH):
        return None
    try:
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _load_modular_corpus(manifest: dict[str, Any]) -> ThreatCorpus | None:
    entries: dict[str, list[dict[str, Any]]] = {}
    fingerprints: dict[str, str] = {}
    built_at = ""
    for source_name, _meta in manifest.get("sources", {}).items():
        cache_path = _source_cache_path(source_name)
        if not os.path.isfile(cache_path):
            continue
        try:
            with open(cache_path, encoding="utf-8") as f:
                data = json.load(f)
            entries[source_name] = data.get("entries", [])
            fingerprints[source_name] = data.get("fingerprint", "")
            if not built_at:
                built_at = data.get("built_at", "")
        except (OSError, json.JSONDecodeError):
            continue
    if not entries:
        return None
    return ThreatCorpus(entries=entries, source_fingerprints=fingerprints, built_at=built_at)


def _load_v1_corpus() -> ThreatCorpus | None:
    path = os.path.join(CACHE_DIR, CORPUS_CACHE_FILENAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    ver = int(data.get("version") or 0)
    if ver < 1:
        return None
    return ThreatCorpus.from_dict(data)


def load_corpus() -> ThreatCorpus | None:
    """Load from modular cache. Falls back to V1 monolithic file."""
    manifest = _load_manifest()
    if manifest and manifest.get("version", 0) >= 2:
        corpus = _load_modular_corpus(manifest)
        if corpus is not None:
            return corpus
    return _load_v1_corpus()


def save_corpus(corpus: ThreatCorpus) -> str:
    """Save to per-source cache files + manifest. Returns manifest path."""
    os.makedirs(CORPUS_CACHE_DIR, exist_ok=True)
    manifest_sources: dict[str, dict[str, Any]] = {}
    for source_name, entries in corpus.entries.items():
        if not entries:
            continue
        fingerprint = corpus.source_fingerprints.get(source_name, "")
        cache_path = _source_cache_path(source_name)
        _atomic_write_json(cache_path, {
            "version": ThreatCorpus.CORPUS_VERSION,
            "source": source_name,
            "fingerprint": fingerprint,
            "count": len(entries),
            "built_at": corpus.built_at,
            "entries": entries,
        })
        manifest_sources[source_name] = {
            "fingerprint": fingerprint,
            "count": len(entries),
        }
    _atomic_write_json(MANIFEST_PATH, {
        "version": ThreatCorpus.CORPUS_VERSION,
        "built_at": corpus.built_at,
        "sources": manifest_sources,
    })
    # Clean up legacy monolithic cache
    legacy = corpus_cache_path()
    if os.path.isfile(legacy):
        with contextlib.suppress(OSError):
            os.rename(legacy, legacy + ".v1_backup")
    return MANIFEST_PATH


def delete_corpus_cache() -> bool:
    """Remove all corpus cache files. Returns True if files were removed."""
    removed = False
    if os.path.isdir(CORPUS_CACHE_DIR):
        for f in os.listdir(CORPUS_CACHE_DIR):
            try:
                os.remove(os.path.join(CORPUS_CACHE_DIR, f))
                removed = True
            except OSError:
                pass
    legacy = corpus_cache_path()
    try:
        os.remove(legacy)
        removed = True
    except OSError:
        pass
    return removed


# ── Download pipeline (registry-based) ─────────────────────────────────────

def _download_url(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ida-pro-mcp/1.0"})
    with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT) as resp:
        data = resp.read(_MAX_DOWNLOAD_BYTES + 1)
        if len(data) > _MAX_DOWNLOAD_BYTES:
            raise ValueError(f"Download exceeds {_MAX_DOWNLOAD_BYTES} bytes")
        return data


def _extract_zip(data: bytes, dest: str, pattern: str | None = None) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = zf.namelist()
        if pattern:
            members = [m for m in members if pattern in m]
        zf.extractall(dest, members=members)


def download_corpus_sources(
    dest_dir: str | None = None,
    *,
    force: bool = False,
    progress_cb: Callable[[str], None] | None = None,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    """Download all (or selected) corpus sources using the SOURCES registry.

    Returns dict with source_dirs mapping source_name → data_dir,
    plus downloaded/errors lists.
    """
    from .sources import SOURCES as _SOURCES

    if dest_dir is None:
        dest_dir = os.path.join(CACHE_DIR, "corpus_sources")
    os.makedirs(dest_dir, exist_ok=True)

    result: dict[str, Any] = {
        "source_dirs": {},
        "downloaded": [],
        "errors": [],
        "dest_dir": dest_dir,
    }

    target_sources = _SOURCES
    if sources:
        target_sources = [s for s in _SOURCES if s.name in sources]

    for source in target_sources:
        if not source.urls:
            continue
        try:
            dl = source.download(dest_dir, force=force, progress_cb=progress_cb)
            result["source_dirs"][source.name] = dl.get("data_dir", "")
            result["downloaded"].extend(dl.get("downloaded", []))
            result["errors"].extend(dl.get("errors", []))
        except Exception as e:
            result["errors"].append(f"{source.name}: {e}")

    return result


def _build_from_sources(download_result: dict[str, Any]) -> ThreatCorpus | None:
    """Build corpus from downloaded sources using the SOURCES registry."""
    from .sources import SOURCES as _SOURCES

    entries: dict[str, list[dict[str, Any]]] = {}
    fingerprints: dict[str, str] = {}
    source_dirs = download_result.get("source_dirs", {})

    for source in _SOURCES:
        data_dir = source_dirs.get(source.name, "")
        if not data_dir or not os.path.isdir(data_dir):
            continue
        try:
            parsed = source.parse(data_dir)
        except Exception:
            parsed = []
        if not parsed:
            continue

        if source.is_multi_type:
            buckets: dict[str, list[dict[str, Any]]] = {}
            for e in parsed:
                bucket = e.pop("_attack_type", source.name)
                buckets.setdefault(bucket, []).append(e)
            for bucket, bucket_entries in buckets.items():
                if bucket in entries:
                    entries[bucket].extend(bucket_entries)
                else:
                    entries[bucket] = bucket_entries
        else:
            entries[source.name] = parsed

        fingerprints[source.name] = source.fingerprint(data_dir)

    if not entries:
        return None
    return ThreatCorpus(entries=entries, source_fingerprints=fingerprints)


def build_corpus_from_sources(
    cwe_path: str | None = None,
    attack_paths: Iterable[str] | None = None,
    yara_dir: str | None = None,
) -> ThreatCorpus:
    """Parse raw source files and return a populated ThreatCorpus.

    Kept for backward compat — new code should use _build_from_sources.
    """
    cwe = parse_cwe_xml(cwe_path) if cwe_path else []
    attack_paths_list = [p for p in (attack_paths or []) if p]
    attack_merged: dict[str, list[dict[str, Any]]] = {
        "attack_pattern": [],
        "malware": [],
        "intrusion_set": [],
        "tool": [],
        "course_of_action": [],
    }
    for ap in attack_paths_list:
        parsed = parse_attack_stix(ap)
        for key in attack_merged:
            attack_merged[key].extend(parsed.get(key) or [])
    yara_rules = parse_yara_dir(yara_dir) if yara_dir else []
    entries: dict[str, list[dict[str, Any]]] = {
        "cwe": cwe,
        "attack_patterns": attack_merged["attack_pattern"],
        "malware": attack_merged["malware"],
        "intrusion_sets": attack_merged["intrusion_set"],
        "tools": attack_merged["tool"],
        "mitigations": attack_merged["course_of_action"],
        "yara_rules": yara_rules,
    }
    fp = compute_source_fingerprint(cwe_path, attack_paths_list, yara_dir)
    return ThreatCorpus(entries=entries, source_fingerprints={"combined": fp})


# ── Singleton ──────────────────────────────────────────────────────────────

_corpus_singleton: ThreatCorpus | None = None
_corpus_lock = __import__("threading").Lock()


def ensure_corpus_loaded(
    rebuild: bool = False,
    cwe_path: str | None = None,
    attack_paths: Iterable[str] | None = None,
    yara_dir: str | None = None,
    auto_download: bool = False,
) -> tuple[ThreatCorpus | None, dict[str, Any]]:
    """Lazy-load the corpus singleton. Thread-safe.

    On first call: loads from cache or builds from sources.
    On subsequent calls: returns cached singleton (unless rebuild=True).
    """
    global _corpus_singleton

    if _corpus_singleton is not None and not rebuild:
        return _corpus_singleton, {
            "loaded": True,
            "from_cache": True,
            "rebuilt": False,
            "singleton": True,
            "counts": _corpus_singleton.count_by_type(),
            "source_fingerprint": _corpus_singleton.source_fingerprint,
        }

    with _corpus_lock:
        if _corpus_singleton is not None and not rebuild:
            return _corpus_singleton, {
                "loaded": True,
                "from_cache": True,
                "rebuilt": False,
                "singleton": True,
                "counts": _corpus_singleton.count_by_type(),
                "source_fingerprint": _corpus_singleton.source_fingerprint,
            }

        # Try cache
        if not rebuild:
            corpus = load_corpus()
            if corpus is not None:
                _corpus_singleton = corpus
                return corpus, {
                    "loaded": True,
                    "from_cache": True,
                    "rebuilt": False,
                    "singleton": True,
                    "counts": corpus.count_by_type(),
                    "source_fingerprint": corpus.source_fingerprint,
                }

        # Build from sources (legacy path if explicit paths provided)
        if cwe_path or attack_paths or yara_dir:
            corpus = build_corpus_from_sources(cwe_path, attack_paths, yara_dir)
            saved = save_corpus(corpus)
            _corpus_singleton = corpus
            return corpus, {
                "loaded": True,
                "from_cache": False,
                "rebuilt": True,
                "cache_path": saved,
                "counts": corpus.count_by_type(),
                "source_fingerprint": corpus.source_fingerprint,
            }

        # Auto-download and build using registry
        if auto_download:
            dl = download_corpus_sources(force=rebuild)
            corpus = _build_from_sources(dl)
            if corpus is not None and not corpus.is_empty():
                saved = save_corpus(corpus)
                _corpus_singleton = corpus
                return corpus, {
                    "loaded": True,
                    "from_cache": False,
                    "rebuilt": True,
                    "cache_path": saved,
                    "counts": corpus.count_by_type(),
                    "source_fingerprint": corpus.source_fingerprint,
                }

        return None, {
            "loaded": False,
            "from_cache": False,
            "rebuilt": False,
            "reason": "no sources provided and no cache available",
        }


def invalidate_corpus_cache() -> None:
    """Clear the singleton and delete all cache files."""
    global _corpus_singleton
    with _corpus_lock:
        _corpus_singleton = None
    delete_corpus_cache()
