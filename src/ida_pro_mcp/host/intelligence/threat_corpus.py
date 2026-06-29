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
  - ``BehaviorClassifier.ANCHORS`` extension (Phase 2a)
  - ``_TFIDFEmbedder._tokens`` synonym expansion (Phase 2b)
  - ``taint`` module signature patterns (Phase 2c)
  - ``intelligence(classify_threat)`` action (Phase 2d)
  - ``SecBertStaticEmbedder`` corpus selection (Phase 3)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from ..config import CACHE_DIR

__all__ = [
    "ThreatCorpus",
    "CORPUS_VERSION",
    "CORPUS_CACHE_FILENAME",
    "corpus_cache_path",
    "load_corpus",
    "save_corpus",
    "delete_corpus_cache",
    "ensure_corpus_loaded",
    "build_corpus_from_sources",
    "parse_cwe_xml",
    "parse_attack_stix",
    "parse_yara_dir",
    "compute_source_fingerprint",
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


def _attack_related(obj: dict[str, Any]) -> list[dict[str, str]]:
    bundle = obj.get("__bundle_objects") or []
    bundle_index = obj.get("__bundle_index")
    if not isinstance(bundle_index, dict):
        return []
    target_ref = obj.get("id")
    out: list[dict[str, str]] = []
    for rel in bundle:
        if rel.get("type") != "relationship":
            continue
        if rel.get("source_ref") != target_ref and rel.get("target_ref") != target_ref:
            continue
        other_ref = rel.get("target_ref") if rel.get("source_ref") == target_ref else rel.get("source_ref")
        if not other_ref:
            continue
        other = bundle_index.get(other_ref)
        if not isinstance(other, dict):
            continue
        rel_type = rel.get("relationship_type") or ""
        other_type = other.get("type") or ""
        other_name = other.get("name") or ""
        out.append({"type": rel_type, "target_type": other_type, "target_name": other_name})
        if len(out) >= 16:
            break
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
    """In-memory holder for the parsed threat corpus."""

    def __init__(
        self,
        cwe: list[dict[str, Any]],
        attack_patterns: list[dict[str, Any]],
        malware: list[dict[str, Any]],
        intrusion_sets: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        mitigations: list[dict[str, Any]],
        yara_rules: list[dict[str, Any]],
        source_fingerprint: str = "",
        built_at: str = "",
    ) -> None:
        self.cwe = cwe
        self.attack_patterns = attack_patterns
        self.malware = malware
        self.intrusion_sets = intrusion_sets
        self.tools = tools
        self.mitigations = mitigations
        self.yara_rules = yara_rules
        self.source_fingerprint = source_fingerprint
        self.built_at = built_at or datetime.now(UTC).isoformat()
        self._cwe_index: dict[str, dict[str, Any]] = {}
        self._attack_index: dict[str, dict[str, Any]] = {}
        self._malware_index: dict[str, dict[str, Any]] = {}
        self._intrusion_index: dict[str, dict[str, Any]] = {}
        self._tool_index: dict[str, dict[str, Any]] = {}
        self._yara_index: dict[str, dict[str, Any]] = {}
        self._yara_string_to_rules: dict[str, list[str]] = {}
        for e in cwe:
            if e.get("id"):
                self._cwe_index[e["id"]] = e
        for e in attack_patterns:
            if e.get("id"):
                self._attack_index[e["id"]] = e
        for e in malware:
            if e.get("id"):
                self._malware_index[e["id"]] = e
            for alias in e.get("aliases") or []:
                key = alias.lower()
                if key and key not in self._malware_index:
                    self._malware_index[key] = e
        for e in intrusion_sets:
            if e.get("id"):
                self._intrusion_index[e["id"]] = e
            for alias in e.get("aliases") or []:
                key = alias.lower()
                if key and key not in self._intrusion_index:
                    self._intrusion_index[key] = e
        for e in tools:
            if e.get("id"):
                self._tool_index[e["id"]] = e
        for r in yara_rules:
            if r.get("name"):
                self._yara_index[r["name"]] = r
            for s in r.get("strings") or []:
                key = s.lower()
                if not key:
                    continue
                self._yara_string_to_rules.setdefault(key, []).append(r["name"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": CORPUS_VERSION,
            "built_at": self.built_at,
            "source_fingerprint": self.source_fingerprint,
            "cwe": self.cwe,
            "attack_patterns": self.attack_patterns,
            "malware": self.malware,
            "intrusion_sets": self.intrusion_sets,
            "tools": self.tools,
            "mitigations": self.mitigations,
            "yara_rules": self.yara_rules,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ThreatCorpus:
        if not isinstance(d, dict):
            return cls([], [], [], [], [], [], [], "", "")
        return cls(
            cwe=list(d.get("cwe") or []),
            attack_patterns=list(d.get("attack_patterns") or []),
            malware=list(d.get("malware") or []),
            intrusion_sets=list(d.get("intrusion_sets") or []),
            tools=list(d.get("tools") or []),
            mitigations=list(d.get("mitigations") or []),
            yara_rules=list(d.get("yara_rules") or []),
            source_fingerprint=str(d.get("source_fingerprint") or ""),
            built_at=str(d.get("built_at") or ""),
        )

    def count_by_type(self) -> dict[str, int]:
        return {
            "cwe": len(self.cwe),
            "attack_patterns": len(self.attack_patterns),
            "malware": len(self.malware),
            "intrusion_sets": len(self.intrusion_sets),
            "tools": len(self.tools),
            "mitigations": len(self.mitigations),
            "yara_rules": len(self.yara_rules),
        }

    def is_empty(self) -> bool:
        return not any([
            self.cwe,
            self.attack_patterns,
            self.malware,
            self.intrusion_sets,
            self.tools,
            self.mitigations,
            self.yara_rules,
        ])

    def find_cwe(self, cwe_id: str) -> dict[str, Any] | None:
        if not cwe_id:
            return None
        key = cwe_id.strip().upper()
        if not key.startswith("CWE-"):
            key = f"CWE-{key}"
        return self._cwe_index.get(key)

    def find_technique(self, attack_id: str) -> dict[str, Any] | None:
        if not attack_id:
            return None
        return self._attack_index.get(attack_id.strip().upper())

    def find_malware(self, name_or_id: str) -> dict[str, Any] | None:
        if not name_or_id:
            return None
        return self._malware_index.get(name_or_id.strip().lower())

    def find_intrusion_set(self, name_or_id: str) -> dict[str, Any] | None:
        if not name_or_id:
            return None
        return self._intrusion_index.get(name_or_id.strip().lower())

    def find_tool(self, name_or_id: str) -> dict[str, Any] | None:
        if not name_or_id:
            return None
        return self._tool_index.get(name_or_id.strip().lower())

    def find_yara(self, name: str) -> dict[str, Any] | None:
        if not name:
            return None
        return self._yara_index.get(name.strip())

    def search_yara_strings(self, needle: str, limit: int = 25) -> list[dict[str, Any]]:
        if not needle:
            return []
        key = needle.lower()
        matches: list[dict[str, Any]] = []
        rule_names = self._yara_string_to_rules.get(key) or []
        for rname in rule_names[:limit]:
            rule = self._yara_index.get(rname)
            if rule is not None:
                matches.append(rule)
        if not matches:
            sub = key[: max(3, len(key) // 2)]
            seen = set()
            for skey, rules in self._yara_string_to_rules.items():
                if sub not in skey:
                    continue
                for rname in rules:
                    if rname in seen:
                        continue
                    seen.add(rname)
                    rule = self._yara_index.get(rname)
                    if rule is not None:
                        matches.append(rule)
                        if len(matches) >= limit:
                            return matches
        return matches

    def all_yara_strings(self, min_len: int = 4, max_count: int = 200_000) -> list[str]:
        """Return a deduplicated flat list of all YARA rule strings, useful for
        seeding the taint signature-pattern tables."""
        out: list[str] = []
        seen = set()
        for rule in self.yara_rules:
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


def corpus_cache_path() -> str:
    """Return the per-user cache path for the threat corpus JSON."""
    return os.path.join(CACHE_DIR, CORPUS_CACHE_FILENAME)


def load_corpus(path: str | None = None) -> ThreatCorpus | None:
    """Load the threat corpus from a JSON cache file. Returns None if missing
    or unparseable. Does not raise."""
    p = path or corpus_cache_path()
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if int(data.get("version") or 0) != CORPUS_VERSION:
        return None
    return ThreatCorpus.from_dict(data)


def save_corpus(corpus: ThreatCorpus, path: str | None = None) -> str:
    """Persist the corpus to the per-user cache directory. Returns the path."""
    p = path or corpus_cache_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    payload = json.dumps(corpus.to_dict(), ensure_ascii=False, separators=(",", ":"))
    if len(payload.encode("utf-8")) > _CORPUS_CACHE_SAVE_MAX_BYTES:
        raise ValueError(
            f"corpus payload {len(payload)} bytes exceeds max {_CORPUS_CACHE_SAVE_MAX_BYTES}"
        )
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(payload)
    os.replace(tmp, p)
    return p


def delete_corpus_cache(path: str | None = None) -> bool:
    """Remove the corpus cache file. Returns True if a file was removed."""
    p = path or corpus_cache_path()
    try:
        os.remove(p)
        return True
    except OSError:
        return False


def build_corpus_from_sources(
    cwe_path: str | None = None,
    attack_paths: Iterable[str] | None = None,
    yara_dir: str | None = None,
) -> ThreatCorpus:
    """Parse the raw source files and return a populated ThreatCorpus."""
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
    fingerprint = compute_source_fingerprint(cwe_path, attack_paths_list, yara_dir)
    return ThreatCorpus(
        cwe=cwe,
        attack_patterns=attack_merged["attack_pattern"],
        malware=attack_merged["malware"],
        intrusion_sets=attack_merged["intrusion_set"],
        tools=attack_merged["tool"],
        mitigations=attack_merged["course_of_action"],
        yara_rules=yara_rules,
        source_fingerprint=fingerprint,
    )


def ensure_corpus_loaded(
    rebuild: bool = False,
    cwe_path: str | None = None,
    attack_paths: Iterable[str] | None = None,
    yara_dir: str | None = None,
) -> tuple[ThreatCorpus | None, dict[str, Any]]:
    """Lazy-load the corpus, optionally rebuilding from sources.

    Returns (corpus, status). When ``rebuild`` is True, sources are required
    and the freshly-built corpus is persisted to the cache. When ``rebuild`` is
    False, the cache is consulted first; on cache miss, the corpus is built
    from sources (if provided) and cached. Returns (None, status) when no
    cache exists and no sources are provided.
    """
    cache_p = corpus_cache_path()
    fingerprint = compute_source_fingerprint(cwe_path or "", attack_paths or [], yara_dir or "")
    if not rebuild and not (cwe_path or attack_paths or yara_dir):
        corpus = load_corpus()
        if corpus is not None:
            return corpus, {
                "loaded": True,
                "from_cache": True,
                "rebuilt": False,
                "cache_path": cache_p,
                "counts": corpus.count_by_type(),
                "source_fingerprint": corpus.source_fingerprint,
            }
    if not (cwe_path or attack_paths or yara_dir):
        return None, {
            "loaded": False,
            "from_cache": False,
            "rebuilt": False,
            "cache_path": cache_p,
            "reason": "no sources provided and no cache available",
        }
    corpus = build_corpus_from_sources(
        cwe_path=cwe_path,
        attack_paths=attack_paths,
        yara_dir=yara_dir,
    )
    if corpus.is_empty():
        return corpus, {
            "loaded": True,
            "from_cache": False,
            "rebuilt": True,
            "cache_path": cache_p,
            "counts": corpus.count_by_type(),
            "source_fingerprint": corpus.source_fingerprint,
            "warning": "built corpus is empty — sources may be missing or malformed",
        }
    saved = save_corpus(corpus)
    return corpus, {
        "loaded": True,
        "from_cache": False,
        "rebuilt": True,
        "cache_path": saved,
        "counts": corpus.count_by_type(),
        "source_fingerprint": fingerprint,
    }
