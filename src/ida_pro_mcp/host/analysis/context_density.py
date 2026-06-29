#!/usr/bin/env python3
"""
ContextDensityOptimizer — Zero-dependency context density maximization middleware.

Deterministic, zero-ML response compaction for reverse-engineering outputs.
Prevents "lost in the middle" degradation by compressing verbose content
(hex dumps, code blocks, xref lists) while preserving exact addresses,
offsets, and critical metadata.
"""

import json
import math
import re
from collections import Counter
from typing import Any


class ContextDensityOptimizer:
    """
    GenericAgent-style contextual information density maximization for RE tasks.

    Maintains a working context budget while maximizing decision-relevant
    information density through aggressive but semantically aware compression.
    """

    def __init__(
        self,
        budget_tokens: int = 30000,
        compact_threshold: int = 10240,
        max_code_preview: int = 5,
        max_hex_preview: int = 3,
        max_xref_items: int = 20,
        max_line_length: int = 200,
    ):
        self.budget_tokens = budget_tokens
        self.compact_threshold = compact_threshold
        self.max_code_preview = max_code_preview
        self.max_hex_preview = max_hex_preview
        self.max_xref_items = max_xref_items
        self.max_line_length = max_line_length

    # ------------------------------------------------------------------
    # String-level compaction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def strip_xml_tags(text: str) -> str:
        """Remove XML/HTML wrappers such as <tool_use>...</tool_use>."""
        if not isinstance(text, str):
            return text
        return re.sub(r'<[^>]+>', '', text)

    def compress_code_blocks(self, text: str, max_lines: int | None = None) -> str:
        """Collapse fenced code blocks longer than max_lines+1 to a preview."""
        if not isinstance(text, str):
            return text
        max_lines = max_lines if max_lines is not None else self.max_code_preview

        # Match ```lang\n...\n``` blocks
        pattern = re.compile(r'(```[\w]*\n)(.*?)(```)', re.DOTALL)

        def _repl(m: re.Match) -> str:
            prefix, content, suffix = m.group(1), m.group(2), m.group(3)
            lines = content.split('\n')
            if len(lines) <= max_lines + 1:
                return m.group(0)
            preview = '\n'.join(lines[:max_lines])
            return (
                f"{prefix}{preview}\n"
                f"... ({len(lines) - max_lines} more lines) ...\n"
                f"{suffix}"
            )

        return pattern.sub(_repl, text)

    def compress_hex_dumps(self, text: str, max_lines: int | None = None) -> str:
        """Collapse contiguous hex-dump lines longer than max_lines+1."""
        if not isinstance(text, str):
            return text
        max_lines = max_lines if max_lines is not None else self.max_hex_preview

        hex_line_re = re.compile(
            r'^\s*(?:0x[0-9a-fA-F]{4,16}|[0-9a-fA-F]{8,16})\s+(?:[0-9a-fA-F]{2}\s+){4,}'
        )

        lines = text.split('\n')
        result: list[str] = []
        i = 0
        while i < len(lines):
            if hex_line_re.match(lines[i]):
                block_start = i
                while i < len(lines) and hex_line_re.match(lines[i]):
                    i += 1
                block = lines[block_start:i]
                if len(block) > max_lines + 1:
                    preview = '\n'.join(block[:max_lines])
                    last = block[-1]
                    result.append(
                        f"{preview}\n"
                        f"... ({len(block) - max_lines} hex lines truncated) ...\n"
                        f"{last}"
                    )
                else:
                    result.extend(block)
            else:
                result.append(lines[i])
                i += 1
        return '\n'.join(result)

    # ------------------------------------------------------------------
    # Xref compaction
    # ------------------------------------------------------------------

    def compress_xref_lists(self, obj: Any, max_items: int | None = None) -> Any:
        """Truncate long xref lists and add a per-segment histogram."""
        max_items = max_items if max_items is not None else self.max_xref_items

        if isinstance(obj, list):
            if not obj:
                return obj
            if all(isinstance(x, str) for x in obj):
                if len(obj) <= max_items:
                    return obj
                preview = obj[:max_items]
                histogram = self._histogram_by_segment(obj)
                hist_str = ', '.join(
                    f"{seg}={count}"
                    for seg, count in sorted(histogram.items(), key=lambda x: -x[1])
                )
                total = len(obj)
                return preview + [
                    f"... ({total - max_items} more xrefs, groups: {hist_str})"
                ]
            return [self.compress_xref_lists(item, max_items) for item in obj]

        if isinstance(obj, dict):
            return {k: self.compress_xref_lists(v, max_items) for k, v in obj.items()}

        if isinstance(obj, str):
            return self._compress_xref_string(obj, max_items)

        return obj

    def _histogram_by_segment(self, addresses: list[str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for addr in addresses:
            seg = self._addr_to_segment(addr)
            counts[seg] = counts.get(seg, 0) + 1
        return counts

    def _addr_to_segment(self, addr: str) -> str:
        m = re.search(r'0x([0-9a-fA-F]+)|\b([0-9a-fA-F]{4,})\b', str(addr))
        if not m:
            return 'unknown'
        val_str = m.group(1) or m.group(2)
        try:
            val = int(val_str, 16)
        except ValueError:
            return 'unknown'
        if val < 0x1000:
            return 'null'
        if val < 0x100000:
            return '.text'
        if val < 0x200000:
            return '.data'
        if val < 0x300000:
            return '.rdata'
        if val < 0x400000:
            return '.bss'
        return '.other'

    def _compress_xref_string(self, text: str, max_items: int) -> str:
        xref_re = re.compile(
            r'(xref[s]?\s*[:]?\s*)((?:0x[0-9a-fA-F]+(?:\s*[,;\s]\s*))+)',
            re.IGNORECASE,
        )

        def _repl(m: re.Match) -> str:
            prefix = m.group(1)
            xrefs_str = m.group(2)
            xrefs = re.findall(r'0x[0-9a-fA-F]+', xrefs_str)
            if len(xrefs) <= max_items:
                return m.group(0)
            preview = ', '.join(xrefs[:max_items])
            histogram = self._histogram_by_segment(xrefs)
            hist_str = ', '.join(
                f"{seg}={count}"
                for seg, count in sorted(histogram.items(), key=lambda x: -x[1])
            )
            total = len(xrefs)
            return f"{prefix} {preview} ... ({total - max_items} more, groups: {hist_str})"

        return xref_re.sub(_repl, text)

    # ------------------------------------------------------------------
    # Information density measurement
    # ------------------------------------------------------------------

    def measure_information_density(self, text: str) -> dict[str, float]:
        """Calculate estimated tokens, lexical diversity, Shannon entropy,
        useful-token ratio, and an overall density score."""
        if not isinstance(text, str) or not text:
            return {
                "estimated_tokens": 0,
                "useful_token_ratio": 0.0,
                "shannon_entropy": 0.0,
                "lexical_diversity": 0.0,
                "density_score": 0.0,
            }

        est_tokens = max(1, len(text) // 4)
        words = text.split()
        if not words:
            return {
                "estimated_tokens": est_tokens,
                "useful_token_ratio": 0.0,
                "shannon_entropy": 0.0,
                "lexical_diversity": 0.0,
                "density_score": 0.0,
            }

        lexical_diversity = len(set(words)) / len(words)
        char_counts = Counter(text)
        total_chars = len(text)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total_chars
            if p > 0:
                entropy -= p * math.log2(p)

        # Useful tokens: addresses, symbol names, register names, type keywords
        useful_re = re.compile(
            r'0x[0-9a-fA-F]+|'
            r'(?:sub_|loc_|off_|unk_|byte_|word_|dword_|qword_)[0-9a-fA-F]+|'
            r'\b(?:dword|qword|byte|word|ptr|'
            r'eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|'
            r'rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|'
            r'rdi|rsi|r8|r9|r10|r11|r12|r13|r14|r15)\b'
        )
        useful_count = sum(1 for word in words if useful_re.search(word))
        useful_token_ratio = useful_count / len(words)

        normalized_lexdiv = min(1.0, lexical_diversity * 3.0)
        normalized_entropy = min(1.0, entropy / 8.0)
        density_score = (
            0.4 * normalized_lexdiv
            + 0.3 * normalized_entropy
            + 0.3 * useful_token_ratio
        )

        return {
            "estimated_tokens": est_tokens,
            "useful_token_ratio": round(useful_token_ratio, 4),
            "shannon_entropy": round(entropy, 4),
            "lexical_diversity": round(lexical_diversity, 4),
            "density_score": round(density_score, 4),
        }

    # ------------------------------------------------------------------
    # Recursive response compaction
    # ------------------------------------------------------------------

    def compact_response(self, data: Any, budget_tokens: int | None = None) -> Any:
        """Main entry point.  Recursively compacts *data* only when the
        serialized size exceeds *compact_threshold* or the estimated token
        count exceeds *budget_tokens*.  Critical metadata (addresses,
        offsets, API names) is preserved."""
        budget_tokens = budget_tokens if budget_tokens is not None else self.budget_tokens

        serialized = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        est_tokens = max(1, len(serialized) // 4)

        # Budget-aware: skip compaction only when BOTH size and token budget are safe
        if len(serialized) <= self.compact_threshold and est_tokens <= budget_tokens:
            return data

        return self._compact_recursive(data, budget_tokens)

    def _compact_recursive(self, data: Any, budget_tokens: int) -> Any:
        if isinstance(data, str):
            return self._compact_string(data)

        if isinstance(data, list):
            compacted = [self._compact_recursive(item, budget_tokens) for item in data]
            # Budget-aware list truncation
            if len(compacted) > self.max_xref_items * 2:
                target = max(self.max_xref_items, budget_tokens // 100)
                if len(compacted) > target:
                    half = target // 2
                    return (
                        compacted[:half]
                        + [f"... ({len(compacted) - target} items truncated) ..."]
                        + compacted[-half:]
                    )
            return compacted

        if isinstance(data, dict):
            out: dict[str, Any] = {}
            for k, v in data.items():
                # Never drop critical metadata keys
                out[k] = self._compact_recursive(v, budget_tokens)
            return out

        return data

    def _compact_string(self, text: str) -> str:
        text = self.strip_xml_tags(text)
        text = self.compress_code_blocks(text)
        text = self.compress_hex_dumps(text)
        text = self.compress_xref_lists(text)

        lines = text.split('\n')
        truncated: list[str] = []
        for line in lines:
            if len(line) > self.max_line_length:
                line = line[: self.max_line_length - 3] + '...'
            truncated.append(line)
        text = '\n'.join(truncated)

        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r'[ \t]+', ' ', text)
        return text.strip()

    # ------------------------------------------------------------------
    # Legacy compatibility shim (matches reference implementation)
    # ------------------------------------------------------------------

    def optimize(self, raw_message: str, context_label: str = "unknown") -> dict[str, Any]:
        """Legacy-style optimization returning full metadata."""
        if not raw_message:
            return {
                "ok": True,
                "compacted": "",
                "original_tokens": 0,
                "compacted_tokens": 0,
                "compression_ratio": 1.0,
                "note": "Empty input",
            }

        original_tokens = max(1, len(raw_message) // 4)
        compacted = self._compact_recursive(raw_message, self.budget_tokens)
        compacted_tokens = max(1, len(compacted) // 4)
        compression_ratio = original_tokens / compacted_tokens

        density_before = self.measure_information_density(raw_message)
        density_after = self.measure_information_density(compacted)

        return {
            "ok": True,
            "compacted": compacted,
            "original_tokens": original_tokens,
            "compacted_tokens": compacted_tokens,
            "compression_ratio": round(compression_ratio, 2),
            "context_label": context_label,
            "info_density_before": density_before,
            "info_density_after": density_after,
            "under_budget": compacted_tokens <= self.budget_tokens,
        }


# Module-level singleton for convenient imports
_default_optimizer = ContextDensityOptimizer()


def compact_response(data: Any, budget_tokens: int | None = None) -> Any:
    """Module-level convenience wrapper."""
    return _default_optimizer.compact_response(data, budget_tokens)


def measure_information_density(text: str) -> dict[str, float]:
    """Module-level convenience wrapper."""
    return _default_optimizer.measure_information_density(text)
