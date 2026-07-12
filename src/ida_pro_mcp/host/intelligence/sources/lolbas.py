"""Source parser for LOLBAS project (Living Off The Land Binaries and Scripts)."""

from __future__ import annotations

import json
import os
from typing import Any

from .base import SourceParser


class LolbasSource(SourceParser):
    name = "lolbas"
    description = "LOLBAS project — Living Off The Land Binaries and Scripts"
    cache_key = "lolbas"

    def __init__(self) -> None:
        self.urls = [
            "https://lolbas-project.github.io/api/lolbas.json",
        ]

    def parse(self, data_dir: str) -> list[dict[str, Any]]:
        json_path = os.path.join(data_dir, "lolbas.json")
        if not os.path.isfile(json_path):
            for f in os.listdir(data_dir):
                if f.endswith(".json"):
                    json_path = os.path.join(data_dir, f)
                    break
        if not os.path.isfile(json_path):
            return []
        try:
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

        entries: list[dict[str, Any]] = []
        for item in data if isinstance(data, list) else []:
            name = item.get("Name", "")
            if not name:
                continue
            techniques: list[str] = []
            for cmd in item.get("Commands", []):
                for tc in (cmd.get("MitreID") or "").split(","):
                    tc = tc.strip()
                    if tc and tc not in techniques:
                        techniques.append(tc)
            usecases: list[str] = []
            for cmd in item.get("Commands", []):
                uc = cmd.get("Category") or cmd.get("Usecase") or ""
                if uc and uc not in usecases:
                    usecases.append(uc)
            entries.append({
                "id": f"LOLBAS-{name}",
                "name": name,
                "description": item.get("Description", ""),
                "full_path": item.get("Full_Path", ""),
                "tactics": usecases[:16],
                "techniques": techniques[:16],
                "commands": [
                    {
                        "command": c.get("Command", ""),
                        "category": c.get("Category", ""),
                        "privilege": c.get("Privilege", ""),
                        "description": c.get("Description", ""),
                    }
                    for c in (item.get("Commands") or [])[:8]
                ],
                "source": "lolbas",
            })
        return entries
