"""Integration tests for the installer's interactive prompts.

These verify prompt functions work correctly without TTY interaction
by monkeypatching ``input()``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from ida_pro_mcp.installer.main import _prompt_model_path, _prompt_yes_no


def test_model_path_prompt_accepts_valid_path(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        model = Path(td) / "bge-code-v1-q8_0.gguf"
        model.write_text("x", encoding="utf-8")

        monkeypatch.setattr("builtins.input", lambda _: str(model))
        result = _prompt_model_path()
        assert result == str(model)


def test_model_path_prompt_rejects_missing_path(monkeypatch):
    responses = iter(["/nonexistent/model.gguf", ""])

    monkeypatch.setattr("builtins.input", lambda _: next(responses))
    result = _prompt_model_path()
    assert result == ""


def test_model_path_prompt_accepts_empty_to_skip(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    result = _prompt_model_path()
    assert result == ""


def test_model_path_prompt_expands_user_dir(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        model = Path(td) / "bge-code-v1.gguf"
        model.write_text("x", encoding="utf-8")

        monkeypatch.setattr("builtins.input", lambda _: str(model))
        result = _prompt_model_path()
        assert result == str(model)


def test_yes_no_prompt_defaults_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert _prompt_yes_no("Test?", default=True) is True


def test_yes_no_prompt_defaults_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")
    assert _prompt_yes_no("Test?", default=False) is False


def test_yes_no_prompt_parses_y(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert _prompt_yes_no("Test?", default=False) is True


def test_yes_no_prompt_parses_n(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert _prompt_yes_no("Test?", default=True) is False


def test_yes_no_prompt_parses_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "yes")
    assert _prompt_yes_no("Test?", default=False) is True


def test_yes_no_prompt_parses_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "no")
    assert _prompt_yes_no("Test?", default=True) is False
