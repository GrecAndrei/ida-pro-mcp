"""IDA Pro MCP Tools Registry"""

from .idb import idb
from .code import code
from .data import data
from .search import search
from .types import types
from .memory import memory
from .modify import modify
from .misc import misc
from .debug import debug
from .funcs import funcs
from .segments import segments
from .project import project
from .plugins import plugins
from .trace import trace
from .fixups import fixups
from .data_ops import data_ops
from .agent import agent
from .microcode import microcode
from .graph import graph
from .bulk import bulk
from .calc import calc
from .ctree import ctree
from .diff import diff
from .lumina import lumina
from .symbols import symbols
from .patterns import patterns
from .structs import structs
from .emulate import emulate
from .export import export
from .history import history
from .strings_xref import strings_xref
from .entropy import entropy
from .imports_deep import imports_deep
from .comments_ai import comments_ai
from .nav import nav
from .colorize import colorize
from .trace_analysis import trace_analysis
from .hooks import hooks
from .taint import taint
from .coverage import coverage
from .wiki import wiki
from .yara_hunt import yara_hunt
from .analysis import analysis
from .query import query
from .edit import edit
from .batch import batch
from .vuln_scan import vuln_scan
from .deobfuscate import deobfuscate
from .crypto_id import crypto_id
from .abi import abi
from .summarize import summarize
from .compare import compare
from .stack_analysis import stack_analysis
from .classify import classify
from .protocol import protocol
from .c2_detect import c2_detect
from .gadgets import gadgets
from .annotation import annotation
from .xref_analysis import xref_analysis
from .string_ops import string_ops
from .cfg_analysis import cfg_analysis
from .binary_info import binary_info
from .llm_helpers import llm_helpers

__all__ = [
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    "modify",
    "misc",
    "debug",
    "funcs",
    "segments",
    "project",
    "plugins",
    "trace",
    "fixups",
    "data_ops",
    "agent",
    "microcode",
    "graph",
    "bulk",
    "calc",
    "ctree",
    "diff",
    "lumina",
    "symbols",
    "patterns",
    "structs",
    "emulate",
    "export",
    "history",
    "strings_xref",
    "entropy",
    "imports_deep",
    "comments_ai",
    "nav",
    "colorize",
    "trace_analysis",
    "hooks",
    "taint",
    "coverage",
    "wiki",
    "yara_hunt",
    "analysis",
    "query",
    "edit",
    "batch",
    "vuln_scan",
    "deobfuscate",
    "crypto_id",
    "abi",
    "summarize",
    "compare",
    "stack_analysis",
    "classify",
    "protocol",
    "c2_detect",
    "gadgets",
    "annotation",
    "xref_analysis",
    "string_ops",
    "cfg_analysis",
    "binary_info",
    "llm_helpers",
]
