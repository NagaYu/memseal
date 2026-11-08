"""GATE 6: no network calls anywhere in the code."""

import ast
import socket
from pathlib import Path

import pytest

from memseal.bench.generator import generate
from memseal.sim.runner import run_bench

PKG = Path(__file__).resolve().parents[1] / "memseal"
FORBIDDEN_MODULES = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp",
                     "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "asyncio",
                     "websocket", "websockets", "subprocess"}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module.split(".")[0]


def test_no_network_imports_in_package():
    files = sorted(PKG.rglob("*.py"))
    assert files
    bad = {(str(f.relative_to(PKG)), m) for f in files for m in _imports(f) if m in FORBIDDEN_MODULES}
    assert bad == set()


def test_no_dynamic_import_or_url_literals():
    for f in PKG.rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        assert "__import__(" not in text and "importlib" not in text, f
        assert "http://" not in text and "https://" not in text, f


def test_full_simulation_runs_with_sockets_disabled(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    r = run_bench(generate("dev"), keep_traces=False)
    assert r["meta"]["network_used"] is False and r["meta"]["llm_used"] is False
