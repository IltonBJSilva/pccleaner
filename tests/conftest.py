"""Rede de segurança de TODOS os testes.

Incidente 16/11/2026: um teste chamou clean() com "C:\\" e esvaziou a pasta do projeto.
A partir de agora, durante os testes, qualquer remoção/movimentação fora de tmp_path
ABORTA o teste antes de tocar o disco, e o cwd é sempre um diretório temporário.

Regra: testes NUNCA usam caminhos reais ("C:\\", %USERPROFILE%, cwd...). Para testar
recusas de caminhos perigosos, use apenas funções de validação (security.*) — nunca clean().
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

_SAFE_BASE = os.path.normcase(os.path.realpath(tempfile.gettempdir()))


def _guard_path(p) -> None:
    try:
        ap = os.path.normcase(os.path.abspath(os.fspath(p)))
    except TypeError:
        return
    if not (ap.startswith(_SAFE_BASE + os.sep) and "pytest-of-" in ap):
        raise RuntimeError(f"[TEST GUARD] operação destrutiva fora de tmp_path bloqueada: {p}")


def _wrap(fn, nargs=1):
    def inner(*a, **k):
        for x in a[:nargs]:
            if isinstance(x, (str, bytes, os.PathLike)):
                _guard_path(x)
        return fn(*a, **k)
    inner.__wrapped__ = fn
    return inner


@pytest.fixture(autouse=True)
def _destructive_guard(monkeypatch, tmp_path):
    for mod, name, n in ((os, "remove", 1), (os, "unlink", 1), (os, "rmdir", 1),
                         (os, "removedirs", 1), (os, "rename", 2), (os, "replace", 2),
                         (shutil, "rmtree", 1), (shutil, "move", 2)):
        monkeypatch.setattr(mod, name, _wrap(getattr(mod, name), n))
    orig_unlink = Path.unlink
    orig_rmdir = Path.rmdir

    def p_unlink(self, *a, **k):
        _guard_path(self)
        return orig_unlink(self, *a, **k)

    def p_rmdir(self, *a, **k):
        _guard_path(self)
        return orig_rmdir(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", p_unlink)
    monkeypatch.setattr(Path, "rmdir", p_rmdir)
    cwd = tmp_path.parent / f"{tmp_path.name}_cwd"
    cwd.mkdir(exist_ok=True)
    monkeypatch.chdir(cwd)   # cwd isolado, fora da árvore dos alvos de teste
    yield


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """Ambiente Windows falso dentro de tmp_path (opt-in)."""
    home = tmp_path / "Users" / "tester"
    env = {
        "USERPROFILE": home,
        "APPDATA": home / "AppData" / "Roaming",
        "LOCALAPPDATA": home / "AppData" / "Local",
        "TEMP": home / "AppData" / "Local" / "Temp",
        "TMP": home / "AppData" / "Local" / "Temp",
        "ProgramData": tmp_path / "ProgramData",
        "SystemRoot": tmp_path / "Windows",
        "PUBLIC": tmp_path / "Users" / "Public",
    }
    for k, v in env.items():
        Path(v).mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(k, str(v))
    return {k: Path(v) for k, v in env.items()}
