"""Testes do classificador — apenas pastas falsas em tmp_path; só validação, nunca exclusão."""
from __future__ import annotations

import os
import subprocess
import time

import pytest

from pccleaner.classifier import classify, default_selected
from pccleaner.core.models import Category, CleanMode, Finding, SafetyLevel


@pytest.fixture
def cenv(tmp_path, monkeypatch):
    home = tmp_path / "cls" / "Users" / "tester"
    local = home / "AppData" / "Local"
    for d in (local / "Temp", home / "AppData" / "Roaming", home / "Documents", home / ".ssh"):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("TEMP", str(local / "Temp"))
    monkeypatch.setenv("TMP", str(local / "Temp"))
    work = tmp_path / "cls" / "work"
    work.mkdir()
    return {"home": home, "local": local, "work": work}


def _f(path, cat=Category.APP_CACHE, safety=SafetyLevel.SAFE, mode=CleanMode.CONTENTS, size=1000, mtime=None):
    return Finding(id=Finding.make_id(str(path), "t"), rule_id="t", name="t", path=str(path), category=cat,
                   app="x", safety=safety, reason="r", recommendation="", clean_mode=mode, size_bytes=size,
                   last_modified=mtime)


def _mk(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


def test_safe_cache_selected(cenv):
    d = _mk(cenv["local"] / "App" / "Cache")
    (d / "data_0").write_bytes(b"x")
    f = classify(_f(d, mtime=time.time() - 10 * 86400))
    assert f.safety is SafetyLevel.SAFE and default_selected(f) and f.recommendation


def test_git_repo_becomes_protected(cenv):
    d = _mk(cenv["local"] / "App" / "Cache")
    _mk(d / ".git")
    f = classify(_f(d))
    assert f.safety is SafetyLevel.PROTECTED and f.notes and not default_selected(f)


def test_downgrade_when_package_json(cenv):
    d = _mk(cenv["local"] / "App" / "Cache")
    (d / "package.json").write_text("{}")
    f = classify(_f(d))
    assert f.safety is SafetyLevel.CAUTION and not default_selected(f)


def test_downgrade_when_source_files(cenv):
    d = _mk(cenv["local"] / "Tool" / "cache")
    (d / "main.py").write_text("print(1)")
    assert classify(_f(d, cat=Category.DEV_CACHE)).safety is SafetyLevel.CAUTION


def test_temp_with_scripts_not_downgraded(cenv):
    d = _mk(cenv["local"] / "Temp" / "x")
    (d / "setup.js").write_text("1")
    assert classify(_f(d, cat=Category.WINDOWS_TEMP)).safety is SafetyLevel.SAFE


def test_sensitive_file_downgrade(cenv):
    d = _mk(cenv["local"] / "App" / "Cache")
    (d / "Cookies").write_bytes(b"x")
    assert classify(_f(d)).safety is SafetyLevel.CAUTION


def test_protected_paths(cenv):
    f = classify(_f(cenv["home"] / "Documents" / "cache"))
    assert f.safety is SafetyLevel.PROTECTED and f.notes and not default_selected(f)
    for p in ("C:\\", "C:", "relative\\path", str(cenv["home"] / ".ssh"), str(cenv["home"])):
        assert classify(_f(p)).safety is SafetyLevel.PROTECTED, p


def test_app_dir_protected():
    import pccleaner
    app_pkg = os.path.dirname(os.path.abspath(pccleaner.__file__))
    assert classify(_f(os.path.join(app_pkg, "__pycache__"), cat=Category.DEV_CACHE)).safety \
        is SafetyLevel.PROTECTED


def test_recent_note_keeps_safe(cenv):
    d = _mk(cenv["local"] / "App" / "Cache")
    f = classify(_f(d, mtime=time.time() - 60))
    assert f.safety is SafetyLevel.SAFE
    assert any("em uso recente" in n.lower() for n in f.notes)


def test_large_review_note(cenv):
    d = _mk(cenv["local"] / "Models")
    f = classify(_f(d, safety=SafetyLevel.REVIEW, size=6 * 1024 ** 3))
    assert any("5 GB" in n for n in f.notes) and not default_selected(f)


def test_node_modules_never_default(cenv):
    d = _mk(cenv["work"] / "proj" / "node_modules")
    f = classify(_f(d, cat=Category.DEV_DEPENDENCIES, mode=CleanMode.WHOLE))
    assert not default_selected(f)


def test_default_selected_rules(cenv):
    d = _mk(cenv["work"] / "c" / "cache")
    assert not default_selected(classify(_f(d, size=0)))
    assert not default_selected(classify(_f(d, mode=CleanMode.NONE)))
    assert not default_selected(classify(_f(d, safety=SafetyLevel.REVIEW)))
    rb = _f("C:\\$Recycle.Bin", cat=Category.RECYCLE_BIN, mode=CleanMode.RECYCLE_BIN)
    assert classify(rb).safety is SafetyLevel.SAFE and default_selected(rb)


def test_reparse_point_protected(cenv):
    target = _mk(cenv["work"] / "real")
    link = cenv["work"] / "jn"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if r.returncode != 0 or not os.path.isdir(link):
        pytest.skip("junction indisponível")
    assert classify(_f(link)).safety is SafetyLevel.PROTECTED
