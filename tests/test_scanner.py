"""Testes do scanner — usam apenas pastas falsas em tmp_path; nunca tocam pastas reais nem apagam nada."""
from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

from pccleaner.core.models import CancelToken, Category, CleanMode, Finding, SafetyLevel, ScanOptions
from pccleaner.scanner import dedupe_findings, expand_pattern, list_children, list_files, measure_tree, run_scan
from pccleaner.scanner import engine


def _write(p, size=10, age_days=0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    if age_days:
        t = time.time() - age_days * 86400
        os.utime(p, (t, t))
    return p


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    tmp_path = tmp_path / "scan"
    home = tmp_path / "home"
    local = home / "AppData" / "Local"
    roaming = home / "AppData" / "Roaming"
    pdata = tmp_path / "ProgramData"
    for d in (home, local, roaming, pdata, local / "Temp", tmp_path / "Windows", tmp_path / "PF", tmp_path / "PF86"):
        d.mkdir(parents=True, exist_ok=True)
    env = {"USERPROFILE": home, "LOCALAPPDATA": local, "APPDATA": roaming, "ProgramData": pdata,
           "TEMP": local / "Temp", "TMP": local / "Temp", "ProgramFiles": tmp_path / "PF",
           "ProgramFiles(x86)": tmp_path / "PF86", "ProgramW6432": tmp_path / "PF"}
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    # Nada de Lixeira real, registro real nem regras em %SystemRoot% (Windows real) nos testes.
    monkeypatch.setattr(engine, "query_recycle_bin", lambda root=None: (0, 0))
    monkeypatch.setattr("pccleaner.detectors.dynamic._installed_names", lambda: set())
    from pccleaner.detectors import all_rules
    safe_rules = [r for r in all_rules() if not any("%systemroot%" in p.lower() for p in r.paths)]
    monkeypatch.setattr(engine, "all_rules", lambda: list(safe_rules))
    return {"home": home, "local": local, "roaming": roaming, "pdata": pdata, "tmp": tmp_path}


def _mklink_junction(link, target) -> bool:
    try:
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, timeout=30)
        return r.returncode == 0 and os.path.isdir(link)
    except (OSError, subprocess.SubprocessError):
        return False


# ------------------------------------------------------------------ measure_tree / listagens

def test_measure_tree_counts_and_min_age(tmp_path):
    _write(tmp_path / "a" / "new.bin", 100)
    _write(tmp_path / "a" / "old.bin", 1000, age_days=10)
    _write(tmp_path / "a" / "sub" / "older.bin", 50, age_days=40)
    b, n, newest = measure_tree(str(tmp_path / "a"))
    assert (b, n) == (1150, 3)
    assert newest is not None and time.time() - newest < 3600
    assert measure_tree(str(tmp_path / "a"), min_age_days=5)[:2] == (1050, 2)
    assert measure_tree(str(tmp_path / "a"), min_age_days=30)[:2] == (50, 1)
    assert measure_tree(str(tmp_path / "a" / "new.bin"))[:2] == (100, 1)
    assert measure_tree(str(tmp_path / "nope")) == (0, 0, None)


def test_junction_not_followed(tmp_path):
    outside = tmp_path / "outside"
    _write(outside / "big.bin", 5000)
    root = tmp_path / "root"
    _write(root / "small.bin", 10)
    if not _mklink_junction(root / "link", outside):
        pytest.skip("não foi possível criar junction")
    assert measure_tree(str(root))[:2] == (10, 1)
    assert all(f.path != str(outside / "big.bin") for f in list_files(str(root)))
    kids = {os.path.basename(c.path): c for c in list_children(str(root))}
    assert kids["link"].size_bytes == 0
    assert expand_pattern(str(root / "*" / "big.bin")) == []


def test_symlink_not_followed(tmp_path):
    outside = tmp_path / "outside"
    _write(outside / "big.bin", 5000)
    root = tmp_path / "root"
    _write(root / "small.bin", 10)
    try:
        os.symlink(outside, root / "sl", target_is_directory=True)
    except OSError:
        pytest.skip("sem privilégio para criar symlink")
    assert measure_tree(str(root))[:2] == (10, 1)


def test_list_children_and_files(tmp_path):
    base = tmp_path / "lc"
    _write(base / "d1" / "x.bin", 300)
    _write(base / "d1" / "y" / "z.bin", 700)
    _write(base / "f.bin", 50)
    kids = list_children(str(base))
    assert [os.path.basename(k.path) for k in kids] == ["d1", "f.bin"]
    assert kids[0].size_bytes == 1000 and kids[0].file_count == 2
    assert [f.size_bytes for f in list_files(str(base), limit=2)] == [700, 300]


def test_expand_pattern_env_and_glob(scan_env):
    ud = scan_env["local"] / "Google" / "Chrome" / "User Data"
    for prof in ("Default", "Profile 1", "[weird]"):
        (ud / prof / "Cache").mkdir(parents=True)
    assert len(expand_pattern(r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache")) == 3
    assert expand_pattern(r"%NAO_EXISTE_VAR%\x") == []


# ------------------------------------------------------------------ run_scan

def test_run_scan_known_locations(scan_env):
    local, home = scan_env["local"], scan_env["home"]
    _write(local / "pip" / "Cache" / "http" / "a", 2000)
    _write(local / "Temp" / "old.tmp", 500, age_days=3)
    _write(local / "Temp" / "new.tmp", 400)
    _write(local / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "data_0", 800)
    _write(local / "Google" / "Chrome" / "User Data" / "Default" / "Cookies", 999)
    _write(local / "Microsoft" / "Windows" / "Explorer" / "thumbcache_256.db", 64)
    _write(home / "Downloads" / "setup.exe", 3000, age_days=60)
    _write(home / "Downloads" / "fresh.exe", 3000)
    res = run_scan(ScanOptions(deep_scan=False))
    by_rule: dict[str, list[Finding]] = {}
    for f in res.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert by_rule["dev.pip"][0].size_bytes == 2000 and by_rule["dev.pip"][0].selected
    assert by_rule["windows.user_temp"][0].size_bytes == 500        # só arquivos com > 1 dia
    chrome = by_rule["browser.chrome.cache"][0]
    assert chrome.path.endswith(r"Default\Cache") and chrome.size_bytes == 800
    assert all("cookies" not in f.path.lower() for f in res.findings)
    thumbs = by_rule["windows.thumbcache"]
    assert thumbs[0].clean_mode is CleanMode.WHOLE and thumbs[0].path.endswith("thumbcache_256.db")
    inst = by_rule["downloads.installers"]
    assert [os.path.basename(f.path) for f in inst] == ["setup.exe"]
    assert not inst[0].selected and inst[0].safety is SafetyLevel.REVIEW
    total = by_rule["downloads.total"][0]
    assert total.clean_mode is CleanMode.NONE and not total.selected
    assert not res.cancelled and res.scan_id


def test_run_scan_deep_matches(scan_env):
    home = scan_env["home"]
    proj = home / "code" / "webapp"
    _write(proj / "package.json", 10)
    _write(proj / "node_modules" / "lib" / "index.js", 5000)
    _write(proj / ".next" / "cache" / "x", 300)
    _write(proj / "src" / "__pycache__" / "m.pyc", 120)
    _write(home / "code" / "other" / "node_modules" / "a.js", 700)      # sem package.json -> não casa
    _write(home / "code" / "other" / "cache" / "b", 70)                 # cache sem pai .next -> não casa
    _write(home / "code" / "rs" / "Cargo.toml", 10)
    _write(home / "code" / "rs" / "target" / "debug" / "app.exe", 900)
    _write(home / ".vscode" / "extensions" / "ext" / "package.json", 1)  # extensões de IDE: não casa
    _write(home / ".vscode" / "extensions" / "ext" / "dist" / "a.js", 50)
    _write(home / "videos2" / "movie.mkv", 2 * 1024 * 1024, age_days=800)
    res = run_scan(ScanOptions(deep_scan=True, roots=[str(home)], large_file_threshold_mb=1, old_file_days=365))
    rules = {f.rule_id: f for f in res.findings}
    nm = rules["proj.node_modules"]
    assert nm.size_bytes == 5000 and nm.safety is SafetyLevel.CAUTION and not nm.selected
    assert rules["proj.next_cache"].path.endswith(r".next\cache") and rules["proj.next_cache"].selected
    assert rules["proj.pycache"].selected
    assert rules["proj.rust_target"].safety is SafetyLevel.REVIEW
    paths = [f.path for f in res.findings]
    assert not any(r"other\node_modules" in p or r"other\cache" in p or "extensions" in p for p in paths)
    assert any(lf.path.endswith("movie.mkv") for lf in res.large_files)
    assert rules["deep.old_large_file"].clean_mode is CleanMode.NONE
    assert res.files_scanned >= 8
    tops = {os.path.basename(t.path): t.size_bytes for t in res.top_folders}
    assert tops["code"] >= 5000 + 300 + 120 + 700 + 70 + 900


def test_deep_scan_skips_junction(scan_env):
    home, tmp = scan_env["home"], scan_env["tmp"]
    outside = tmp / "outside_proj"
    _write(outside / "package.json", 1)
    _write(outside / "node_modules" / "z.js", 999)
    (home / "code").mkdir(parents=True, exist_ok=True)
    if not _mklink_junction(home / "code" / "linked", outside):
        pytest.skip("não foi possível criar junction")
    res = run_scan(ScanOptions(deep_scan=True, roots=[str(home)]))
    assert not any("outside_proj" in f.path or r"linked\node_modules" in f.path for f in res.findings)


def test_deep_scan_skips_app_dir(scan_env, monkeypatch):
    app = scan_env["home"] / "PCCleaner"
    _write(app / "pkg" / "__pycache__" / "a.pyc", 10)
    monkeypatch.setattr(engine, "_app_dir", lambda: str(app))
    res = run_scan(ScanOptions(deep_scan=True, roots=[str(scan_env["home"])]))
    assert not any("PCCleaner" in f.path for f in res.findings)


def test_cancel_returns_partial(scan_env):
    home = scan_env["home"]
    for i in range(30):
        _write(home / "bulk" / f"d{i}" / "f.bin", 10)
    tok = CancelToken()
    calls = []

    def progress(p):
        calls.append(p)
        tok.cancel()

    res = run_scan(ScanOptions(deep_scan=True, roots=[str(home)]), progress=progress, cancel=tok)
    assert res.cancelled and calls


def test_cancel_from_other_thread(scan_env):
    _write(scan_env["home"] / "a" / "b.bin", 10)
    tok = CancelToken()
    t = threading.Timer(0.0, tok.cancel)
    t.start()
    t.join()
    assert run_scan(ScanOptions(deep_scan=True), cancel=tok).cancelled


def _finding(path, rule_id, safety=SafetyLevel.SAFE, size=100, mode=CleanMode.CONTENTS):
    return Finding(id=Finding.make_id(path, rule_id), rule_id=rule_id, name=rule_id, path=path,
                   category=Category.DEV_CACHE, app="x", safety=safety, reason="", recommendation="",
                   clean_mode=mode, size_bytes=size)


def test_dedupe_nested_and_exact():
    parent = _finding(r"C:\x\cache", "parent", SafetyLevel.SAFE, 1000)
    child_same = _finding(r"C:\x\cache\sub", "child", SafetyLevel.SAFE, 200)
    out = dedupe_findings([child_same, parent])
    assert [f.rule_id for f in out] == ["parent"] and out[0].size_bytes == 1000

    parent = _finding(r"C:\x\cache", "parent", SafetyLevel.SAFE, 1000)
    child_risky = _finding(r"C:\x\cache\models", "child", SafetyLevel.REVIEW, 300)
    out = dedupe_findings([parent, child_risky])
    assert {f.rule_id for f in out} == {"parent", "child"}
    p = next(f for f in out if f.rule_id == "parent")
    assert p.size_bytes == 700 and p.notes                       # não conta em dobro

    a = _finding(r"C:\u\.cache\huggingface", "dev.huggingface", SafetyLevel.REVIEW)
    b = _finding(r"C:\u\.cache\huggingface", "dev.dot_cache_other", SafetyLevel.REVIEW)
    out = dedupe_findings([b, a], {"dev.huggingface": 1, "dev.dot_cache_other": 2})
    assert [f.rule_id for f in out] == ["dev.huggingface"]

    info = _finding(r"C:\u\Downloads", "downloads.total", SafetyLevel.REVIEW, 5000, CleanMode.NONE)
    inst = _finding(r"C:\u\Downloads\a.exe", "downloads.installers", SafetyLevel.REVIEW, 100, CleanMode.WHOLE)
    assert len(dedupe_findings([info, inst])) == 2


def test_known_findings_dedupe_with_deep(scan_env):
    """__pycache__ dentro de um cache já listado não vira item separado."""
    local = scan_env["local"]
    _write(local / "pip" / "Cache" / "__pycache__" / "a.pyc", 10)
    _write(local / "pip" / "Cache" / "b", 10)
    res = run_scan(ScanOptions(deep_scan=True, roots=[str(local / "pip")]))
    assert [f.rule_id for f in res.findings if "pip" in f.path] == ["dev.pip"]
