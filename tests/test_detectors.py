"""Testes dos detectors — apenas pastas falsas em tmp_path."""
from __future__ import annotations

import os
import time

import pytest

from pccleaner.core.models import Category, CleanMode, SafetyLevel
from pccleaner.detectors import all_rules, dynamic, dynamic_findings
from pccleaner.scanner.engine import _DeepIndex


def _write(p, size=10, age_days=0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x" * size)
    if age_days:
        t = time.time() - age_days * 86400
        os.utime(p, (t, t))
    return p


@pytest.fixture
def env(tmp_path, monkeypatch):
    base = tmp_path / "det"
    local, roaming, pdata = base / "Local", base / "Roaming", base / "ProgramData"
    for d in (local, roaming, pdata):
        d.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    monkeypatch.setenv("ProgramData", str(pdata))
    # %TEMP% real contém tmp_path; aponta para outro lugar para não mascarar os resíduos de teste.
    for k in ("TEMP", "TMP", "USERPROFILE"):
        monkeypatch.setenv(k, str(base / "other"))
    monkeypatch.setattr(dynamic, "_installed_names", lambda: {"googlechrome", "googlellc", "discordinc"})
    return {"local": local, "roaming": roaming, "pdata": pdata}


def test_rules_are_well_formed():
    rules = all_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)) and len(rules) > 100
    for r in rules:
        assert r.paths or r.dir_names or r.clean_mode is CleanMode.RECYCLE_BIN, r.id
        assert r.reason and r.recommendation, r.id
        for p in r.paths:
            assert "%" in p, f"{r.id}: caminho sem variável de ambiente: {p}"


def test_browser_rules_never_target_sensitive_data():
    banned = ("cookies", "login data", "history", "session", "bookmarks", "web data", "local state",
              "preferences", "places.sqlite", "logins.json", "key4.db")
    for r in all_rules():
        if r.category is Category.BROWSER_CACHE:
            for p in r.paths:
                assert p.lower().rsplit("\\", 1)[-1] not in banned, (r.id, p)


def _match(index, name, parent_dir, siblings=()):
    parent_dir.mkdir(parents=True, exist_ok=True)
    for s in siblings:
        _write(parent_dir / s, 1)
    names = {n.lower() for n in os.listdir(parent_dir)} | {name.lower()}
    return index.match(name.lower(), str(parent_dir), parent_dir.name.lower(), names)


def test_dir_name_matching(tmp_path):
    idx = _DeepIndex(all_rules())
    base = tmp_path / "m"
    assert _match(idx, "__pycache__", base / "p1").id == "proj.pycache"
    assert _match(idx, "cache", base / "p2" / ".next").id == "proj.next_cache"
    assert _match(idx, "cache", base / "p2" / "random") is None
    assert _match(idx, "node_modules", base / "p3") is None
    r = _match(idx, "node_modules", base / "p4", ["package.json"])
    assert r.id == "proj.node_modules" and r.safety is SafetyLevel.CAUTION
    assert _match(idx, "target", base / "p5") is None
    assert _match(idx, "target", base / "p6", ["Cargo.toml"]).id == "proj.rust_target"
    assert _match(idx, "build", base / "p7") is None
    assert _match(idx, "dist", base / "p8", ["pyproject.toml"]).id == "proj.build_dist"
    assert _match(idx, "out", base / "p8b", ["package.json"]) is None
    assert _match(idx, "obj", base / "p9", ["App.csproj"]).id == "proj.dotnet_bin_obj"
    assert _match(idx, "bin", base / "p10") is None
    assert _match(idx, "Library", base / "p11") is None
    assert _match(idx, "Library", base / "p12", [r"ProjectSettings\ProjectVersion.txt"]).id == "proj.unity_library"
    assert _match(idx, "Intermediate", base / "p13", ["Game.uproject"]).id == "proj.unreal_intermediate"
    assert _match(idx, ".godot", base / "p14", ["project.godot"]).id == "proj.godot"


def test_capcut_keeps_newest_version(env):
    apps = env["local"] / "CapCut" / "Apps"
    for v in ("9.10.0.100", "9.9.1.4203", "8.9.1.3802", "10.0.0.1"):
        _write(apps / v / "CapCut.exe", 1000)
    _write(apps / "CapCut.exe", 5)
    (apps / "notaversion").mkdir()
    found = dynamic.capcut_old_versions()
    assert sorted(os.path.basename(f.path) for f in found) == ["8.9.1.3802", "9.10.0.100", "9.9.1.4203"]
    for f in found:
        assert f.category is Category.OLD_VERSIONS and f.safety is SafetyLevel.SAFE
        assert f.clean_mode is CleanMode.WHOLE and f.size_bytes == 1000


def test_capcut_single_version_nothing(env):
    _write(env["local"] / "CapCut" / "Apps" / "9.0.0.1" / "a", 10)
    assert dynamic.capcut_old_versions() == []


def test_squirrel_old_versions(env):
    d = env["local"] / "Discord"
    _write(d / "Update.exe", 10)
    for v in ("1.0.9100", "1.0.9268", "1.0.10"):
        _write(d / f"app-{v}" / "Discord.exe", 500)
    _write(env["local"] / "Other" / "app-1.0" / "x", 10)     # sem Update.exe não é Squirrel
    _write(env["local"] / "Other" / "app-2.0" / "x", 10)
    found = dynamic.squirrel_old_versions()
    assert sorted(os.path.basename(f.path) for f in found) == ["app-1.0.10", "app-1.0.9100"]
    assert all(f.app == "Discord" for f in found)


def test_leftovers_conservative(env):
    local = env["local"]
    big = 51 * 1024 * 1024
    _write(local / "OldGameStudio" / "data.bin", big, age_days=200)          # resíduo
    _write(local / "Google" / "x.bin", big, age_days=200)                     # nome de sistema/instalado
    _write(local / "Discord" / "x.bin", big, age_days=200)                    # instalado
    _write(local / "RecentTool" / "x.bin", big)                               # em uso recente
    _write(local / "SmallThing" / "x.bin", 1000, age_days=200)                # pequeno
    _write(local / "Microsoft" / "x.bin", big, age_days=200)                  # sistema
    found = dynamic.leftover_findings(bases=[str(local)])
    assert [os.path.basename(f.path) for f in found] == ["OldGameStudio"]
    assert found[0].category is Category.LEFTOVERS and found[0].safety is SafetyLevel.REVIEW
    assert "confirme" in found[0].reason


def test_dynamic_findings_survives_errors(env, monkeypatch):
    def boom(cancel=None):
        raise RuntimeError("x")
    monkeypatch.setattr(dynamic, "capcut_old_versions", boom)
    assert isinstance(dynamic_findings(), list)


def test_name_matching_helper():
    inst = {"easportsfc26", "riotgamesinc", "marvelrivals"}
    assert dynamic.name_matches_installed("EA SPORTS FC 26", inst)
    assert dynamic.name_matches_installed("Riot Games", inst)
    assert dynamic.name_matches_installed("MarvelRivals_Launcher", inst)
    assert not dynamic.name_matches_installed("Hogwarts Legacy", inst)
