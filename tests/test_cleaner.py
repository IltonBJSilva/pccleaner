"""Testes do cleaner. Todos os alvos ficam em tmp_path; caminhos reais só em testes com
funções de exclusão substituídas por AssertionError."""
from __future__ import annotations

import ctypes
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from pccleaner import cleaner
from pccleaner.cleaner import engine, safe_fs
from pccleaner.core.models import CancelToken, Category, CleanMode, Finding, SafetyLevel
from pccleaner.quarantine import QuarantineManager


def mk(path, *, mode=CleanMode.CONTENTS, safety=SafetyLevel.SAFE, category=Category.APP_CACHE,
       app="TestApp", min_age_days=0, size=100, name="Item", requires_admin=False) -> Finding:
    p = str(path)
    return Finding(id=Finding.make_id(p, "t"), rule_id="t", name=name, path=p, category=category, app=app,
                   safety=safety, reason="r", recommendation="r", clean_mode=mode, size_bytes=size,
                   min_age_days=min_age_days, requires_admin=requires_admin)


def write(path: Path, data: bytes = b"x" * 100, age_days: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if age_days is not None:
        t = time.time() - age_days * 86400
        os.utime(path, (t, t))
    return path


@pytest.fixture
def qm(tmp_path):
    return QuarantineManager(tmp_path / "quarantine")


def test_contents_keeps_root(tmp_path, qm):
    root = tmp_path / "w" / "cache"
    write(root / "a.tmp", b"a" * 10)
    write(root / "sub" / "deep" / "c.tmp", b"c" * 30)
    rep = cleaner.clean([mk(root)], quarantine_manager=qm)
    assert root.is_dir() and list(root.iterdir()) == []
    assert rep.freed_bytes == 40 and rep.files_removed == 2 and rep.items[0].errors == []
    assert not rep.items[0].quarantined   # SAFE em CONTENTS: apagado direto


def test_min_age_days(tmp_path, qm):
    root = tmp_path / "w" / "logs"
    old = write(root / "old.log", age_days=40)
    new = write(root / "new.log")
    rep = cleaner.clean([mk(root, min_age_days=30)], quarantine_manager=qm)
    assert not old.exists() and new.exists() and rep.files_removed == 1


def test_locked_file_skipped(tmp_path, qm):
    root = tmp_path / "w" / "cache"
    locked, free = write(root / "locked.bin"), write(root / "free.bin")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k32.CreateFileW(str(locked), 0x80000000, 0, None, 3, 0x80, None)   # share mode 0
    assert h not in (None, ctypes.c_void_p(-1).value)
    try:
        rep = cleaner.clean([mk(root)], quarantine_manager=qm)
    finally:
        k32.CloseHandle(h)
    assert locked.exists() and not free.exists()
    assert rep.items[0].files_skipped == 1 and any("locked.bin" in e for e in rep.items[0].errors)


def test_readonly_removed(tmp_path, qm):
    f = write(tmp_path / "w" / "cache" / "ro.txt")
    os.chmod(f, stat.S_IREAD)
    cleaner.clean([mk(f.parent)], quarantine_manager=qm)
    assert not f.exists()


def test_junction_unlinked_not_followed(tmp_path, qm):
    sentinel = tmp_path / "sentinel"
    s1 = write(sentinel / "nested" / "keep.txt")
    root = tmp_path / "w" / "cache"
    write(root / "junk.tmp")
    link = root / "link"
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(sentinel)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("mklink /J indisponível")
    rep = cleaner.clean([mk(root)], quarantine_manager=qm)
    assert not os.path.lexists(link) and s1.exists()
    assert rep.items[0].errors == []


def test_sensitive_files_preserved(tmp_path, qm):
    root = tmp_path / "w" / "Profile"
    cookies, junk = write(root / "Cookies"), write(root / "Cache" / "data_0")
    rep = cleaner.clean([mk(root)], quarantine_manager=qm)
    assert cookies.exists() and not junk.exists() and rep.items[0].files_skipped == 1


def test_whole_quarantine_then_restore(tmp_path, qm):
    root = tmp_path / "w" / "oldapp"
    f = write(root / "sub" / "data.bin", b"d" * 50)
    rep = cleaner.clean([mk(root, mode=CleanMode.WHOLE, safety=SafetyLevel.REVIEW)], quarantine_manager=qm)
    assert rep.items[0].quarantined and not root.exists() and rep.freed_bytes == 50
    (b,) = qm.list_batches()
    assert qm.restore(b.batch_id) == 1 and f.read_bytes() == b"d" * 50


def test_whole_without_quarantine(tmp_path, qm):
    root = tmp_path / "w" / "build"
    write(root / "a" / "b.o", b"1" * 50)
    rep = cleaner.clean([mk(root, mode=CleanMode.WHOLE)], use_quarantine=False, quarantine_manager=qm)
    assert not root.exists() and rep.freed_bytes == 50


def test_contents_review_quarantined(tmp_path, qm):
    root = tmp_path / "w" / "logs"
    a = write(root / "a.log", b"a" * 10)
    rep = cleaner.clean([mk(root, safety=SafetyLevel.REVIEW)], quarantine_manager=qm)
    assert rep.items[0].quarantined and not a.exists() and root.is_dir()
    assert qm.restore(qm.list_batches()[0].batch_id) == 1 and a.exists()


def test_command_and_protected_skipped(tmp_path, qm):
    f = write(tmp_path / "w" / "pip" / "x.whl")
    rep = cleaner.clean([mk(f.parent, mode=CleanMode.COMMAND), mk(f.parent, safety=SafetyLevel.PROTECTED)],
                        quarantine_manager=qm)
    assert f.exists() and all(i.errors for i in rep.items)


def test_cancel_stops(tmp_path, qm):
    r1, r2 = tmp_path / "w" / "c1", tmp_path / "w" / "c2"
    f1, f2 = write(r1 / "a.tmp"), write(r2 / "a.tmp")
    tok = CancelToken()

    def progress(path, done, total):
        if done == 1:
            tok.cancel()

    rep = cleaner.clean([mk(r1), mk(r2)], progress=progress, cancel=tok, quarantine_manager=qm)
    assert rep.cancelled and not f1.exists() and f2.exists()


def test_recycle_bin_uses_shell_api(monkeypatch, qm):
    monkeypatch.setattr(engine, "recycle_bin_info", lambda: (123, 3))
    called = []
    monkeypatch.setattr(engine, "empty_recycle_bin", lambda: called.append(1))
    rep = cleaner.clean([mk("X:\\$Recycle.Bin", mode=CleanMode.RECYCLE_BIN, category=Category.RECYCLE_BIN)],
                        quarantine_manager=qm)
    assert called and rep.freed_bytes == 123


# ---------------------------------------------------------------- caminhos perigosos (sem exclusão possível)
@pytest.fixture
def no_delete(monkeypatch):
    def boom(*a, **k):
        raise AssertionError(f"exclusão NÃO deveria ocorrer: {a}")
    for mod, name in ((os, "remove"), (os, "unlink"), (os, "rmdir"), (os, "removedirs"), (os, "rename"),
                      (os, "replace"), (shutil, "rmtree"), (shutil, "move")):
        monkeypatch.setattr(mod, name, boom)
    for name in ("remove_file", "remove_link", "remove_empty_dir"):
        monkeypatch.setattr(safe_fs, name, boom)


@pytest.mark.parametrize("path", ["C:", "c:", "C:\\", "c:\\", "C:/", "relative\\dir"])
@pytest.mark.parametrize("mode", [CleanMode.CONTENTS, CleanMode.WHOLE])
def test_clean_refuses_dangerous_paths_without_deleting(no_delete, path, mode):
    rep = cleaner.clean([mk(path, mode=mode)], use_quarantine=False)
    assert rep.freed_bytes == 0 and rep.files_removed == 0
    assert any("segurança" in e for e in rep.items[0].errors)


def test_clean_refuses_cwd_and_ancestors(no_delete, tmp_path):
    cwd = os.getcwd()
    for p in (cwd, os.path.dirname(cwd), str(tmp_path.parent)):
        rep = cleaner.clean([mk(p)], use_quarantine=False)
        assert rep.items[0].errors and rep.files_removed == 0


def test_independent_root_checks():
    for bad in ("C:", "c:", "C:\\", "C:\\one", "\\\\srv\\share\\x", "C:\\a\\..\\b"):
        with pytest.raises(Exception):
            safe_fs.assert_independent_root(bad)
    with pytest.raises(Exception):
        safe_fs.assert_independent_root(os.getcwd())
    with pytest.raises(Exception):
        safe_fs.assert_independent_root(os.path.join(safe_fs._APP_ROOT, "pccleaner"))


def test_preview_consequences():
    msgs = "\n".join(cleaner.preview_consequences([
        mk("X:\\a\\b", category=Category.BROWSER_CACHE, app="Google Chrome"),
        mk("X:\\a\\hf", app="Hugging Face"),
        mk("X:\\a\\big", mode=CleanMode.WHOLE, safety=SafetyLevel.CAUTION, size=5 * 1024 ** 3,
           requires_admin=True, name="Grande"),
        mk("X:\\a\\pip", mode=CleanMode.COMMAND)]))
    for s in ("Navegadores precisarão recarregar páginas", "Modelos de IA serão baixados novamente",
              "administrador", "DEFINITIVAMENTE", "Feche", "limpeza manual"):
        assert s in msgs
