"""Testes de security.* — apenas funções de VALIDAÇÃO (nada é apagado aqui)."""
from __future__ import annotations

import os
import subprocess

import pytest

from pccleaner.core import security as s

E = s.UnsafePathError


@pytest.mark.parametrize("p", ["C:\\", "c:", "C:", "c:\\", "C:/", "D:\\"])
def test_old_bug_drive_root_refused(p):
    with pytest.raises(E):
        s.assert_target_root_allowed(p)


@pytest.mark.parametrize("p", ["", "relative\\x\\y", "\\\\server\\share\\x\\y", "\\\\?\\C:\\x\\y",
                               "C:\\a\\..\\..\\b\\c", "C:\\onlyone"])
def test_bad_syntax_or_shallow(p):
    with pytest.raises(E):
        s.assert_target_root_allowed(p)


def test_ancestor_of_protected_denied():
    home = s._REAL_HOME
    with pytest.raises(E):
        s.assert_target_root_allowed(os.path.dirname(home))      # C:\Users
    with pytest.raises(E):
        s.assert_target_root_allowed(os.path.join(home, "AppData"))


def test_project_root_denied(tmp_path):
    proj = tmp_path / "proj"
    (proj / ".git").mkdir(parents=True)
    with pytest.raises(E):
        s.assert_target_root_allowed(str(proj))
    (tmp_path / "py" ).mkdir()
    (tmp_path / "py" / "pyproject.toml").write_text("")
    with pytest.raises(E):
        s.assert_target_root_allowed(str(tmp_path / "py"))


def test_app_dir_and_cwd_denied():
    with pytest.raises(E):
        s.assert_target_root_allowed(s._APP_DIR)
    with pytest.raises(E):
        s.assert_target_root_allowed(os.path.join(s._APP_DIR, "pccleaner", "cleaner"))
    with pytest.raises(E):
        s.assert_target_root_allowed(os.getcwd())
    with pytest.raises(E):
        s.assert_target_root_allowed(os.path.dirname(os.getcwd()))


def test_real_env_snapshot_still_protects(fake_env):
    real_docs = os.path.join(s._REAL_HOME, "Documents", "x")
    assert os.environ["USERPROFILE"] != s._REAL_HOME
    with pytest.raises(E):
        s.assert_target_root_allowed(real_docs)
    with pytest.raises(E):
        s.assert_deletable(os.path.join(s._REAL_HOME, ".ssh", "id_x"), os.path.join(s._REAL_HOME, ".ssh"),
                           allow_scope_root=False)
    # e o ambiente falso também é protegido
    with pytest.raises(E):
        s.assert_target_root_allowed(str(fake_env["USERPROFILE"] / "Documents" / "a"))


def test_assert_deletable_rules(tmp_path):
    scope = tmp_path / "w" / "cache"
    scope.mkdir(parents=True)
    ok = str(scope / "a.tmp")
    s.assert_deletable(ok, str(scope), allow_scope_root=False)
    with pytest.raises(E):
        s.assert_deletable(str(scope), str(scope), allow_scope_root=False)
    s.assert_deletable(str(scope), str(scope), allow_scope_root=True)
    with pytest.raises(E):
        s.assert_deletable(str(tmp_path / "w" / "other.txt"), str(scope), allow_scope_root=False)
    with pytest.raises(E):
        s.assert_deletable(str(scope / ".." / "x"), str(scope), allow_scope_root=False)
    for name in ("Cookies", "Login Data", "key4.db", ".env"):
        with pytest.raises(E):
            s.assert_deletable(str(scope / name), str(scope), allow_scope_root=False)


def test_ancestor_junction_refused(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    scope = tmp_path / "w" / "cache"
    scope.mkdir(parents=True)
    link = scope / "j"
    if subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True).returncode:
        pytest.skip("mklink /J indisponível")
    assert s.is_reparse_point(str(link))
    with pytest.raises(E):
        s.assert_deletable(str(link / "f.txt"), str(scope), allow_scope_root=False)
