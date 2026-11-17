"""Validações de segurança. TODA exclusão deve passar por `assert_deletable`.

Defesa em camadas (incidente de 16/11/2026: "C:\\" normalizado para "c:" = diretório ATUAL
do drive C, o que esvaziou a pasta do projeto):

1. Sintaxe: só caminhos absolutos totalmente qualificados `X:\\...` (nunca "c:", relativos,
   UNC, dispositivos, `..`).
2. Profundidade mínima: a raiz de um item precisa ter >= 2 componentes abaixo do drive.
3. Nunca raiz de unidade; nunca um ANCESTRAL de local protegido (Users, perfil, Windows...).
4. Locais protegidos calculados a partir do ambiente ATUAL **e** de um snapshot do ambiente real
   tirado no import (testes que alteram variáveis de ambiente não desligam a proteção real).
5. Nunca o diretório de trabalho atual, nem o diretório do próprio app, nem ancestrais deles.
6. Nunca pastas que são raiz de projeto/repositório (.git, .venv, pyproject.toml...).
7. Nunca atravessar reparse points (symlinks/junctions).
8. Arquivos sensíveis (cookies, logins, chaves) preservados mesmo dentro de um alvo.
"""
from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path


class UnsafePathError(Exception):
    pass


_ENV_KEYS = ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "ProgramData",
             "ProgramFiles", "ProgramFiles(x86)", "SystemRoot", "SystemDrive", "PUBLIC")
_REAL_ENV: dict[str, str] = {k: os.environ.get(k, "") for k in _ENV_KEYS}
_REAL_HOME = os.environ.get("USERPROFILE") or str(Path.home())

# Pasta do próprio app (código-fonte ou executável congelado).
_APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False)
                                           else os.path.dirname(os.path.dirname(__file__))))

_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")

PROJECT_MARKERS = (".git", ".hg", ".svn", ".venv", "pyproject.toml", "setup.py",
                   "setup.cfg", "Cargo.toml", "go.mod", ".sln")


def norm(p: str | os.PathLike[str]) -> str:
    """Caminho absoluto normalizado (minúsculas) para COMPARAÇÃO. Mantém a barra de raiz de drive."""
    s = os.path.normcase(os.path.abspath(os.fspath(p)))
    drive, rest = os.path.splitdrive(s)
    rest = rest.rstrip("\\/")
    return drive + (rest if rest else "\\")


def is_within(child: str, parent: str) -> bool:
    c, p = norm(child), norm(parent)
    if c == p:
        return True
    prefix = p if p.endswith("\\") else p + "\\"
    return c.startswith(prefix)


def is_reparse_point(path: str | os.PathLike[str]) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)) or stat.S_ISLNK(st.st_mode)


def is_drive_root(path: str) -> bool:
    if not _ABS_RE.match(path or ""):
        # "c:" ou relativo: tratado como raiz/ambíguo — nunca aceitável.
        return True
    _, rest = os.path.splitdrive(os.path.abspath(path))
    return rest.strip("\\/") == ""


def path_depth(path: str) -> int:
    _, rest = os.path.splitdrive(os.path.abspath(path))
    return len([x for x in re.split(r"[\\/]+", rest) if x])


def _envs() -> list[dict[str, str]]:
    cur = {k: os.environ.get(k, "") for k in _ENV_KEYS}
    return [cur, _REAL_ENV]


def _homes() -> list[str]:
    hs = {_REAL_HOME}
    if os.environ.get("USERPROFILE"):
        hs.add(os.environ["USERPROFILE"])
    return [h for h in hs if h]


def protected_exact() -> list[str]:
    """Caminhos que NUNCA podem ser alvo direto de exclusão (nem ancestrais deles)."""
    out: list[str] = []
    for env in _envs():
        windir = env.get("SystemRoot") or r"C:\Windows"
        out += [
            windir,
            os.path.join(windir, "Temp"),
            os.path.join(windir, "SoftwareDistribution"),
            os.path.join(windir, "SoftwareDistribution", "Download"),
            os.path.join(windir, "Prefetch"),
            env.get("ProgramFiles") or r"C:\Program Files",
            env.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
            env.get("ProgramData") or r"C:\ProgramData",
            env.get("APPDATA", ""), env.get("LOCALAPPDATA", ""),
            env.get("TEMP", ""), env.get("TMP", ""), env.get("PUBLIC", ""),
        ]
    for home in _homes():
        out += [os.path.dirname(home), home, os.path.join(home, "AppData"),
                os.path.join(home, "AppData", "Local"), os.path.join(home, "AppData", "Roaming"),
                os.path.join(home, "AppData", "LocalLow"), os.path.join(home, ".cache")]
        for sub in ("Desktop", "Documents", "Pictures", "Videos", "Music", "Downloads",
                    "OneDrive", "Favorites", "Contacts", "Saved Games"):
            out.append(os.path.join(home, sub))
    return sorted({norm(x) for x in out if x})


def protected_trees() -> list[str]:
    """Árvores inteiras onde NADA pode ser apagado."""
    out: list[str] = []
    for env in _envs():
        windir = env.get("SystemRoot") or r"C:\Windows"
        out += [os.path.join(windir, s) for s in
                ("System32", "SysWOW64", "WinSxS", "Installer", "assembly", "Boot", "Fonts",
                 "servicing", "Microsoft.NET")]
        if env.get("APPDATA"):
            out += [os.path.join(env["APPDATA"], "Microsoft", s)
                    for s in ("Credentials", "Protect", "SystemCertificates", "Crypto")]
        if env.get("LOCALAPPDATA"):
            out.append(os.path.join(env["LOCALAPPDATA"], "Microsoft", "Credentials"))
    for home in _homes():
        out += [os.path.join(home, s) for s in
                (".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", "Documents", "Pictures",
                 "Videos", "Music", "Desktop")]
        out += [p for p in _glob_onedrive(home)]
    return sorted({norm(x) for x in out if x})


def _glob_onedrive(home: str) -> list[str]:
    try:
        return [e.path for e in os.scandir(home) if e.is_dir(follow_symlinks=False)
                and e.name.lower().startswith("onedrive")]
    except OSError:
        return []


SENSITIVE_FILE_NAMES = {
    "cookies", "cookies-journal", "login data", "login data-journal", "login data for account",
    "web data", "web data-journal", "history", "bookmarks", "preferences", "secure preferences",
    "local state", "key4.db", "logins.json", "cert9.db", "places.sqlite", "cookies.sqlite",
    "id_rsa", "id_ed25519", "known_hosts", ".git-credentials", ".netrc", ".env",
}


def is_sensitive_file(path: str) -> bool:
    return os.path.basename(path).lower() in SENSITIVE_FILE_NAMES


def assert_safe_path_syntax(path: str) -> None:
    if not path or not isinstance(path, str):
        raise UnsafePathError("Caminho vazio")
    if "\x00" in path:
        raise UnsafePathError("Caminho contém byte nulo")
    if path.startswith(("\\\\", "//")):
        raise UnsafePathError(f"Caminhos UNC/dispositivo não são permitidos: {path}")
    if not _ABS_RE.match(path):
        raise UnsafePathError(f"Caminho precisa ser absoluto e completo (X:\\...): {path}")
    if ".." in re.split(r"[\\/]+", path):
        raise UnsafePathError(f"Path traversal detectado: {path}")


def is_project_root(path: str) -> bool:
    try:
        names = {e.name.lower() for e in os.scandir(path)}
    except OSError:
        return False
    if any(m.lower() in names for m in PROJECT_MARKERS):
        return True
    return any(n.endswith(".sln") for n in names)


def assert_target_root_allowed(root: str) -> None:
    """Valida o caminho de um Finding (raiz da limpeza)."""
    assert_safe_path_syntax(root)
    if is_drive_root(root):
        raise UnsafePathError(f"Raiz de unidade nunca pode ser limpa: {root}")
    if path_depth(root) < 2:
        raise UnsafePathError(f"Caminho raso demais para limpeza: {root}")
    n = norm(root)
    for t in protected_trees():
        if is_within(n, t):
            raise UnsafePathError(f"Caminho dentro de área protegida: {root}")
    for p in protected_exact():
        if is_within(p, n) and p != n:
            raise UnsafePathError(f"Caminho contém área protegida ({p}): {root}")
    for special in (os.getcwd(), _APP_DIR):
        if is_within(special, n):
            raise UnsafePathError(f"Caminho contém o diretório atual/do aplicativo: {root}")
    if is_within(n, _APP_DIR):
        raise UnsafePathError(f"Caminho dentro da pasta do próprio aplicativo: {root}")
    if is_project_root(root):
        raise UnsafePathError(f"Pasta é raiz de projeto/repositório — nunca limpa: {root}")


def assert_deletable(target: str, scope_root: str, *, allow_scope_root: bool) -> None:
    """Verifica se `target` pode ser apagado dentro do escopo `scope_root`.

    allow_scope_root=True permite apagar o próprio scope_root (CleanMode.WHOLE).
    """
    assert_safe_path_syntax(target)
    assert_target_root_allowed(scope_root)
    t, r = norm(target), norm(scope_root)
    if not is_within(t, r):
        raise UnsafePathError(f"Fora do escopo autorizado: {target} (escopo {scope_root})")
    if t == r and not allow_scope_root:
        raise UnsafePathError(f"A pasta raiz do item não pode ser removida neste modo: {target}")
    if t in protected_exact():
        raise UnsafePathError(f"Caminho protegido: {target}")
    for tree in protected_trees():
        if is_within(t, tree):
            raise UnsafePathError(f"Caminho dentro de área protegida: {target}")
    for special in (os.getcwd(), _APP_DIR):
        if is_within(special, t):
            raise UnsafePathError(f"Alvo contém o diretório atual/do aplicativo: {target}")
    if is_sensitive_file(t):
        raise UnsafePathError(f"Arquivo sensível (credenciais/sessões) preservado: {target}")
    cur = os.path.dirname(os.path.abspath(target))
    root_abs = os.path.abspath(scope_root)
    while is_within(cur, root_abs) and norm(cur) != norm(root_abs):
        if is_reparse_point(cur):
            raise UnsafePathError(f"Ancestral é link/junção: {cur}")
        cur = os.path.dirname(cur)
