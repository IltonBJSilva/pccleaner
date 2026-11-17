"""Primitivas de exclusão seguras (sem seguir reparse points).

Todo alvo passa por `security.assert_deletable` ANTES de qualquer operação destrutiva e toda
raiz passa por `assert_independent_root` (defesa em profundidade, independente de security.py).
Nunca usa shutil.rmtree nem comandos de shell (del/rd/rm).
"""
from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Callable

from pccleaner.core import security
from pccleaner.core.models import CancelToken

log = logging.getLogger("pccleaner.cleaner")

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_DIRECTORY = 0x10
MAX_ERRORS_PER_ITEM = 50

# WinError: 32 = arquivo em uso, 33 = região bloqueada, 145 = pasta não vazia
_LOCK_ERRORS = {32, 33}
_DIR_NOT_EMPTY = {145}

_FULL_PATH_RE = re.compile(r"^[A-Za-z]:\\")
_APP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _components(path: str) -> list[str]:
    return [c for c in re.split(r"[\\/]+", path[3:]) if c]


def assert_independent_root(path: str) -> None:
    """Verificações próprias do cleaner, independentes de security.py (incidente 16/11/2026).

    Recusa: caminho que não seja `X:\\...` totalmente qualificado com >= 2 componentes;
    raiz de unidade; o diretório atual ou qualquer ancestral dele; a pasta do app ou ancestrais;
    qualquer coisa dentro da pasta do app.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        raise security.UnsafePathError(f"Caminho inválido: {path!r}")
    if not _FULL_PATH_RE.match(path):
        raise security.UnsafePathError(f"Caminho precisa ser absoluto e completo (X:\\...): {path}")
    comps = _components(path)
    if len(comps) < 2 or any(c in (".", "..") for c in comps):
        raise security.UnsafePathError(f"Caminho raso demais ou com '..': {path}")
    if security.is_drive_root(path):
        raise security.UnsafePathError(f"Raiz de unidade: {path}")
    p = os.path.normcase(os.path.normpath(path)).rstrip("\\")
    for special in (os.getcwd(), _APP_ROOT):
        s = os.path.normcase(os.path.normpath(special)).rstrip("\\")
        if s == p or s.startswith(p + "\\"):
            raise security.UnsafePathError(f"Caminho é (ou contém) o diretório atual/do app: {path}")
    a = os.path.normcase(os.path.normpath(_APP_ROOT)).rstrip("\\")
    if p.startswith(a + "\\"):
        raise security.UnsafePathError(f"Caminho dentro da pasta do app: {path}")


@dataclass
class WalkStats:
    freed: int = 0
    removed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False
    _suppressed: int = 0

    def add_error(self, msg: str) -> None:
        if len(self.errors) < MAX_ERRORS_PER_ITEM:
            self.errors.append(msg)
        else:
            self._suppressed += 1

    def finalize_errors(self) -> list[str]:
        out = list(self.errors)
        if self._suppressed:
            out.append(f"... e mais {self._suppressed} ocorrência(s) não listadas")
        return out


def _attrs(st: os.stat_result) -> int:
    return getattr(st, "st_file_attributes", 0)


def is_readonly(path: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return bool(_attrs(st) & FILE_ATTRIBUTE_READONLY) or not (st.st_mode & stat.S_IWRITE)


def is_lock_error(exc: BaseException) -> bool:
    return getattr(exc, "winerror", None) in _LOCK_ERRORS


def call_with_readonly_retry(fn: Callable[[str], object], path: str) -> None:
    """Executa fn(path); se falhar por atributo somente-leitura, limpa o atributo e tenta 1x."""
    try:
        fn(path)
    except PermissionError as exc:
        if is_lock_error(exc) or not is_readonly(path):
            raise
        os.chmod(path, stat.S_IWRITE)
        fn(path)


def remove_file(path: str) -> int:
    """Remove um arquivo comum (não link). Retorna o tamanho (lstat antes de apagar)."""
    size = os.lstat(path).st_size
    call_with_readonly_retry(os.unlink, path)
    log.info("Apagado: %s (%d bytes)", path, size)
    return size


def remove_link(path: str) -> None:
    """Remove um symlink/junção sem tocar no destino."""
    st = os.lstat(path)
    if _attrs(st) & FILE_ATTRIBUTE_DIRECTORY:
        call_with_readonly_retry(os.rmdir, path)   # junção / symlink de pasta: remove só o link
    else:
        call_with_readonly_retry(os.unlink, path)
    log.info("Link removido (destino preservado): %s", path)


def remove_empty_dir(path: str) -> bool:
    """Remove a pasta se estiver vazia. Retorna False se não estiver vazia."""
    try:
        with os.scandir(path) as it:
            if next(it, None) is not None:
                return False
    except FileNotFoundError:
        return False
    try:
        call_with_readonly_retry(os.rmdir, path)
    except OSError as exc:
        if getattr(exc, "winerror", None) in _DIR_NOT_EMPTY:
            return False
        raise
    log.info("Pasta vazia removida: %s", path)
    return True


FileAction = Callable[[str], int]   # recebe caminho validado, retorna bytes liberados


def process_tree(
    root: str,
    scope: str,
    stats: WalkStats,
    *,
    cutoff: float | None = None,
    file_action: FileAction | None = None,
    cancel: CancelToken | None = None,
    on_file: Callable[[str], None] | None = None,
    remove_dirs: bool = True,
) -> None:
    """Percorre `root` (pasta) apagando seu CONTEÚDO, nunca a própria `root`.

    - Não segue reparse points: links/junções são removidos como link.
    - cutoff: só processa arquivos com mtime < cutoff (None = todos).
    - file_action: ação para cada arquivo já validado (padrão: remove_file).
    - Subpastas são removidas de baixo para cima quando ficam vazias.
    """
    assert_independent_root(scope)
    security.assert_target_root_allowed(scope)
    if not security.is_within(root, scope):
        raise security.UnsafePathError(f"Fora do escopo autorizado: {root}")
    action = file_action or remove_file
    stack: list[tuple[str, bool]] = [(root, False)]   # pós-ordem iterativa
    while stack:
        if cancel is not None and cancel.cancelled:
            stats.cancelled = True
            return
        d, visited = stack.pop()
        if visited:
            if d != root and remove_dirs:
                _try_remove_dir(d, scope, stats)
            continue
        stack.append((d, True))
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError as exc:
            stats.add_error(f"Não foi possível listar {d}: {exc}")
            continue
        for entry in entries:
            if cancel is not None and cancel.cancelled:
                stats.cancelled = True
                return
            p = entry.path
            if on_file is not None:
                on_file(p)
            try:
                st = os.lstat(p)
            except FileNotFoundError:
                continue
            except OSError as exc:
                stats.skipped += 1
                stats.add_error(f"Sem acesso: {p}: {exc}")
                continue
            if security.is_reparse_point(p):
                _handle_link(p, scope, stats)
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append((p, False))
                continue
            if cutoff is not None and st.st_mtime >= cutoff:
                continue   # recente demais — mantido por regra de idade
            _handle_file(p, scope, stats, action)


def _handle_link(p: str, scope: str, stats: WalkStats) -> None:
    try:
        security.assert_deletable(p, scope, allow_scope_root=False)
        remove_link(p)
        stats.removed += 1
    except security.UnsafePathError as exc:
        stats.skipped += 1
        stats.add_error(f"Preservado: {exc}")
    except OSError as exc:
        stats.skipped += 1
        stats.add_error(f"Falha ao remover link {p}: {exc}")


def _handle_file(p: str, scope: str, stats: WalkStats, action: FileAction) -> None:
    try:
        security.assert_deletable(p, scope, allow_scope_root=False)
    except security.UnsafePathError as exc:
        stats.skipped += 1
        stats.add_error(f"Preservado: {exc}")
        return
    try:
        stats.freed += action(p)
        stats.removed += 1
    except FileNotFoundError:
        pass
    except PermissionError as exc:
        stats.skipped += 1
        why = "em uso por outro programa" if is_lock_error(exc) else "acesso negado"
        stats.add_error(f"Ignorado ({why}): {p}")
        log.warning("Ignorado (%s): %s", why, p)
    except OSError as exc:
        stats.skipped += 1
        stats.add_error(f"Falha ao apagar {p}: {exc}")
        log.warning("Falha ao apagar %s: %s", p, exc)


def _try_remove_dir(d: str, scope: str, stats: WalkStats) -> None:
    try:
        security.assert_deletable(d, scope, allow_scope_root=False)
    except security.UnsafePathError:
        return
    try:
        remove_empty_dir(d)
    except OSError as exc:
        if not is_lock_error(exc):
            stats.add_error(f"Não foi possível remover a pasta {d}: {exc}")


def delete_path(path: str, scope: str, stats: WalkStats, *, cancel: CancelToken | None = None,
                file_action: FileAction | None = None) -> None:
    """Apaga `path` inteiro (arquivo, link ou pasta) com o walker seguro."""
    assert_independent_root(scope)
    assert_independent_root(path)
    security.assert_deletable(path, scope, allow_scope_root=True)
    if security.is_reparse_point(path):
        remove_link(path)
        stats.removed += 1
        return
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        action = file_action or remove_file
        try:
            stats.freed += action(path)
            stats.removed += 1
        except PermissionError as exc:
            stats.skipped += 1
            why = "em uso por outro programa" if is_lock_error(exc) else "acesso negado"
            stats.add_error(f"Ignorado ({why}): {path}")
        return
    process_tree(path, scope, stats, cancel=cancel, file_action=file_action)
    if stats.cancelled:
        return
    try:
        if not remove_empty_dir(path):
            stats.add_error(f"Pasta mantida (ainda contém itens preservados/em uso): {path}")
    except OSError as exc:
        stats.add_error(f"Não foi possível remover a pasta {path}: {exc}")


def tree_size(path: str) -> tuple[int, int]:
    """(bytes, arquivos) sem seguir links. Somente leitura."""
    total = files = 0
    try:
        st0 = os.lstat(path)
        if not stat.S_ISDIR(st0.st_mode) or security.is_reparse_point(path):
            return st0.st_size, 1
    except OSError:
        return 0, 0
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if security.is_reparse_point(e.path):
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(e.path)
                    else:
                        total += st.st_size
                        files += 1
        except OSError:
            continue
    return total, files
