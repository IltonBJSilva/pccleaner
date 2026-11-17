"""Primitivas de sistema de arquivos: medição de árvores sem seguir links, listagens e expansão de padrões."""
from __future__ import annotations

import fnmatch
import heapq
import os
import stat
import time
from typing import Iterator

from pccleaner.core.models import CancelToken, FolderStat, LargeFile

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
# Arquivos "somente na nuvem" (OneDrive/Arquivos sob demanda): o tamanho lógico não ocupa disco.
CLOUD_ONLY = 0x1000 | 0x40000 | 0x400000   # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS


def entry_is_link(entry: os.DirEntry, st: os.stat_result | None = None) -> bool:
    """True para symlink, junction ou qualquer reparse point."""
    try:
        if entry.is_symlink():
            return True
        if hasattr(entry, "is_junction") and entry.is_junction():
            return True
        if st is None:
            st = entry.stat(follow_symlinks=False)
        return bool(getattr(st, "st_file_attributes", 0) & REPARSE)
    except OSError:
        return True


def path_is_link(path: str) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    if getattr(os.path, "isjunction", None) and os.path.isjunction(path):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & REPARSE)


def disk_bytes(st: os.stat_result) -> int:
    """Tamanho que conta como espaço em disco (0 para arquivos que estão só na nuvem)."""
    if getattr(st, "st_file_attributes", 0) & CLOUD_ONLY:
        return 0
    return st.st_size


def iter_files(path: str, cancel: CancelToken | None = None,
               errors: list[str] | None = None) -> Iterator[tuple[str, os.stat_result]]:
    """Itera (caminho, stat) de todos os arquivos sob `path`, sem seguir links/junctions."""
    stack = [path]
    while stack:
        if cancel is not None and cancel.cancelled:
            return
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError as e:
            if errors is not None and len(errors) < 500:
                errors.append(f"{d}: {e.strerror or e}")
            continue
        with it:
            for entry in it:
                try:
                    st = entry.stat(follow_symlinks=False)
                    if entry_is_link(entry, st):
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(entry.path)
                    else:
                        yield entry.path, st
                except OSError as e:
                    if errors is not None and len(errors) < 500:
                        errors.append(f"{entry.path}: {e.strerror or e}")


def measure_tree(path: str, cancel: CancelToken | None = None,
                 min_age_days: int = 0) -> tuple[int, int, float | None]:
    """Retorna (bytes, arquivos, mtime_mais_recente). Com min_age_days>0 só conta arquivos mais antigos que N dias.

    `newest_mtime` considera todos os arquivos (indica se a pasta está em uso), não só os contados.
    Aceita também um arquivo isolado. Nunca segue symlinks/junctions.
    """
    cutoff = time.time() - min_age_days * 86400 if min_age_days > 0 else None
    try:
        st = os.lstat(path)
    except OSError:
        return 0, 0, None
    if path_is_link(path):
        return 0, 0, None
    if not stat.S_ISDIR(st.st_mode):
        if cutoff is not None and st.st_mtime >= cutoff:
            return 0, 0, st.st_mtime
        return disk_bytes(st), 1, st.st_mtime
    total = count = 0
    newest: float | None = None
    for _p, fst in iter_files(path, cancel):
        m = fst.st_mtime
        if newest is None or m > newest:
            newest = m
        if cutoff is not None and m >= cutoff:
            continue
        total += disk_bytes(fst)
        count += 1
    return total, count, newest


def list_children(path: str, cancel: CancelToken | None = None) -> list[FolderStat]:
    """Filhos imediatos de `path` (pastas medidas recursivamente e arquivos), ordenados por tamanho desc."""
    out: list[FolderStat] = []
    try:
        with os.scandir(path) as it:
            entries = list(it)
    except OSError:
        return out
    for entry in entries:
        if cancel is not None and cancel.cancelled:
            break
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if entry_is_link(entry, st):
            out.append(FolderStat(entry.path, 0, 0, None))
        elif stat.S_ISDIR(st.st_mode):
            b, n, m = measure_tree(entry.path, cancel)
            out.append(FolderStat(entry.path, b, n, m))
        else:
            out.append(FolderStat(entry.path, disk_bytes(st), 1, st.st_mtime))
    out.sort(key=lambda f: f.size_bytes, reverse=True)
    return out


def list_files(path: str, limit: int = 500) -> list[LargeFile]:
    """Maiores arquivos dentro de `path` (recursivo), ordenados por tamanho desc."""
    try:
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            return [LargeFile(path, disk_bytes(st), st.st_mtime, st.st_atime)]
    except OSError:
        return []
    heap: list[tuple[int, str, float, float]] = []
    for p, fst in iter_files(path):
        item = (disk_bytes(fst), p, fst.st_mtime, fst.st_atime)
        if len(heap) < limit:
            heapq.heappush(heap, item)
        elif item[0] > heap[0][0]:
            heapq.heapreplace(heap, item)
    heap.sort(reverse=True)
    return [LargeFile(p, s, m, a) for s, p, m, a in heap]


# ---------------------------------------------------------------- expansão de padrões

def _has_magic(s: str) -> bool:
    return any(c in s for c in "*?[")


def expand_pattern(pattern: str, *, dirs_only: bool = False) -> list[str]:
    """Expande %VARS% e curingas (*, ?) segmento a segmento, sem seguir junctions.

    Não usa `glob` para evitar problemas com colchetes em nomes de usuário e para casar arquivos ocultos/ponto.
    Variáveis não definidas fazem o padrão ser ignorado.
    """
    expanded = os.path.expandvars(pattern)
    if "%" in expanded:
        return []
    expanded = os.path.normpath(expanded)
    drive, rest = os.path.splitdrive(expanded)
    if not drive:
        return []
    parts = [p for p in rest.replace("/", "\\").split("\\") if p]
    current = [drive + "\\"]
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        nxt: list[str] = []
        if _has_magic(part):
            pat = part.lower()
            for base in current:
                try:
                    with os.scandir(base) as it:
                        for e in it:
                            if not fnmatch.fnmatchcase(e.name.lower(), pat):
                                continue
                            try:
                                is_dir = e.is_dir(follow_symlinks=False)
                            except OSError:
                                continue
                            if entry_is_link(e):
                                continue
                            if not last and not is_dir:
                                continue
                            if last and dirs_only and not is_dir:
                                continue
                            nxt.append(e.path)
                except OSError:
                    continue
        else:
            for base in current:
                p = os.path.join(base, part)
                if last:
                    if os.path.lexists(p) and not path_is_link(p):
                        if dirs_only and not os.path.isdir(p):
                            continue
                        nxt.append(p)
                elif os.path.isdir(p) and not path_is_link(p):
                    nxt.append(p)
        current = nxt
        if not current:
            return []
    return sorted(set(current))


def marker_present(parent: str, marker: str, names_lower: set[str] | None = None) -> bool:
    """Verifica marcador irmão: nome exato, caminho relativo (a\\b) ou curinga (*.csproj)."""
    if _has_magic(marker):
        if names_lower is None:
            try:
                names_lower = {n.lower() for n in os.listdir(parent)}
            except OSError:
                return False
        pat = marker.lower()
        return any(fnmatch.fnmatchcase(n, pat) for n in names_lower)
    if names_lower is not None and "\\" not in marker and "/" not in marker:
        return marker.lower() in names_lower
    return os.path.exists(os.path.join(parent, marker))
