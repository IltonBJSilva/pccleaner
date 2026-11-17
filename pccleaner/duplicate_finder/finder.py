"""Localizador de arquivos duplicados (somente leitura — NUNCA apaga nada).

Agrupa por tamanho -> hash parcial (primeiros 64 KB) -> SHA-256 completo em streaming.
Não segue reparse points e ignora pastas do sistema (Windows, Program Files...).
"""
from __future__ import annotations

import hashlib
import logging
import os
import stat
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from pccleaner.core import security
from pccleaner.core.models import CancelToken

log = logging.getLogger("pccleaner.duplicates")

PARTIAL_BYTES = 64 * 1024
_CHUNK = 1024 * 1024
_SKIP_NAMES = {"$recycle.bin", "system volume information", "$windows.~bt", "$windows.~ws",
               "windowsapps", "$winreagent"}


@dataclass
class DuplicateGroup:
    sha256: str
    size_bytes: int
    paths: list[str] = field(default_factory=list)

    @property
    def wasted_bytes(self) -> int:
        return self.size_bytes * max(0, len(self.paths) - 1)


def _excluded_roots() -> list[str]:
    env = os.environ
    cands = [env.get("SystemRoot", r"C:\Windows"), env.get("ProgramFiles", r"C:\Program Files"),
             env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), env.get("ProgramW6432", "")]
    return [security.norm(c) for c in cands if c]


def _hash_file(path: str, limit: int | None, cancel: CancelToken | None) -> str | None:
    h = hashlib.sha256()
    remaining = limit
    try:
        with open(path, "rb") as fh:
            while remaining is None or remaining > 0:
                if cancel is not None and cancel.cancelled:
                    return None
                buf = fh.read(_CHUNK if remaining is None else min(_CHUNK, remaining))
                if not buf:
                    break
                h.update(buf)
                if remaining is not None:
                    remaining -= len(buf)
    except OSError:
        return None
    return h.hexdigest()


def find_duplicates(roots: list[str], min_size_bytes: int = 1024 * 1024,
                    progress: Callable[[str, int], None] | None = None,
                    cancel: CancelToken | None = None) -> list[DuplicateGroup]:
    excluded = _excluded_roots()
    by_size: dict[int, list[str]] = defaultdict(list)
    seen_paths: set[str] = set()
    seen_inodes: set[tuple[int, int]] = set()
    count = 0

    def cancelled() -> bool:
        return cancel is not None and cancel.cancelled

    stack = [os.path.abspath(r) for r in roots if r and os.path.isdir(r)]
    while stack and not cancelled():
        d = stack.pop()
        if any(security.is_within(d, ex) for ex in excluded) or security.is_reparse_point(d):
            continue
        try:
            with os.scandir(d) as it:
                entries = list(it)
        except OSError:
            continue
        for e in entries:
            if cancelled():
                break
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if getattr(st, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(st.st_mode):
                continue   # reparse point: nunca seguir
            if stat.S_ISDIR(st.st_mode):
                if e.name.lower() not in _SKIP_NAMES:
                    stack.append(e.path)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            count += 1
            if progress is not None and count % 200 == 0:
                progress(e.path, count)
            if st.st_size < max(1, min_size_bytes):
                continue
            key = security.norm(e.path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            if st.st_ino:
                ino = (st.st_dev, st.st_ino)
                if ino in seen_inodes:   # hard link: não desperdiça espaço
                    continue
                seen_inodes.add(ino)
            by_size[st.st_size].append(e.path)

    groups: list[DuplicateGroup] = []
    for size, paths in by_size.items():
        if cancelled():
            break
        if len(paths) < 2:
            continue
        partial: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            hp = _hash_file(p, PARTIAL_BYTES, cancel)
            if hp is not None:
                partial[hp].append(p)
        for cand in partial.values():
            if len(cand) < 2:
                continue
            full: dict[str, list[str]] = defaultdict(list)
            for p in cand:
                if progress is not None:
                    progress(p, count)
                hf = _hash_file(p, None, cancel)
                if hf is not None:
                    full[hf].append(p)
            for digest, same in full.items():
                if len(same) >= 2:
                    groups.append(DuplicateGroup(sha256=digest, size_bytes=size, paths=sorted(same)))
    groups.sort(key=lambda g: (g.wasted_bytes, g.size_bytes), reverse=True)
    return groups
