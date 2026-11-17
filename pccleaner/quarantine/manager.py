"""Quarentena reversível: itens são MOVIDOS para a pasta do app e podem ser restaurados.

Layout:  <base>/<batch_id>/batch.json      metadados (created_at)
         <base>/<batch_id>/items.jsonl     uma linha JSON por item (append O(1))
         <base>/<batch_id>/data/<uid>/<nome original>
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from pccleaner import config
from pccleaner.cleaner import safe_fs
from pccleaner.core import security

log = logging.getLogger("pccleaner.quarantine")

_BATCH_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ERROR_NOT_SAME_DEVICE = 17


@dataclass
class QuarantineBatch:
    batch_id: str
    created_at: float
    item_count: int
    size_bytes: int
    items: list[dict] = field(default_factory=list)


class QuarantineError(Exception):
    pass


class QuarantineManager:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else config.quarantine_dir()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        safe_fs.assert_independent_root(str(self.base_dir.resolve()))
        self._lock = threading.Lock()

    def _batch_dir(self, batch_id: str) -> Path:
        if not _BATCH_RE.match(batch_id or ""):
            raise QuarantineError(f"Identificador de lote inválido: {batch_id!r}")
        return self.base_dir / batch_id

    @staticmethod
    def _read_items(bdir: Path) -> list[dict]:
        items: list[dict] = []
        try:
            with open(bdir / "items.jsonl", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        try:
                            items.append(json.loads(line))
                        except ValueError:
                            log.warning("Linha de manifesto inválida em %s", bdir)
        except FileNotFoundError:
            pass
        return items

    @staticmethod
    def _write_items(bdir: Path, items: list[dict]) -> None:
        tmp = bdir / "items.jsonl.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for it in items:
                fh.write(json.dumps(it, ensure_ascii=False) + "\n")
        os.replace(tmp, bdir / "items.jsonl")

    @staticmethod
    def _read_meta(bdir: Path) -> dict:
        try:
            return json.loads((bdir / "batch.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"created_at": 0.0}

    def new_batch(self) -> str:
        batch_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
        bdir = self._batch_dir(batch_id)
        (bdir / "data").mkdir(parents=True)
        (bdir / "batch.json").write_text(json.dumps({"batch_id": batch_id, "created_at": time.time()}),
                                         encoding="utf-8")
        (bdir / "items.jsonl").touch()
        return batch_id

    def store(self, batch_id: str, path: str) -> str:
        """Move `path` (arquivo ou pasta) para a quarentena. Retorna o caminho armazenado."""
        bdir = self._batch_dir(batch_id)
        if not bdir.is_dir():
            raise QuarantineError(f"Lote inexistente: {batch_id}")
        safe_fs.assert_independent_root(path)
        path = os.path.abspath(path)
        security.assert_deletable(path, path, allow_scope_root=True)
        if security.is_within(path, str(self.base_dir)) or security.is_within(str(self.base_dir), path):
            raise security.UnsafePathError(f"Não é possível pôr a própria quarentena em quarentena: {path}")
        is_dir = stat.S_ISDIR(os.lstat(path).st_mode) and not security.is_reparse_point(path)
        size, _ = safe_fs.tree_size(path)
        dest_parent = bdir / "data" / uuid.uuid4().hex[:12]
        dest_parent.mkdir(parents=True)
        dest = dest_parent / (os.path.basename(path.rstrip("\\/")) or "item")
        try:
            os.rename(path, dest)
        except OSError as exc:
            if getattr(exc, "winerror", None) != _ERROR_NOT_SAME_DEVICE:
                _rmdir_quiet(dest_parent)
                raise
            self._cross_volume_move(path, str(dest), is_dir)
        entry = {"original_path": path, "stored_path": str(dest), "size": size, "is_dir": is_dir,
                 "stored_at": time.time()}
        with self._lock, open(bdir / "items.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        log.info("Quarentena [%s]: %s -> %s (%d bytes)", batch_id, path, dest, size)
        return str(dest)

    @staticmethod
    def _cross_volume_move(src: str, dest: str, is_dir: bool) -> None:
        if not is_dir:
            shutil.copy2(src, dest, follow_symlinks=False)
            try:
                safe_fs.call_with_readonly_retry(os.unlink, src)
            except OSError:
                _unlink_quiet(dest)
                raise
            return
        _copy_tree_no_links(src, dest)
        stats = safe_fs.WalkStats()
        safe_fs.delete_path(src, src, stats)
        if stats.errors:
            log.warning("Origem não removida por completo (%s): %s", src, "; ".join(stats.errors[:5]))

    def list_batches(self) -> list[QuarantineBatch]:
        out: list[QuarantineBatch] = []
        try:
            entries = list(os.scandir(self.base_dir))
        except OSError:
            return out
        for e in entries:
            if not e.is_dir(follow_symlinks=False) or not _BATCH_RE.match(e.name):
                continue
            bdir = Path(e.path)
            items = [{"original_path": i.get("original_path", ""), "stored_path": i.get("stored_path", ""),
                      "size": int(i.get("size", 0))} for i in self._read_items(bdir)]
            out.append(QuarantineBatch(batch_id=e.name,
                                       created_at=float(self._read_meta(bdir).get("created_at", 0.0)),
                                       item_count=len(items), size_bytes=sum(i["size"] for i in items),
                                       items=items))
        out.sort(key=lambda b: b.created_at, reverse=True)
        return out

    def restore(self, batch_id: str) -> int:
        """Restaura aos caminhos originais. Nunca sobrescreve: usa sufixo " (restaurado N)"."""
        bdir = self._batch_dir(batch_id)
        if not bdir.is_dir():
            raise QuarantineError(f"Lote inexistente: {batch_id}")
        restored = 0
        with self._lock:
            remaining: list[dict] = []
            for it in self._read_items(bdir):
                stored, original = it.get("stored_path", ""), it.get("original_path", "")
                if not stored or not original or not security.is_within(stored, str(bdir)):
                    remaining.append(it)
                    continue
                if not os.path.lexists(stored):
                    continue
                try:
                    security.assert_safe_path_syntax(original)
                    final = self._restore_one(stored, original)
                    restored += 1
                    log.info("Restaurado: %s -> %s", stored, final)
                    _rmdir_quiet(Path(stored).parent)
                except (OSError, security.UnsafePathError, QuarantineError) as exc:
                    log.warning("Falha ao restaurar %s: %s", original, exc)
                    remaining.append(it)
            if remaining:
                self._write_items(bdir, remaining)
            else:
                try:
                    safe_fs.delete_path(str(bdir), str(bdir), safe_fs.WalkStats())
                except (OSError, security.UnsafePathError) as exc:
                    log.warning("Não foi possível remover lote vazio %s: %s", bdir, exc)
        return restored

    @staticmethod
    def _restore_one(stored: str, original: str) -> str:
        parent = os.path.dirname(original)
        os.makedirs(parent, exist_ok=True)
        if os.path.isdir(stored) and not security.is_reparse_point(stored):
            base, ext = os.path.basename(original), ""
        else:
            base, ext = os.path.splitext(os.path.basename(original))
        candidate, n = original, 1
        while n <= 1000:
            if not os.path.lexists(candidate):
                try:
                    os.rename(stored, candidate)   # os.rename no Windows NUNCA sobrescreve
                    return candidate
                except FileExistsError:
                    pass
                except OSError as exc:
                    if getattr(exc, "winerror", None) != _ERROR_NOT_SAME_DEVICE:
                        raise
                    if os.path.isdir(stored):
                        _copy_tree_no_links(stored, candidate)
                        safe_fs.delete_path(stored, stored, safe_fs.WalkStats())
                    else:
                        shutil.copy2(stored, candidate)
                        os.unlink(stored)
                    return candidate
            candidate = os.path.join(parent, f"{base}{' (restaurado)' if n == 1 else f' (restaurado {n})'}{ext}")
            n += 1
        raise QuarantineError(f"Não foi possível achar nome livre para {original}")

    def purge(self, batch_id: str) -> int:
        """Apaga definitivamente o lote. Retorna bytes liberados."""
        bdir = self._batch_dir(batch_id)
        if not bdir.is_dir():
            return 0
        stats = safe_fs.WalkStats()
        with self._lock:
            safe_fs.delete_path(str(bdir), str(bdir), stats)
        if stats.errors:
            log.warning("Purga incompleta do lote %s: %s", batch_id, "; ".join(stats.errors[:5]))
        return stats.freed

    def purge_expired(self, keep_days: int) -> int:
        cutoff = time.time() - max(0, keep_days) * 86400
        return sum(self.purge(b.batch_id) for b in self.list_batches() if b.created_at < cutoff)

    def total_size(self) -> int:
        return safe_fs.tree_size(str(self.base_dir))[0]


def _copy_tree_no_links(src: str, dest: str) -> None:
    os.makedirs(dest, exist_ok=False)
    for entry in os.scandir(src):
        if security.is_reparse_point(entry.path):
            continue   # links não são copiados (destino preservado)
        target = os.path.join(dest, entry.name)
        if entry.is_dir(follow_symlinks=False):
            _copy_tree_no_links(entry.path, target)
        else:
            shutil.copy2(entry.path, target, follow_symlinks=False)


def _rmdir_quiet(p: Path) -> None:
    try:
        os.rmdir(p)
    except OSError:
        pass


def _unlink_quiet(p: str) -> None:
    try:
        os.unlink(p)
    except OSError:
        pass
