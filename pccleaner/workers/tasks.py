"""Workers concretos. Os módulos de backend são importados de forma tardia (dentro de work())
para que a GUI possa ser importada mesmo que algum backend esteja indisponível."""
from __future__ import annotations

import copy
from typing import Any

from pccleaner.core.models import Finding, ScanOptions, ScanProgress
from pccleaner.workers.base import BaseWorker


class ScanWorker(BaseWorker):
    """progress -> ScanProgress (cópia); finished -> ScanResult."""

    def __init__(self, options: ScanOptions) -> None:
        super().__init__()
        self.options = options
        self.last_progress: ScanProgress | None = None

    def _on_progress(self, p: ScanProgress) -> None:
        snap = copy.copy(p)
        snap.categories = dict(p.categories or {})
        self.last_progress = snap
        self.emit_progress(snap)

    def work(self) -> Any:
        from pccleaner.scanner import run_scan
        result = run_scan(self.options, self._on_progress, self.cancel_token)
        if self.last_progress is not None:
            self.emit_progress(self.last_progress, force=True)
        return result


class CleanWorker(BaseWorker):
    """progress -> (caminho_atual, feito, total); finished -> CleanReport.

    Segurança: somente achados marcados pelo usuário (selected=True) e limpáveis são
    repassados a clean() — nunca a lista inteira.
    """

    def __init__(self, findings: list[Finding], *, use_quarantine: bool = True,
                 quarantine_max_bytes: int = 2 * 1024 ** 3) -> None:
        super().__init__()
        self.findings = [f for f in findings if f.selected and f.cleanable]
        self.use_quarantine = use_quarantine
        self.quarantine_max_bytes = quarantine_max_bytes

    def _on_progress(self, current: str, done: int, total: int) -> None:
        self.emit_progress((current, done, total), force=(done >= total))

    def work(self) -> Any:
        from pccleaner.cleaner import clean
        from pccleaner.core.models import CleanReport, now
        if not self.findings:
            t = now()
            return CleanReport(started_at=t, finished_at=t, items=[])
        return clean(self.findings, use_quarantine=self.use_quarantine,
                     quarantine_max_bytes=self.quarantine_max_bytes,
                     progress=self._on_progress, cancel=self.cancel_token)


class DuplicateWorker(BaseWorker):
    """progress -> (caminho_atual, arquivos_processados); finished -> list[DuplicateGroup]."""

    def __init__(self, roots: list[str], min_size_bytes: int = 1024 * 1024) -> None:
        super().__init__()
        self.roots = list(roots)
        self.min_size_bytes = int(min_size_bytes)

    def _on_progress(self, current: str, count: int) -> None:
        self.emit_progress((current, count))

    def work(self) -> Any:
        from pccleaner.duplicate_finder import find_duplicates
        return find_duplicates(self.roots, min_size_bytes=self.min_size_bytes,
                               progress=self._on_progress, cancel=self.cancel_token)


class ChildrenWorker(BaseWorker):
    """finished -> (path, list[FolderStat])."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self.path = path

    def work(self) -> Any:
        from pccleaner.scanner import list_children
        return self.path, list_children(self.path, cancel=self.cancel_token)


class FilesWorker(BaseWorker):
    """finished -> (path, list[LargeFile])."""

    def __init__(self, path: str, limit: int = 500) -> None:
        super().__init__()
        self.path = path
        self.limit = limit

    def work(self) -> Any:
        from pccleaner.scanner import list_files
        return self.path, list_files(self.path, limit=self.limit)
