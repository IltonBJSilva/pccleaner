"""Scanner do PCCleaner (somente leitura — nunca apaga nada).

API pública:
- run_scan(options, progress=None, cancel=None) -> ScanResult
- measure_tree(path, cancel=None, min_age_days=0) -> (bytes, arquivos, mtime_mais_recente)
- list_children(path, cancel=None) -> list[FolderStat]
- list_files(path, limit=500) -> list[LargeFile]
"""
from __future__ import annotations

from .engine import dedupe_findings, run_scan
from .fs import expand_pattern, list_children, list_files, measure_tree
from .recyclebin import query_recycle_bin

__all__ = ["run_scan", "measure_tree", "list_children", "list_files", "dedupe_findings", "expand_pattern",
           "query_recycle_bin"]
