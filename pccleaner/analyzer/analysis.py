"""Análises sobre o resultado de uma varredura e informações de unidades (somente leitura)."""
from __future__ import annotations

import ctypes
import shutil
import string
import sys
import time
from collections import defaultdict

from pccleaner.core.models import ScanResult

DRIVE_FIXED = 3
RECENT_DAYS = 30
OLD_DAYS = 365


def list_drives() -> list[dict]:
    """Unidades fixas: [{letter, root, total, used, free}]."""
    drives: list[dict] = []
    if sys.platform != "win32":
        return drives
    k32 = ctypes.windll.kernel32
    k32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    mask = k32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        root = f"{letter}:\\"
        if not mask & (1 << i) or k32.GetDriveTypeW(root) != DRIVE_FIXED:
            continue
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        drives.append({"letter": letter, "root": root, "total": u.total, "used": u.used, "free": u.free})
    return drives


def summarize(result: ScanResult) -> dict:
    by_category: dict[str, int] = defaultdict(int)
    by_app: dict[str, int] = defaultdict(int)
    by_safety: dict[str, int] = defaultdict(int)
    for f in result.findings:
        by_category[f.category.value] += f.size_bytes
        by_app[f.app or "Outros"] += f.size_bytes
        by_safety[f.safety.value] += f.size_bytes
    t = time.time()
    recent = sorted((fs for fs in result.top_folders
                     if fs.newest_mtime is not None and fs.newest_mtime >= t - RECENT_DAYS * 86400),
                    key=lambda fs: fs.size_bytes, reverse=True)
    old_large = sorted((lf for lf in result.large_files if lf.mtime < t - OLD_DAYS * 86400),
                       key=lambda lf: lf.size_bytes, reverse=True)

    def srt(d: dict[str, int]) -> dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: kv[1], reverse=True))

    return {"by_category": srt(by_category), "by_app": srt(by_app), "by_safety": srt(by_safety),
            "recent_growth": recent, "old_large_files": old_large,
            "recoverable_bytes": result.recoverable_bytes}
