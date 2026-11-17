"""Utilitários da GUI: formatação, Explorer, elevação de privilégios, recursos."""
from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from pccleaner.core.models import human_size

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def fmt_size(n: int | float | None) -> str:
    return human_size(n or 0)


def fmt_int(n: int | None) -> str:
    return f"{int(n or 0):,}".replace(",", ".")


def fmt_dt(ts: float | str | None) -> str:
    if ts in (None, "", 0):
        return "—"
    try:
        if isinstance(ts, str):
            try:
                ts = float(ts)
            except ValueError:
                return datetime.fromisoformat(ts).strftime("%d/%m/%Y %H:%M")
        return datetime.fromtimestamp(float(ts)).strftime("%d/%m/%Y %H:%M")
    except (OSError, ValueError, OverflowError):
        return str(ts)


def fmt_duration(sec: float | None) -> str:
    sec = int(sec or 0)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m:02d}m {s:02d}s"


def resource_path(rel: str) -> Path:
    """Caminho de um recurso (assets/...) tanto no código-fonte quanto no executável PyInstaller."""
    base = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT))
    return base / rel


def open_in_explorer(path: str) -> None:
    """Abre o Explorer selecionando o item (ou a pasta existente mais próxima)."""
    if not path:
        return
    p = os.path.abspath(path)
    try:
        if os.path.exists(p):
            subprocess.Popen(f'explorer /select,"{p}"')
            return
        parent = p
        while parent and not os.path.isdir(parent):
            nxt = os.path.dirname(parent)
            if nxt == parent:
                return
            parent = nxt
        os.startfile(parent)  # type: ignore[attr-defined]
    except OSError as exc:
        log.warning("Falha ao abrir Explorer em %s: %s", p, exc)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def relaunch_as_admin() -> bool:
    """Reabre o app com UAC (runas). Retorna True se o novo processo foi iniciado."""
    try:
        if getattr(sys, "frozen", False):
            exe, params, cwd = sys.executable, subprocess.list2cmdline(sys.argv[1:]), None
        else:
            exe, params, cwd = sys.executable, "-m pccleaner", str(PROJECT_ROOT)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, cwd, 1)  # type: ignore[attr-defined]
        return int(rc) > 32
    except (AttributeError, OSError) as exc:
        log.warning("Falha ao reabrir como administrador: %s", exc)
        return False


def default_roots() -> list[str]:
    return [os.environ.get("USERPROFILE") or str(Path.home())]


def fallback_drives() -> list[dict]:
    """Lista unidades fixas sem depender do analyzer (usado se o backend falhar)."""
    import shutil
    import string
    drives: list[dict] = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
        get_type = ctypes.windll.kernel32.GetDriveTypeW  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return drives
    for i, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << i):
            continue
        root = f"{letter}:\\"
        if get_type(root) != 3:  # DRIVE_FIXED
            continue
        try:
            u = shutil.disk_usage(root)
        except OSError:
            continue
        drives.append({"letter": letter, "root": root, "total": u.total, "used": u.used, "free": u.free})
    return drives


def get_drives() -> list[dict]:
    try:
        from pccleaner.analyzer import list_drives
        return list(list_drives())
    except Exception as exc:  # noqa: BLE001
        log.info("analyzer.list_drives indisponível (%s); usando fallback", exc)
        return fallback_drives()


def value_bytes(v) -> int:
    """Extrai bytes de valores heterogêneos (int, dict, objeto com size_bytes)."""
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, dict):
        for k in ("size_bytes", "bytes", "size", "total"):
            if k in v:
                return int(v[k] or 0)
        return 0
    if isinstance(v, (tuple, list)) and v:
        return value_bytes(v[0])
    return int(getattr(v, "size_bytes", 0) or 0)


def refusal_reason(path: str) -> str | None:
    """Motivo pelo qual o backend recusará limpar `path` (None = permitido)."""
    try:
        from pccleaner.core.security import UnsafePathError, assert_target_root_allowed
    except ImportError:  # pragma: no cover
        return None
    try:
        assert_target_root_allowed(path)
        return None
    except UnsafePathError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return f"Não foi possível validar o caminho: {exc}"
