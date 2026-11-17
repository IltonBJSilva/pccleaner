"""Consulta (somente leitura) do tamanho da Lixeira via SHQueryRecycleBinW."""
from __future__ import annotations

import ctypes
import sys


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint32), ("i64Size", ctypes.c_int64), ("i64NumItems", ctypes.c_int64)]


def query_recycle_bin(root: str | None = None) -> tuple[int, int]:
    """Retorna (bytes, itens) da Lixeira. `root=None` consulta todas as unidades."""
    if sys.platform != "win32":
        return 0, 0
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
    try:
        fn = ctypes.windll.shell32.SHQueryRecycleBinW
        fn.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_SHQUERYRBINFO)]
        fn.restype = ctypes.c_long
        hr = fn(root, ctypes.byref(info))
    except (OSError, AttributeError):
        return 0, 0
    if hr != 0:
        return 0, 0
    return int(info.i64Size), int(info.i64NumItems)
