"""Base de conhecimento de locais limpáveis no Windows 10/11.

API pública:
- all_rules() -> list[Rule]
- dynamic_findings(cancel=None) -> list[Finding]
"""
from __future__ import annotations

from functools import lru_cache

from pccleaner.core.models import Rule

from . import apps, browsers, dev, downloads, projects, windows
from .downloads import DOWNLOADS_TOTAL_RULE_ID
from .dynamic import dynamic_findings
from .windows import RECYCLE_BIN_RULE_ID


@lru_cache(maxsize=1)
def _rules() -> tuple[Rule, ...]:
    # Ordem importa: em caso de empate na deduplicação, a regra que vem antes vence (mais específica primeiro).
    rs = [*windows.rules(), *browsers.rules(), *apps.rules(), *dev.rules(), *projects.rules(), *downloads.rules()]
    ids = [r.id for r in rs]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise RuntimeError(f"IDs de regra duplicados: {sorted(dup)}")
    return tuple(rs)


def all_rules() -> list[Rule]:
    return list(_rules())


def rule_by_id(rule_id: str) -> Rule | None:
    for r in _rules():
        if r.id == rule_id:
            return r
    return None


__all__ = ["all_rules", "dynamic_findings", "rule_by_id", "RECYCLE_BIN_RULE_ID", "DOWNLOADS_TOTAL_RULE_ID"]
