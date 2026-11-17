"""Helpers para declarar regras de forma compacta."""
from __future__ import annotations

from pccleaner.core.models import Category, CleanMode, Rule, SafetyLevel

S = SafetyLevel.SAFE
RV = SafetyLevel.REVIEW
C = SafetyLevel.CAUTION
P = SafetyLevel.PROTECTED

CONTENTS = CleanMode.CONTENTS
WHOLE = CleanMode.WHOLE
NONE = CleanMode.NONE
COMMAND = CleanMode.COMMAND
RECYCLE = CleanMode.RECYCLE_BIN

REC_SAFE = "Pode ser limpo com segurança; o conteúdo é recriado automaticamente quando necessário."
REC_CLOSE_APP = ("Pode ser limpo com segurança. Feche o aplicativo antes para liberar arquivos em uso; "
                 "o cache será recriado automaticamente.")
REC_REVIEW = "Revise antes de limpar: o conteúdo pode ser útil ou demorar para ser recriado."
REC_CAUTION = "Atenção: só limpe se souber o que está removendo. Não é selecionado por padrão."


def rule(id: str, name: str, category: Category, app: str, safety: SafetyLevel, reason: str,
         recommendation: str = "", clean_mode: CleanMode = CONTENTS, paths: tuple[str, ...] | list[str] = (),
         dir_names: tuple[str, ...] = (), parent_names: tuple[str, ...] = (),
         sibling_markers: tuple[str, ...] = (), min_age_days: int = 0, requires_admin: bool = False,
         command_hint: str = "") -> Rule:
    if not recommendation:
        recommendation = {S: REC_SAFE, RV: REC_REVIEW, C: REC_CAUTION}.get(safety, "Apenas informativo.")
    return Rule(id=id, name=name, category=category, app=app, safety=safety, reason=reason,
                recommendation=recommendation, clean_mode=clean_mode, paths=tuple(paths),
                dir_names=tuple(dir_names), parent_names=tuple(parent_names),
                sibling_markers=tuple(sibling_markers), min_age_days=min_age_days,
                requires_admin=requires_admin, command_hint=command_hint)


def finding_from_rule(r: Rule, path: str, size: int, count: int, newest: float | None,
                      name: str | None = None, reason: str | None = None):
    from pccleaner.core.models import Finding
    return Finding(id=Finding.make_id(path, r.id), rule_id=r.id, name=name or r.name, path=path,
                   category=r.category, app=r.app, safety=r.safety, reason=reason or r.reason,
                   recommendation=r.recommendation, clean_mode=r.clean_mode, size_bytes=size, file_count=count,
                   last_modified=newest, min_age_days=r.min_age_days, requires_admin=r.requires_admin,
                   command_hint=r.command_hint)
