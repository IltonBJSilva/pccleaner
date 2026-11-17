"""Classificador: valida e ajusta o nível de segurança de cada Finding sem confiar apenas no nome.

API pública:
- classify(finding) -> Finding   (altera e devolve o mesmo objeto)
- default_selected(finding) -> bool
"""
from __future__ import annotations

import ctypes
import os
import sys
import time
from functools import lru_cache

from pccleaner.core import security
from pccleaner.core.models import Category, CleanMode, Finding, SafetyLevel

GB = 1024 ** 3
RECENT_SECONDS = 86400

# Categorias "de cache": conteúdo deveria ser só dado regenerável.
CACHE_CATEGORIES = {
    Category.WINDOWS_TEMP, Category.BROWSER_CACHE, Category.APP_CACHE, Category.DEV_CACHE, Category.GPU_CACHE,
    Category.THUMBNAILS, Category.SYSTEM_LOGS, Category.CRASH_DUMPS, Category.WINDOWS_UPDATE,
}
# Em pastas temporárias é normal haver scripts soltos; não rebaixar por isso.
SOURCE_CHECK_EXEMPT = {Category.WINDOWS_TEMP}
SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".cpp", ".c", ".h", ".go", ".rs", ".rb",
               ".php", ".kt", ".swift", ".ipynb", ".sln", ".csproj"}
PROJECT_MARKERS = {".git", ".hg", ".svn", "package.json", "pyproject.toml", "cargo.toml", "go.mod", "pom.xml"}
NEVER_DEFAULT = {Category.DEV_DEPENDENCIES, Category.LEFTOVERS, Category.INSTALLERS, Category.DOWNLOADS,
                 Category.LARGE_FILES, Category.OLD_FILES, Category.DUPLICATES, Category.SYSTEM_FILES}

DEFAULT_RECOMMENDATION = {
    SafetyLevel.SAFE: "Pode ser limpo com segurança; o conteúdo é recriado automaticamente.",
    SafetyLevel.REVIEW: "Revise o conteúdo antes de limpar.",
    SafetyLevel.CAUTION: "Atenção: limpe apenas se tiver certeza. Não é selecionado por padrão.",
    SafetyLevel.PROTECTED: "Área protegida: o PCCleaner não apaga este item (apenas informativo).",
}


@lru_cache(maxsize=1)
def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


def _note(f: Finding, text: str) -> None:
    if text not in f.notes:
        f.notes.append(text)


def _downgrade(f: Finding, level: SafetyLevel, note: str) -> None:
    if level.rank > f.safety.rank:
        f.safety = level
    _note(f, note)


def _protect(f: Finding, note: str) -> Finding:
    f.safety = SafetyLevel.PROTECTED
    _note(f, note)
    f.recommendation = DEFAULT_RECOMMENDATION[SafetyLevel.PROTECTED]
    f.selected = False
    return f


def _inspect_top_level(path: str) -> tuple[bool, list[str], list[str]]:
    """(tem marcador de projeto/VCS, arquivos-fonte no topo, arquivos sensíveis no topo)."""
    has_project = False
    sources: list[str] = []
    sensitive: list[str] = []
    try:
        with os.scandir(path) as it:
            for i, e in enumerate(it):
                if i > 5000:
                    break
                low = e.name.lower()
                if low in PROJECT_MARKERS:
                    has_project = True
                try:
                    is_file = e.is_file(follow_symlinks=False)
                except OSError:
                    continue
                if is_file:
                    if os.path.splitext(low)[1] in SOURCE_EXTS and len(sources) < 5:
                        sources.append(e.name)
                    if security.is_sensitive_file(e.name) and len(sensitive) < 5:
                        sensitive.append(e.name)
    except OSError:
        pass
    return has_project, sources, sensitive


def _assert_not_drive_root(path: str) -> None:
    """Defesa extra (independente de security.py): raiz de unidade nunca é alvo."""
    if not path:
        return
    drive, rest = os.path.splitdrive(path)
    if drive and rest.strip("\\/") == "":
        raise security.UnsafePathError(f"Raiz de unidade nunca pode ser limpa: {path}")


def classify(finding: Finding) -> Finding:
    f = finding

    # 1) Lixeira: tratada pela API do shell, sem caminho a validar.
    if f.clean_mode is CleanMode.RECYCLE_BIN:
        if not f.recommendation:
            f.recommendation = DEFAULT_RECOMMENDATION[f.safety]
        return f

    # 2) Validação de segurança do caminho raiz (projeto, pasta do app, áreas protegidas...).
    try:
        _assert_not_drive_root(f.path)
        security.assert_target_root_allowed(f.path)
    except security.UnsafePathError as e:
        return _protect(f, f"Protegido pelo PCCleaner: {e}")
    if security.is_reparse_point(f.path):
        return _protect(f, "O caminho é um link/junção; não será seguido nem apagado.")
    if os.path.isfile(f.path) and security.is_sensitive_file(f.path):
        return _protect(f, "Arquivo sensível (credenciais/sessão) — nunca é apagado.")

    # 3) Conteúdo de pastas de cache: não confiar só no nome.
    if f.category in CACHE_CATEGORIES and f.clean_mode in (CleanMode.CONTENTS, CleanMode.WHOLE) \
            and os.path.isdir(f.path):
        has_project, sources, sensitive = _inspect_top_level(f.path)
        if has_project:
            _downgrade(f, SafetyLevel.CAUTION,
                       "A pasta contém um repositório/projeto (.git, package.json...) — pode não ser só cache.")
        if sources and f.category not in SOURCE_CHECK_EXEMPT:
            _downgrade(f, SafetyLevel.CAUTION,
                       f"Contém arquivos de código-fonte ({', '.join(sources[:3])}) — confira antes de limpar.")
        if sensitive:
            _downgrade(f, SafetyLevel.CAUTION,
                       f"Contém arquivos sensíveis ({', '.join(sensitive[:3])}); eles serão preservados.")

    # 4) Uso recente.
    if f.safety is SafetyLevel.SAFE and f.last_modified and time.time() - f.last_modified < RECENT_SECONDS:
        _note(f, "Em uso recente — alguns arquivos podem estar bloqueados e serão ignorados.")

    # 5) Itens muito grandes para revisar.
    if f.safety is SafetyLevel.REVIEW and f.size_bytes > 5 * GB and f.cleanable:
        _note(f, "Item muito grande (mais de 5 GB): confira se não há algo que você queira manter.")

    if f.category is Category.DEV_DEPENDENCIES:
        _note(f, "Dependências de projeto nunca são selecionadas automaticamente.")
    if f.requires_admin and not is_admin():
        _note(f, "Requer executar o PCCleaner como administrador.")
    if f.clean_mode in (CleanMode.NONE, CleanMode.COMMAND):
        _note(f, "Apenas informativo: o PCCleaner não apaga este item.")
    if not f.recommendation:
        f.recommendation = DEFAULT_RECOMMENDATION[f.safety]
    return f


def default_selected(finding: Finding) -> bool:
    f = finding
    if f.safety is not SafetyLevel.SAFE or not f.cleanable or f.size_bytes <= 0:
        return False
    if f.category in NEVER_DEFAULT:
        return False
    if f.requires_admin and not is_admin():
        return False
    return True


__all__ = ["classify", "default_selected", "is_admin"]
