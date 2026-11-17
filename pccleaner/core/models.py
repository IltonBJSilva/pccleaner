"""Contratos de dados compartilhados entre todos os módulos do PCCleaner.

NÃO altere assinaturas sem atualizar todos os consumidores (scanner, cleaner, gui, reporting, database).
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class SafetyLevel(str, Enum):
    SAFE = "seguro"            # cache/temporário regenerável
    REVIEW = "revisar"         # logs, resíduos, arquivos antigos
    CAUTION = "atencao"        # grandes, dependências, projetos
    PROTECTED = "protegido"    # nunca limpar (apenas informativo)

    @property
    def label(self) -> str:
        return {
            "seguro": "Seguro",
            "revisar": "Revisar",
            "atencao": "Atenção",
            "protegido": "Protegido",
        }[self.value]

    @property
    def rank(self) -> int:
        return ["seguro", "revisar", "atencao", "protegido"].index(self.value)


class Category(str, Enum):
    WINDOWS_TEMP = "Temporários do Windows"
    WINDOWS_UPDATE = "Windows Update"
    SYSTEM_LOGS = "Logs e diagnósticos"
    CRASH_DUMPS = "Despejos de erro"
    THUMBNAILS = "Miniaturas"
    RECYCLE_BIN = "Lixeira"
    BROWSER_CACHE = "Cache de navegador"
    DEV_CACHE = "Cache de desenvolvimento"
    DEV_DEPENDENCIES = "Dependências de projeto"
    BUILD_ARTIFACTS = "Artefatos de build"
    APP_CACHE = "Cache de aplicativo"
    GPU_CACHE = "Cache de GPU/shaders"
    OLD_VERSIONS = "Versões antigas de apps"
    INSTALLERS = "Instaladores baixados"
    LEFTOVERS = "Resíduos de programas"
    DOWNLOADS = "Downloads"
    LARGE_FILES = "Arquivos grandes"
    OLD_FILES = "Arquivos antigos"
    DUPLICATES = "Duplicados"
    SYSTEM_FILES = "Arquivos de sistema"
    OTHER = "Outros"


class CleanMode(str, Enum):
    CONTENTS = "contents"      # apaga o conteúdo da pasta, mantém a pasta
    WHOLE = "whole"            # apaga o caminho inteiro (pasta ou arquivo)
    RECYCLE_BIN = "recycle"    # esvazia a lixeira via API do shell
    COMMAND = "command"        # executa comando oficial da ferramenta (ex.: pip cache purge) — só informativo/manual
    NONE = "none"              # só relatório, nunca apagado pelo app


@dataclass(frozen=True)
class Rule:
    """Regra declarativa de detecção. Produzida pelos detectors."""
    id: str
    name: str
    category: Category
    app: str
    safety: SafetyLevel
    reason: str
    recommendation: str
    clean_mode: CleanMode = CleanMode.CONTENTS
    # Caminhos fixos (com %VARS% e glob * permitidos). Expandidos pelo scanner.
    paths: tuple[str, ...] = ()
    # Nomes de pasta casados durante a varredura profunda (case-insensitive).
    dir_names: tuple[str, ...] = ()
    # Para dir_names: pasta-pai deve ter um destes nomes (ex.: "cache" exige pai ".next").
    parent_names: tuple[str, ...] = ()
    # Para dir_names: um destes arquivos deve existir ao lado (no pai) — ex.: package.json p/ node_modules.
    sibling_markers: tuple[str, ...] = ()
    # Só apaga arquivos com mtime mais antigo que N dias (0 = todos).
    min_age_days: int = 0
    requires_admin: bool = False
    # Comando oficial sugerido (mostrado na UI) — o app NÃO executa automaticamente.
    command_hint: str = ""


@dataclass
class Finding:
    id: str
    rule_id: str
    name: str
    path: str
    category: Category
    app: str
    safety: SafetyLevel
    reason: str
    recommendation: str
    clean_mode: CleanMode
    size_bytes: int = 0
    file_count: int = 0
    last_modified: float | None = None   # mtime mais recente dentro do item
    min_age_days: int = 0
    requires_admin: bool = False
    command_hint: str = ""
    notes: list[str] = field(default_factory=list)   # observações do classificador
    selected: bool = False

    @staticmethod
    def make_id(path: str, rule_id: str) -> str:
        return hashlib.sha1(f"{rule_id}|{path.lower()}".encode("utf-8")).hexdigest()[:16]

    @property
    def cleanable(self) -> bool:
        return self.safety is not SafetyLevel.PROTECTED and self.clean_mode in (
            CleanMode.CONTENTS, CleanMode.WHOLE, CleanMode.RECYCLE_BIN)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["safety"] = self.safety.value
        d["clean_mode"] = self.clean_mode.value
        return d


@dataclass
class FolderStat:
    path: str
    size_bytes: int
    file_count: int
    newest_mtime: float | None = None


@dataclass
class LargeFile:
    path: str
    size_bytes: int
    mtime: float
    atime: float | None = None


@dataclass
class ScanProgress:
    phase: str = ""                 # "Locais conhecidos", "Varredura profunda", "Classificação"...
    current_path: str = ""
    files_scanned: int = 0
    bytes_scanned: int = 0
    findings_count: int = 0
    categories: dict[str, int] = field(default_factory=dict)   # categoria -> BYTES encontrados
    elapsed: float = 0.0
    percent: float = -1.0           # -1 = indeterminado
    errors: int = 0


@dataclass
class ScanOptions:
    roots: list[str] = field(default_factory=list)   # raízes da varredura profunda; vazio = perfil do usuário
    deep_scan: bool = True
    include_downloads: bool = True
    large_file_threshold_mb: int = 500
    old_file_days: int = 365
    top_folders: int = 50


@dataclass
class ScanResult:
    scan_id: str
    started_at: float
    finished_at: float
    findings: list[Finding]
    top_folders: list[FolderStat]
    large_files: list[LargeFile]
    files_scanned: int
    bytes_scanned: int
    errors: list[str]
    cancelled: bool = False

    @property
    def recoverable_bytes(self) -> int:
        return sum(f.size_bytes for f in self.findings
                   if f.safety in (SafetyLevel.SAFE, SafetyLevel.REVIEW) and f.cleanable)


@dataclass
class CleanItemResult:
    finding_id: str
    path: str
    freed_bytes: int = 0
    files_removed: int = 0
    files_skipped: int = 0
    quarantined: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class CleanReport:
    started_at: float
    finished_at: float
    items: list[CleanItemResult]
    cancelled: bool = False

    @property
    def freed_bytes(self) -> int:
        return sum(i.freed_bytes for i in self.items)

    @property
    def files_removed(self) -> int:
        return sum(i.files_removed for i in self.items)

    @property
    def error_count(self) -> int:
        return sum(len(i.errors) for i in self.items)


class CancelToken:
    """Token de cancelamento cooperativo, thread-safe."""

    def __init__(self) -> None:
        self._ev = threading.Event()

    def cancel(self) -> None:
        self._ev.set()

    @property
    def cancelled(self) -> bool:
        return self._ev.is_set()


def human_size(n: int | float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024
    return f"{n:.1f} TB"


def now() -> float:
    return time.time()
