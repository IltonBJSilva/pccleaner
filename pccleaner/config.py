"""Configurações persistentes e caminhos de dados do app."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path

APP_NAME = "PCCleaner"
APP_VERSION = "1.0.0"


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    d = Path(base) / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return data_dir() / "history.sqlite3"


def quarantine_dir() -> Path:
    d = data_dir() / "quarantine"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir() -> Path:
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Settings:
    deep_scan_roots: list[str] = field(default_factory=list)  # vazio = perfil do usuário
    large_file_threshold_mb: int = 500
    old_file_days: int = 365
    use_quarantine: bool = True
    quarantine_max_mb: int = 2048        # itens maiores que isso são apagados direto (com aviso)
    quarantine_keep_days: int = 7
    theme: str = "dark"

    @classmethod
    def load(cls) -> "Settings":
        p = data_dir() / "settings.json"
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
            return cls(**known)
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self) -> None:
        p = data_dir() / "settings.json"
        p.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")


def setup_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    h = logging.handlers.RotatingFileHandler(logs_dir() / "pccleaner.log", maxBytes=2_000_000,
                                             backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(h)
