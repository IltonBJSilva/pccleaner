"""Estado compartilhado entre as páginas (resultado atual, configurações, último relatório)."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from pccleaner.config import Settings
from pccleaner.core.models import CleanReport, ScanResult


class AppState(QObject):
    resultChanged = Signal(object)      # ScanResult | None
    settingsChanged = Signal(object)    # Settings
    historyChanged = Signal()
    cleanFinished = Signal(object)      # CleanReport
    navigate = Signal(str)              # chave da página
    startScan = Signal(object)          # ScanOptions

    def __init__(self, settings: Settings | None = None) -> None:
        super().__init__()
        self.settings = settings or Settings.load()
        self.result: ScanResult | None = None
        self.last_clean: CleanReport | None = None

    def set_result(self, result: ScanResult | None) -> None:
        self.result = result
        self.resultChanged.emit(result)

    def save_settings(self) -> None:
        self.settings.save()
        self.settingsChanged.emit(self.settings)
