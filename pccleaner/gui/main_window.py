"""Janela principal: barra lateral + páginas empilhadas."""
from __future__ import annotations

import logging

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QListWidget, QListWidgetItem,
                               QMainWindow, QMessageBox, QStackedWidget, QVBoxLayout, QWidget)

from pccleaner.config import APP_NAME, APP_VERSION, Settings
from pccleaner.core.models import ScanOptions, ScanResult
from pccleaner.gui import theme
from pccleaner.gui.pages.dashboard import DashboardPage
from pccleaner.gui.pages.duplicates import DuplicatesPage
from pccleaner.gui.pages.history import HistoryPage
from pccleaner.gui.pages.quarantine import QuarantinePage
from pccleaner.gui.pages.results import ResultsPage
from pccleaner.gui.pages.scan import ScanPage
from pccleaner.gui.pages.settings import SettingsPage
from pccleaner.gui.pages.storage import StoragePage
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_size, is_admin
from pccleaner.gui.widgets import make_label
from pccleaner.workers import cancel_all

log = logging.getLogger(__name__)

NAV = [
    ("dashboard", "🏠  Painel"),
    ("scan", "📡  Análise"),
    ("results", "📋  Resultados"),
    ("storage", "📊  Armazenamento"),
    ("duplicates", "🧬  Duplicados"),
    ("quarantine", "🗃  Quarentena"),
    ("history", "🕘  Histórico"),
    ("settings", "⚙  Configurações"),
]


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings | None = None, *, auto_refresh: bool = True) -> None:
        super().__init__()
        self.state = AppState(settings)
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}" + ("  [Administrador]" if is_admin() else ""))
        self.resize(1360, 860)
        self.setMinimumSize(1000, 640)

        central = QWidget()
        lay = QHBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        side = QWidget()
        side.setFixedWidth(220)
        side_l = QVBoxLayout(side)
        side_l.setContentsMargins(0, 0, 0, 0)
        side_l.setSpacing(0)
        side_l.addWidget(make_label("🧹 PCCleaner", "brand"))
        self.nav = QListWidget()
        self.nav.setObjectName("sidebar")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side_l.addWidget(self.nav, 1)
        lay.addWidget(side)
        self.stack = QStackedWidget()
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.pages: dict[str, QWidget] = {
            "dashboard": DashboardPage(self.state, auto_refresh=auto_refresh),
            "scan": ScanPage(),
            "results": ResultsPage(self.state),
            "storage": StoragePage(self.state),
            "duplicates": DuplicatesPage(self.state),
            "quarantine": QuarantinePage(self.state),
            "history": HistoryPage(self.state),
            "settings": SettingsPage(self.state),
        }
        self._keys = [k for k, _ in NAV]
        for key, label in NAV:
            self.nav.addItem(QListWidgetItem(label))
            self.stack.addWidget(self.pages[key])
        self.nav.currentRowChanged.connect(self._on_nav)
        self.nav.setCurrentRow(0)

        self.state.navigate.connect(self.go)
        self.state.startScan.connect(self.start_scan)
        self.state.settingsChanged.connect(self._apply_theme)
        scan: ScanPage = self.pages["scan"]  # type: ignore[assignment]
        scan.scanFinished.connect(self._on_scan_finished)
        scan.scanFailed.connect(self._on_scan_failed)
        self.statusBar().showMessage("Pronto.")

    # ------------------------------------------------------------------ navegação
    def go(self, key: str) -> None:
        if key in self._keys:
            self.nav.setCurrentRow(self._keys.index(key))

    def _on_nav(self, row: int) -> None:
        if row < 0:
            return
        self.stack.setCurrentIndex(row)
        page = self.stack.currentWidget()
        if hasattr(page, "on_show"):
            page.on_show()

    def _apply_theme(self, settings: Settings) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet(settings.theme))

    # ------------------------------------------------------------------ análise
    def start_scan(self, options: ScanOptions) -> None:
        scan: ScanPage = self.pages["scan"]  # type: ignore[assignment]
        if not scan.is_running():
            self.pages["dashboard"].set_scanning(True)  # type: ignore[attr-defined]
            self.statusBar().showMessage("Analisando…")
            scan.start(options)
        self.go("scan")

    def _on_scan_finished(self, result: ScanResult) -> None:
        self.pages["dashboard"].set_scanning(False)  # type: ignore[attr-defined]
        if result is None:
            return
        try:
            from pccleaner.database import HistoryDB
            HistoryDB().save_scan(result)
        except Exception as exc:  # noqa: BLE001
            log.warning("Falha ao salvar análise no histórico: %s", exc)
        self.state.set_result(result)
        self.state.historyChanged.emit()
        self.statusBar().showMessage(
            f"Análise {'cancelada' if result.cancelled else 'concluída'}: {len(result.findings)} itens, "
            f"{fmt_size(result.recoverable_bytes)} recuperáveis.")
        self.go("results")

    def _on_scan_failed(self, msg: str) -> None:
        self.pages["dashboard"].set_scanning(False)  # type: ignore[attr-defined]
        self.statusBar().showMessage("Falha na análise.")
        QMessageBox.critical(self, "Falha na análise", msg)

    # ------------------------------------------------------------------ fechamento
    def closeEvent(self, ev: QCloseEvent) -> None:  # noqa: N802
        if self.pages["scan"].is_running():  # type: ignore[attr-defined]
            if QMessageBox.question(self, APP_NAME, "Uma análise está em andamento. Cancelar e sair?") \
                    != QMessageBox.StandardButton.Yes:
                ev.ignore()
                return
        cancel_all(3000)
        ev.accept()
