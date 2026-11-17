"""Painel: unidades, resumo da última varredura e opções de análise."""
from __future__ import annotations

import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QCheckBox, QFileDialog, QGridLayout, QHBoxLayout,
                               QInputDialog, QListWidget, QMessageBox, QPushButton, QVBoxLayout,
                               QWidget)

from pccleaner.core.models import ScanOptions
from pccleaner.gui.pages import Page, scrollable
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import (default_roots, fmt_dt, fmt_int, fmt_size, get_drives, is_admin,
                                 relaunch_as_admin)
from pccleaner.gui.widgets import Card, DriveCard, StatCard, make_label
from pccleaner.workers import FunctionWorker

log = logging.getLogger(__name__)


class RootsEditor(QWidget):
    """Lista editável de pastas/unidades raiz."""

    def __init__(self, roots: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setMaximumHeight(110)
        lay.addWidget(self.list, 1)
        col = QVBoxLayout()
        for text, fn in (("Adicionar pasta…", self.add_folder), ("Adicionar unidade…", self.add_drive),
                         ("Remover", self.remove), ("Restaurar padrão", self.reset)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            col.addWidget(b)
        col.addStretch(1)
        lay.addLayout(col)
        self.set_roots(roots or default_roots())

    def set_roots(self, roots: list[str]) -> None:
        self.list.clear()
        for r in roots:
            self.list.addItem(r)

    def roots(self) -> list[str]:
        return [self.list.item(i).text() for i in range(self.list.count())]

    def _add(self, path: str) -> None:
        path = os.path.normpath(path)
        if path and path not in self.roots():
            self.list.addItem(path)

    def add_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Escolher pasta para analisar")
        if d:
            self._add(d)

    def add_drive(self) -> None:
        drives = [str(d["letter"]).rstrip(":\\") + ":\\" for d in get_drives()]
        if not drives:
            return
        item, ok = QInputDialog.getItem(self, "Adicionar unidade", "Unidade inteira:", drives, 0, False)
        if ok and item:
            self._add(item)

    def remove(self) -> None:
        for it in self.list.selectedItems():
            self.list.takeItem(self.list.row(it))

    def reset(self) -> None:
        self.set_roots(default_roots())


class DashboardPage(Page):
    title = "Painel"

    def __init__(self, state: AppState, parent: QWidget | None = None, auto_refresh: bool = True) -> None:
        super().__init__(parent)
        self.state = state
        self._workers: list = []
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        head = QHBoxLayout()
        head.addWidget(make_label("Painel", "h1"))
        head.addStretch(1)
        btn_refresh = QPushButton("Atualizar")
        btn_refresh.clicked.connect(self.refresh)
        head.addWidget(btn_refresh)
        lay.addLayout(head)

        lay.addWidget(make_label("Unidades", "h2"))
        self.drives_grid = QGridLayout()
        self.drives_grid.setSpacing(12)
        lay.addLayout(self.drives_grid)

        lay.addWidget(make_label("Última análise", "h2"))
        stats = QHBoxLayout()
        self.card_files = StatCard("Arquivos analisados")
        self.card_findings = StatCard("Oportunidades encontradas")
        self.card_recover = StatCard("Espaço recuperável", subtitle="Itens Seguros e Revisar")
        self.card_last = StatCard("Última varredura")
        for c in (self.card_files, self.card_findings, self.card_recover, self.card_last):
            stats.addWidget(c)
        lay.addLayout(stats)

        opts = Card()
        opts.lay.addWidget(make_label("Opções da análise", "h2"))
        self.chk_deep = QCheckBox("Varredura profunda (caches, node_modules, builds…)")
        self.chk_deep.setChecked(True)
        self.chk_downloads = QCheckBox("Incluir pasta Downloads")
        self.chk_downloads.setChecked(True)
        opts.lay.addWidget(self.chk_deep)
        opts.lay.addWidget(self.chk_downloads)
        opts.lay.addWidget(make_label("Pastas/unidades analisadas na varredura profunda:", "muted"))
        self.roots = RootsEditor(list(state.settings.deep_scan_roots))
        opts.lay.addWidget(self.roots)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn_scan = QPushButton("🔍  Analisar")
        self.btn_scan.setObjectName("big")
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.clicked.connect(self._start_scan)
        row.addWidget(self.btn_scan)
        row.addStretch(1)
        opts.lay.addLayout(row)
        lay.addWidget(opts)

        adm = QHBoxLayout()
        if is_admin():
            adm.addWidget(make_label("🛡 Executando como administrador.", "hint"))
        else:
            adm.addWidget(make_label("Itens marcados com 🛡 exigem administrador.", "hint"))
            b = QPushButton("Reabrir como administrador")
            b.clicked.connect(self._elevate)
            adm.addWidget(b)
        adm.addStretch(1)
        lay.addLayout(adm)
        lay.addStretch(1)
        self.root.addWidget(scrollable(inner))

        state.resultChanged.connect(lambda _r: self.refresh_last_scan())
        state.historyChanged.connect(self.refresh_last_scan)
        state.cleanFinished.connect(lambda _r: self.refresh_drives())
        if auto_refresh:
            self.refresh()

    # ------------------------------------------------------------------ ações
    def _start_scan(self) -> None:
        roots = self.roots.roots()
        s = self.state.settings
        s.deep_scan_roots = [] if roots == default_roots() else roots
        try:
            s.save()
        except OSError as exc:
            log.warning("Falha ao salvar configurações: %s", exc)
        self.state.startScan.emit(ScanOptions(
            roots=roots, deep_scan=self.chk_deep.isChecked(),
            include_downloads=self.chk_downloads.isChecked(),
            large_file_threshold_mb=s.large_file_threshold_mb, old_file_days=s.old_file_days))

    def set_scanning(self, on: bool) -> None:
        self.btn_scan.setEnabled(not on)
        self.btn_scan.setText("Analisando…" if on else "🔍  Analisar")

    def _elevate(self) -> None:
        if QMessageBox.question(self, "Reabrir como administrador",
                                "O PCCleaner será reaberto com privilégios de administrador (UAC) e esta "
                                "janela será fechada. Continuar?") != QMessageBox.StandardButton.Yes:
            return
        if relaunch_as_admin():
            QApplication.instance().quit()
        else:
            QMessageBox.warning(self, "PCCleaner", "Não foi possível reabrir como administrador.")

    # ------------------------------------------------------------------ dados
    def refresh(self) -> None:
        self.refresh_drives()
        self.refresh_last_scan()

    def _run(self, fn, on_done) -> None:
        w = FunctionWorker(fn)

        def drop(*_a, w=w) -> None:
            if w in self._workers:
                self._workers.remove(w)
        w.finished.connect(on_done)
        w.error.connect(lambda m: log.warning("Painel: %s", m))
        w.finished.connect(drop)
        w.error.connect(drop)
        self._workers.append(w)
        w.start()

    def refresh_drives(self) -> None:
        self._run(get_drives, self._show_drives)

    def _show_drives(self, drives: list[dict]) -> None:
        while self.drives_grid.count():
            it = self.drives_grid.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        if not drives:
            self.drives_grid.addWidget(make_label("Nenhuma unidade fixa encontrada.", "muted"), 0, 0)
        for i, d in enumerate(drives):
            self.drives_grid.addWidget(DriveCard(d), i // 3, i % 3)

    def refresh_last_scan(self) -> None:
        r = self.state.result
        if r is not None:
            self.card_files.set(fmt_int(r.files_scanned), fmt_size(r.bytes_scanned) + " analisados")
            self.card_findings.set(fmt_int(len(r.findings)))
            self.card_recover.set(fmt_size(r.recoverable_bytes))
            self.card_last.set(fmt_dt(r.started_at), "Cancelada" if r.cancelled else "Concluída")
            return

        def load():
            from pccleaner.database import HistoryDB
            return HistoryDB().last_scan()
        self._run(load, self._show_last_db)

    def _show_last_db(self, row: dict | None) -> None:
        if self.state.result is not None:
            return
        if not row:
            self.card_last.set("Nunca", "Clique em Analisar para começar")
            return
        self.card_files.set(fmt_int(row.get("files_scanned")))
        self.card_findings.set(fmt_int(row.get("findings")))
        self.card_recover.set(fmt_size(row.get("recoverable_bytes")))
        self.card_last.set(fmt_dt(row.get("started_at")), "Cancelada" if row.get("cancelled") else "Do histórico")
