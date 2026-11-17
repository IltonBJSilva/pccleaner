"""Histórico de análises e limpezas + exportação de relatório."""
from __future__ import annotations

import logging
import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QFileDialog, QHBoxLayout, QHeaderView,
                               QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
                               QWidget)

from pccleaner.gui.pages import Page
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_dt, fmt_duration, fmt_int, fmt_size
from pccleaner.gui.widgets import make_label
from pccleaner.workers import FunctionWorker

log = logging.getLogger(__name__)


def _load(limit: int = 200):
    from pccleaner.database import HistoryDB
    db = HistoryDB()
    return db.list_scans(limit), db.list_cleans(limit)


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    return t


def _fill(t: QTableWidget, rows: list[list[str]]) -> None:
    t.setRowCount(len(rows))
    for r, vals in enumerate(rows):
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if c > 0:
                it.setTextAlignment(int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
            t.setItem(r, c, it)


class HistoryPage(Page):
    title = "Histórico"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self._worker = None
        head = QHBoxLayout()
        head.addWidget(make_label("Histórico", "h1"))
        head.addStretch(1)
        self.btn_refresh = QPushButton("Atualizar")
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_export = QPushButton("Exportar relatório da última análise…")
        self.btn_export.setObjectName("primary")
        self.btn_export.clicked.connect(self.export)
        head.addWidget(self.btn_refresh)
        head.addWidget(self.btn_export)
        self.root.addLayout(head)
        self.lbl_status = make_label("", "muted")
        self.root.addWidget(self.lbl_status)
        tabs = QTabWidget()
        self.t_scans = _table(["Data", "Duração", "Arquivos", "Oportunidades", "Recuperável", "Status"])
        self.t_cleans = _table(["Data", "Duração", "Liberado", "Arquivos removidos", "Erros"])
        tabs.addTab(self.t_scans, "Análises")
        tabs.addTab(self.t_cleans, "Limpezas")
        self.root.addWidget(tabs, 1)
        state.historyChanged.connect(self.refresh)
        state.resultChanged.connect(lambda _r: self._update_export())
        self._update_export()

    def on_show(self) -> None:
        self.refresh()

    def _update_export(self) -> None:
        self.btn_export.setEnabled(self.state.result is not None)
        self.btn_export.setToolTip("" if self.state.result else "Execute uma análise nesta sessão para exportar.")

    def refresh(self) -> None:
        if self._worker is not None and self._worker.is_running():
            return
        w = FunctionWorker(_load)
        w.finished.connect(self._show)
        w.error.connect(lambda m: self.lbl_status.setText(f"Histórico indisponível: {m}"))
        self._worker = w
        w.start()

    def _show(self, res) -> None:
        scans, cleans = res
        _fill(self.t_scans, [[fmt_dt(s.get("started_at")), fmt_duration(s.get("duration")),
                              fmt_int(s.get("files_scanned")), fmt_int(s.get("findings")),
                              fmt_size(s.get("recoverable_bytes")),
                              "Cancelada" if s.get("cancelled") else "Concluída"] for s in scans])
        _fill(self.t_cleans, [[fmt_dt(c.get("started_at")), fmt_duration(c.get("duration")),
                               fmt_size(c.get("freed_bytes")), fmt_int(c.get("files_removed")),
                               fmt_int(c.get("errors"))] for c in cleans])
        self.lbl_status.setText(f"{len(scans)} análises · {len(cleans)} limpezas registradas")

    def export(self) -> None:
        result = self.state.result
        if result is None:
            return
        default = os.path.join(os.path.expanduser("~"), "Desktop", "PCCleaner-relatorio.html")
        path, flt = QFileDialog.getSaveFileName(self, "Exportar relatório", default,
                                                "Relatório HTML (*.html);;JSON (*.json);;CSV (*.csv)")
        if not path:
            return
        ext = os.path.splitext(path)[1].lower().lstrip(".")
        fmt = ext if ext in ("json", "csv", "html") else (
            "json" if "JSON" in flt else "csv" if "CSV" in flt else "html")
        if not path.lower().endswith("." + fmt):
            path += "." + fmt
        try:
            from pccleaner.reporting import export_report
            out = export_report(result, path, fmt, clean_report=self.state.last_clean)
        except Exception as exc:  # noqa: BLE001
            log.exception("Falha ao exportar relatório")
            QMessageBox.critical(self, "Exportar relatório", f"Falha ao exportar: {exc}")
            return
        QMessageBox.information(self, "Exportar relatório", f"Relatório salvo em:\n{out or path}")
