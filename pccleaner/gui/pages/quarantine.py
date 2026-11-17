"""Quarentena: lotes de itens removidos, com restauração e exclusão definitiva."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QMessageBox,
                               QPushButton, QTableWidget, QTableWidgetItem, QWidget)

from pccleaner.gui.pages import Page
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_dt, fmt_int, fmt_size
from pccleaner.gui.widgets import make_label
from pccleaner.workers import FunctionWorker


def _manager():
    from pccleaner.quarantine import QuarantineManager
    return QuarantineManager()


def _load():
    m = _manager()
    return m.list_batches(), m.total_size()


def _item_text(it) -> str:
    if isinstance(it, dict):
        return str(it.get("original_path") or it.get("path") or it)
    return str(getattr(it, "original_path", None) or getattr(it, "path", None) or it)


class QuarantinePage(Page):
    title = "Quarentena"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self._worker = None
        self._batches: list = []
        head = QHBoxLayout()
        head.addWidget(make_label("Quarentena", "h1"))
        head.addStretch(1)
        self.lbl_total = make_label("", "muted")
        head.addWidget(self.lbl_total)
        self.root.addLayout(head)
        self.root.addWidget(make_label(
            "Itens limpos com a quarentena ativada ficam guardados aqui e podem ser restaurados ao local "
            "original. Lotes mais antigos que o prazo configurado podem ser excluídos definitivamente.",
            "muted", wrap=True))
        t = self.table = QTableWidget(0, 4)
        t.setHorizontalHeaderLabels(["Lote", "Criado em", "Itens", "Tamanho"])
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.root.addWidget(t, 1)
        row = QHBoxLayout()
        self.btn_refresh = QPushButton("Atualizar")
        self.btn_restore = QPushButton("Restaurar lote")
        self.btn_restore.setObjectName("primary")
        self.btn_purge = QPushButton("Excluir definitivamente")
        self.btn_purge.setObjectName("danger")
        self.btn_expired = QPushButton("Excluir lotes expirados")
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_restore.clicked.connect(self.restore)
        self.btn_purge.clicked.connect(self.purge)
        self.btn_expired.clicked.connect(self.purge_expired)
        self.buttons = (self.btn_refresh, self.btn_restore, self.btn_purge, self.btn_expired)
        for b in self.buttons:
            row.addWidget(b)
        row.addStretch(1)
        self.lbl_status = make_label("", "muted")
        row.addWidget(self.lbl_status)
        self.root.addLayout(row)
        state.cleanFinished.connect(lambda _r: self.refresh())
        state.historyChanged.connect(self.refresh)

    def on_show(self) -> None:
        self.refresh()

    def _busy(self, on: bool) -> None:
        for b in self.buttons:
            b.setEnabled(not on)

    def _run(self, fn, done) -> None:
        if self._worker is not None and self._worker.is_running():
            return
        self._busy(True)
        w = FunctionWorker(fn)
        w.finished.connect(lambda res: (self._busy(False), done(res)))
        w.error.connect(lambda m: (self._busy(False), self.lbl_status.setText(f"Erro: {m}")))
        self._worker = w
        w.start()

    def refresh(self) -> None:
        self._run(_load, self._show)

    def _show(self, res) -> None:
        batches, total = res
        self._batches = sorted(batches, key=lambda b: b.created_at or 0, reverse=True)
        self.table.setRowCount(len(self._batches))
        for r, b in enumerate(self._batches):
            vals = [str(b.batch_id), fmt_dt(b.created_at), fmt_int(b.item_count), fmt_size(b.size_bytes)]
            tip = "\n".join(_item_text(i) for i in list(b.items or [])[:30])
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                it.setToolTip(tip)
                if c >= 2:
                    it.setTextAlignment(int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
                self.table.setItem(r, c, it)
        self.lbl_total.setText(f"{len(self._batches)} lotes · {fmt_size(total)} em quarentena")

    def _current(self):
        r = self.table.currentRow()
        return self._batches[r] if 0 <= r < len(self._batches) else None

    def restore(self) -> None:
        b = self._current()
        if b is None or QMessageBox.question(
                self, "Restaurar", f"Restaurar {b.item_count} item(ns) do lote {b.batch_id} para os locais "
                "originais?") != QMessageBox.StandardButton.Yes:
            return
        self._run(lambda: _manager().restore(b.batch_id), self._after("restaurado(s)"))

    def purge(self) -> None:
        b = self._current()
        if b is None or QMessageBox.warning(
                self, "Excluir definitivamente",
                f"Excluir definitivamente o lote {b.batch_id} ({fmt_size(b.size_bytes)})? "
                "Esta ação não pode ser desfeita.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        self._run(lambda: _manager().purge(b.batch_id), self._after("excluído(s)"))

    def purge_expired(self) -> None:
        days = self.state.settings.quarantine_keep_days
        if QMessageBox.question(self, "Excluir expirados",
                                f"Excluir definitivamente os lotes com mais de {days} dias?") \
                != QMessageBox.StandardButton.Yes:
            return
        self._run(lambda: _manager().purge_expired(days), self._after("excluído(s) por expiração"))

    def _after(self, verb: str):
        def done(n) -> None:
            self.lbl_status.setText(f"{fmt_int(n or 0)} item(ns)/lote(s) {verb}.")
            self._worker = None
            self.refresh()
        return done
