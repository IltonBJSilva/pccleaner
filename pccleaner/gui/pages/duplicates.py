"""Duplicados: busca por hash, seleção manual de cópias (sempre mantendo ao menos uma)."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QMessageBox,
                               QPushButton, QSpinBox, QTreeWidget, QTreeWidgetItem, QWidget)

from pccleaner.core.models import Category, CleanMode, Finding, SafetyLevel
from pccleaner.gui.dialogs import run_clean_flow
from pccleaner.gui.pages import Page
from pccleaner.gui.pages.dashboard import RootsEditor
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_dt, fmt_int, fmt_size, open_in_explorer, refusal_reason
from pccleaner.gui.widgets import Card, make_label
from pccleaner.workers import DuplicateWorker

PATH_ROLE = Qt.ItemDataRole.UserRole + 1
SIZE_ROLE = Qt.ItemDataRole.UserRole + 2
MAX_GROUPS_SHOWN = 5000


def _mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def make_duplicate_finding(path: str, size: int) -> Finding:
    return Finding(
        id=Finding.make_id(path, "duplicate"), rule_id="duplicate",
        name=os.path.basename(path), path=path, category=Category.DUPLICATES, app="",
        safety=SafetyLevel.REVIEW,
        reason="Conteúdo idêntico (SHA-256) a outro arquivo do mesmo grupo.",
        recommendation="Mantenha ao menos uma cópia; as demais vão para a quarentena.",
        clean_mode=CleanMode.WHOLE, size_bytes=int(size), file_count=1,
        last_modified=_mtime(path), selected=True)


class DuplicatesPage(Page):
    title = "Duplicados"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        self.worker: DuplicateWorker | None = None
        self._guard = False
        self.root.addWidget(make_label("Arquivos duplicados", "h1"))
        self.root.addWidget(make_label(
            "Nada é apagado automaticamente. Marque as cópias que deseja remover — ao menos uma cópia de "
            "cada grupo é sempre mantida. Arquivos em áreas protegidas (Documentos, Imagens, Área de "
            "Trabalho…) são apenas exibidos (🔒).", "muted", wrap=True))
        opts = Card()
        opts.lay.addWidget(make_label("Pastas para procurar:", "muted"))
        self.roots = RootsEditor([])
        opts.lay.addWidget(self.roots)
        row = QHBoxLayout()
        row.addWidget(make_label("Tamanho mínimo:"))
        self.spin = QSpinBox()
        self.spin.setRange(0, 100000)
        self.spin.setValue(1)
        self.spin.setSuffix(" MB")
        row.addWidget(self.spin)
        row.addStretch(1)
        self.lbl_status = make_label("", "muted")
        row.addWidget(self.lbl_status, 2)
        self.btn_find = QPushButton("Procurar duplicados")
        self.btn_find.setObjectName("primary")
        self.btn_find.clicked.connect(self.start)
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel)
        row.addWidget(self.btn_find)
        row.addWidget(self.btn_cancel)
        opts.lay.addLayout(row)
        self.root.addWidget(opts)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["Arquivo", "Tamanho", "Modificado"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.itemDoubleClicked.connect(lambda it, _c: self._open(it))
        self.root.addWidget(self.tree, 1)

        foot = QHBoxLayout()
        self.lbl_sel = make_label("0 cópias selecionadas · 0 B", "h2")
        foot.addWidget(self.lbl_sel)
        foot.addStretch(1)
        btn_open = QPushButton("Abrir local")
        btn_open.clicked.connect(lambda: self._open(self.tree.currentItem()))
        self.btn_clean = QPushButton("Enviar selecionados para a quarentena…")
        self.btn_clean.setObjectName("primary")
        self.btn_clean.setEnabled(False)
        self.btn_clean.clicked.connect(self.clean_selected)
        foot.addWidget(btn_open)
        foot.addWidget(self.btn_clean)
        self.root.addLayout(foot)

    # ------------------------------------------------------------------ busca
    def start(self) -> None:
        roots = self.roots.roots()
        if not roots:
            QMessageBox.information(self, "PCCleaner", "Adicione ao menos uma pasta.")
            return
        self.tree.clear()
        self._update_sel()
        self.worker = DuplicateWorker(roots, self.spin.value() * 1024 * 1024)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.btn_find.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.lbl_status.setText("Procurando…")
        self.worker.start()

    def cancel(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.lbl_status.setText("Cancelando…")

    def _on_progress(self, payload) -> None:
        current, count = payload
        self.lbl_status.setText(self.lbl_status.fontMetrics().elidedText(
            f"{fmt_int(count)} arquivos · {current}", Qt.TextElideMode.ElideMiddle, 420))

    def _done(self) -> None:
        self.btn_find.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    def _on_error(self, msg: str) -> None:
        self._done()
        self.lbl_status.setText("Falha na busca.")
        QMessageBox.critical(self, "Duplicados", msg)

    def _on_finished(self, groups) -> None:
        self._done()
        self.set_groups(groups or [])

    def set_groups(self, groups) -> None:
        groups = sorted(groups, key=lambda g: g.wasted_bytes, reverse=True)
        wasted = sum(g.wasted_bytes for g in groups)
        self._guard = True
        self.tree.setUpdatesEnabled(False)
        self.tree.clear()
        for g in groups[:MAX_GROUPS_SHOWN]:
            top = QTreeWidgetItem([f"{len(g.paths)} cópias · desperdício {fmt_size(g.wasted_bytes)}",
                                   fmt_size(g.size_bytes), g.sha256[:12]])
            top.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            top.setToolTip(2, g.sha256)
            for p in g.paths:
                ch = QTreeWidgetItem([p, fmt_size(g.size_bytes), fmt_dt(_mtime(p))])
                ch.setData(0, PATH_ROLE, p)
                ch.setData(0, SIZE_ROLE, int(g.size_bytes))
                reason = refusal_reason(p)
                if reason:  # backend recusaria: só exibe, sem checkbox
                    ch.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    ch.setText(0, "🔒 " + p)
                    ch.setToolTip(0, reason)
                else:
                    ch.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                                | Qt.ItemFlag.ItemIsUserCheckable)
                    ch.setCheckState(0, Qt.CheckState.Unchecked)
                    ch.setToolTip(0, p)
                top.addChild(ch)
            self.tree.addTopLevelItem(top)
        if len(groups) <= 300:
            self.tree.expandAll()
        self.tree.setUpdatesEnabled(True)
        self._guard = False
        extra = f" (mostrando {MAX_GROUPS_SHOWN})" if len(groups) > MAX_GROUPS_SHOWN else ""
        self.lbl_status.setText(f"{fmt_int(len(groups))} grupos{extra} · {fmt_size(wasted)} desperdiçados")
        self._update_sel()

    # ------------------------------------------------------------------ seleção
    def _on_item_changed(self, item: QTreeWidgetItem, col: int) -> None:
        if self._guard or col != 0 or item.parent() is None:
            return
        parent = item.parent()
        if item.checkState(0) == Qt.CheckState.Checked:
            # Itens protegidos (sem checkbox) contam como cópias mantidas.
            kept = [parent.child(i) for i in range(parent.childCount())
                    if parent.child(i).checkState(0) != Qt.CheckState.Checked]
            if not kept:
                self._guard = True
                item.setCheckState(0, Qt.CheckState.Unchecked)
                self._guard = False
                self.lbl_status.setText("Ao menos uma cópia de cada grupo deve ser mantida.")
        self._update_sel()

    def selected(self) -> list[tuple[str, int]]:
        out = []
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                ch = top.child(j)
                if ch.flags() & Qt.ItemFlag.ItemIsUserCheckable and ch.checkState(0) == Qt.CheckState.Checked:
                    out.append((ch.data(0, PATH_ROLE), int(ch.data(0, SIZE_ROLE) or 0)))
        return out

    def _update_sel(self) -> None:
        sel = self.selected()
        self.lbl_sel.setText(f"{len(sel)} cópias selecionadas · {fmt_size(sum(s for _, s in sel))}")
        self.btn_clean.setEnabled(bool(sel))

    def _open(self, item: QTreeWidgetItem | None) -> None:
        if item is None:
            return
        p = item.data(0, PATH_ROLE) or (item.child(0).data(0, PATH_ROLE) if item.childCount() else None)
        if p:
            open_in_explorer(p)

    def clean_selected(self) -> None:
        sel = self.selected()
        if not sel:
            return
        findings = [make_duplicate_finding(p, s) for p, s in sel]
        report = run_clean_flow(self, findings, self.state.settings,
                                title="Enviar duplicados para a quarentena", force_quarantine=True)
        if report is None:
            return
        removed = {i.path.lower() for i in report.items if not i.errors and (i.freed_bytes or i.files_removed)}
        self._guard = True
        for i in range(self.tree.topLevelItemCount() - 1, -1, -1):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount() - 1, -1, -1):
                if (top.child(j).data(0, PATH_ROLE) or "").lower() in removed:
                    top.removeChild(top.child(j))
            if top.childCount() < 2:
                self.tree.takeTopLevelItem(i)
        self._guard = False
        self._update_sel()
        self.state.last_clean = report
        self.state.historyChanged.emit()
