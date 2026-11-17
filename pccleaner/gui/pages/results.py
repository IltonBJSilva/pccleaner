"""Resultados: tabela de achados com filtros, painel de detalhes e limpeza."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QHBoxLayout,
                               QHeaderView, QLineEdit, QPushButton, QSplitter, QTableView,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from pccleaner.core.models import Category, CleanReport, Finding, SafetyLevel
from pccleaner.gui.dialogs import run_clean_flow
from pccleaner.gui.pages import Page, scrollable
from pccleaner.gui.results_model import (COL_ACTION, COL_APP, COL_CAT, COL_CHECK, COL_FILES,
                                         COL_MTIME, COL_NAME, COL_PATH, COL_SAFETY, COL_SIZE,
                                         FINDING_ROLE, FindingsModel, FindingsProxy)
from pccleaner.gui.state import AppState
from pccleaner.gui.utils import fmt_dt, fmt_int, fmt_size, open_in_explorer
from pccleaner.gui.widgets import Card, SafetyBadgeDelegate, make_label
from pccleaner.workers import ChildrenWorker, FilesWorker


class _SizeItem(QTableWidgetItem):
    """Item que ordena numericamente pelo valor em UserRole."""

    def __lt__(self, other) -> bool:
        return (self.data(Qt.ItemDataRole.UserRole) or 0) < (other.data(Qt.ItemDataRole.UserRole) or 0)


class DetailPanel(Card):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding: Finding | None = None
        self.worker = None
        self.setMinimumWidth(320)
        self.lbl_title = make_label("Selecione um item", "h2", wrap=True)
        self.lbl_path = make_label("", "muted", wrap=True)
        self.lbl_path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_info = make_label("", None, wrap=True)
        self.lbl_info.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_info.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(0, 0, 0, 0)
        for w in (self.lbl_title, self.lbl_path, self.lbl_info):
            il.addWidget(w)
        cmd_row = QHBoxLayout()
        self.cmd = QLineEdit()
        self.cmd.setReadOnly(True)
        self.cmd.setPlaceholderText("Sem comando oficial sugerido")
        self.btn_copy = QPushButton("Copiar")
        self.btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self.cmd.text()))
        cmd_row.addWidget(self.cmd, 1)
        cmd_row.addWidget(self.btn_copy)
        il.addWidget(make_label("Comando oficial (execute manualmente se preferir):", "muted"))
        il.addLayout(cmd_row)
        il.addStretch(1)
        self.lay.addWidget(scrollable(inner), 2)

        btns = QHBoxLayout()
        self.btn_open = QPushButton("Abrir no Explorer")
        self.btn_expand = QPushButton("Expandir pasta")
        self.btn_files = QPushButton("Ver arquivos")
        self.btn_open.clicked.connect(lambda: self.finding and open_in_explorer(self.finding.path))
        self.btn_expand.clicked.connect(self.expand)
        self.btn_files.clicked.connect(self.list_files)
        for b in (self.btn_open, self.btn_expand, self.btn_files):
            btns.addWidget(b)
        self.lay.addLayout(btns)
        self.lbl_sub = make_label("", "muted")
        self.lay.addWidget(self.lbl_sub)
        self.sub = QTableWidget(0, 3)
        self.sub.setHorizontalHeaderLabels(["Caminho", "Tamanho", "Info"])
        self.sub.verticalHeader().setVisible(False)
        self.sub.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sub.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sub.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sub.setSortingEnabled(True)
        self.sub.doubleClicked.connect(self._open_sub)
        self.lay.addWidget(self.sub, 3)
        self.show_finding(None)

    def show_finding(self, f: Finding | None) -> None:
        self._cancel_worker()
        self.finding = f
        self.sub.setRowCount(0)
        self.lbl_sub.setText("")
        for b in (self.btn_open, self.btn_expand, self.btn_files):
            b.setEnabled(f is not None)
        if f is None:
            self.lbl_title.setText("Selecione um item")
            self.lbl_path.setText("")
            self.lbl_info.setText("Clique em uma linha para ver a justificativa, a recomendação e as ações.")
            self.cmd.setText("")
            return
        is_dir = os.path.isdir(f.path)
        self.btn_expand.setEnabled(is_dir)
        self.btn_files.setEnabled(is_dir)
        self.lbl_title.setText(("🛡 " if f.requires_admin else "") + (f.name or f.path))
        self.lbl_path.setText(f.path)
        notes = "".join(f"<li>{n}</li>" for n in f.notes)
        admin = "<p>🛡 <b>Exige administrador</b> para limpeza completa.</p>" if f.requires_admin else ""
        age = f"<p>Apenas arquivos com mais de {f.min_age_days} dias serão removidos.</p>" if f.min_age_days else ""
        self.lbl_info.setText(
            f"<p><b>Categoria:</b> {f.category.value} · <b>App:</b> {f.app or '—'} · "
            f"<b>Segurança:</b> {f.safety.label}</p>"
            f"<p><b>Tamanho:</b> {fmt_size(f.size_bytes)} em {fmt_int(f.file_count)} arquivo(s) · "
            f"<b>Modificado:</b> {fmt_dt(f.last_modified)}</p>"
            f"<p><b>Por que foi detectado:</b><br>{f.reason}</p>"
            f"<p><b>Recomendação:</b><br>{f.recommendation}</p>"
            + (f"<p><b>Observações:</b></p><ul>{notes}</ul>" if notes else "") + admin + age
            + ("" if f.cleanable else "<p>🔒 <b>Item informativo/protegido:</b> não será apagado pelo app.</p>"))
        self.cmd.setText(f.command_hint or "")
        self.btn_copy.setEnabled(bool(f.command_hint))

    def _cancel_worker(self) -> None:
        if self.worker is not None:
            self.worker.cancel()
            self.worker = None

    def _start(self, worker, label: str) -> None:
        self._cancel_worker()
        self.sub.setRowCount(0)
        self.lbl_sub.setText(label)
        self.worker = worker
        worker.error.connect(lambda m, w=worker: self.worker is w and self.lbl_sub.setText(f"Erro: {m}"))
        worker.start()

    def expand(self) -> None:
        if self.finding:
            w = ChildrenWorker(self.finding.path)
            w.finished.connect(lambda res, w=w: self.worker is w and self._show_children(res))
            self._start(w, "Calculando tamanhos das subpastas…")

    def list_files(self) -> None:
        if self.finding:
            w = FilesWorker(self.finding.path, 500)
            w.finished.connect(lambda res, w=w: self.worker is w and self._show_files(res))
            self._start(w, "Listando arquivos…")

    def _fill(self, rows: list[tuple[str, int, str]]) -> None:
        self.sub.setSortingEnabled(False)
        self.sub.setRowCount(len(rows))
        for r, (path, size, info) in enumerate(rows):
            it = QTableWidgetItem(path)
            it.setToolTip(path)
            self.sub.setItem(r, 0, it)
            s = _SizeItem(fmt_size(size))
            s.setData(Qt.ItemDataRole.UserRole, size)
            s.setTextAlignment(int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
            self.sub.setItem(r, 1, s)
            self.sub.setItem(r, 2, QTableWidgetItem(info))
        self.sub.setSortingEnabled(True)
        self.sub.sortItems(1, Qt.SortOrder.DescendingOrder)
        self.sub.resizeColumnToContents(1)

    def _show_children(self, res) -> None:
        path, items = res
        self.worker = None
        self._fill([(c.path, c.size_bytes, f"{fmt_int(c.file_count)} arq.") for c in items])
        self.lbl_sub.setText(f"{len(items)} subitens em {path}")

    def _show_files(self, res) -> None:
        path, items = res
        self.worker = None
        self._fill([(f.path, f.size_bytes, fmt_dt(f.mtime)) for f in items])
        self.lbl_sub.setText(f"{len(items)} maiores arquivos em {path}")

    def _open_sub(self, index) -> None:
        it = self.sub.item(index.row(), 0)
        if it:
            open_in_explorer(it.text())


class ResultsPage(Page):
    title = "Resultados"

    def __init__(self, state: AppState, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.state = state
        head = QHBoxLayout()
        head.addWidget(make_label("Resultados", "h1"))
        head.addStretch(1)
        self.lbl_summary = make_label("Nenhuma análise realizada ainda.", "muted")
        head.addWidget(self.lbl_summary)
        self.root.addLayout(head)

        bar = QHBoxLayout()
        self.cmb_cat = QComboBox()
        self.cmb_cat.addItem("Todas as categorias", None)
        self.cmb_safety = QComboBox()
        self.cmb_safety.addItem("Todos os níveis", None)
        for s in SafetyLevel:
            self.cmb_safety.addItem(s.label, s)
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Buscar por nome, caminho ou app…")
        self.txt_search.setClearButtonEnabled(True)
        btn_safe = QPushButton("Selecionar todos seguros")
        btn_none = QPushButton("Desmarcar tudo")
        for w in (self.cmb_cat, self.cmb_safety):
            bar.addWidget(w)
        bar.addWidget(self.txt_search, 1)
        bar.addWidget(btn_safe)
        bar.addWidget(btn_none)
        self.root.addLayout(bar)

        self.model = FindingsModel(self)
        self.proxy = FindingsProxy(self)
        self.proxy.setSourceModel(self.model)
        v = self.view = QTableView()
        v.setModel(self.proxy)
        v.setSortingEnabled(True)
        v.setAlternatingRowColors(True)
        v.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        v.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        v.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        v.verticalHeader().setVisible(False)
        v.verticalHeader().setDefaultSectionSize(30)
        v.setWordWrap(False)
        v.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        v.setItemDelegateForColumn(COL_SAFETY, SafetyBadgeDelegate(v))
        hh = v.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for col, w in ((COL_CHECK, 36), (COL_CAT, 180), (COL_NAME, 170), (COL_PATH, 300), (COL_SIZE, 90),
                       (COL_FILES, 80), (COL_MTIME, 130), (COL_APP, 110), (COL_SAFETY, 105), (COL_ACTION, 220)):
            v.setColumnWidth(col, w)
        v.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
        v.clicked.connect(self._on_current)
        v.selectionModel().currentRowChanged.connect(lambda cur, _prev: self._on_current(cur))

        self.detail = DetailPanel()
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(v)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setSizes([900, 380])
        self.root.addWidget(split, 1)

        foot = QHBoxLayout()
        self.lbl_sel = make_label("0 itens selecionados · 0 B", "h2")
        foot.addWidget(self.lbl_sel)
        foot.addWidget(make_label("Itens marcados com 🛡 exigem administrador · 🔒 = protegido/informativo", "hint"))
        foot.addStretch(1)
        self.btn_clean = QPushButton("Limpar selecionados…")
        self.btn_clean.setObjectName("primary")
        self.btn_clean.setEnabled(False)
        self.btn_clean.clicked.connect(self.clean_selected)
        foot.addWidget(self.btn_clean)
        self.root.addLayout(foot)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(lambda: self.proxy.set_text(self.txt_search.text()))
        self.txt_search.textChanged.connect(lambda _t: self._search_timer.start())
        self.cmb_cat.currentIndexChanged.connect(lambda _i: self.proxy.set_category(self.cmb_cat.currentData()))
        self.cmb_safety.currentIndexChanged.connect(lambda _i: self.proxy.set_safety(self.cmb_safety.currentData()))
        btn_safe.clicked.connect(self.select_all_safe)
        btn_none.clicked.connect(self.model.clear_selection)
        self.model.selectionChanged.connect(self._on_selection)
        state.resultChanged.connect(self.set_result)

    # ------------------------------------------------------------------ dados
    def set_result(self, result) -> None:
        findings = list(result.findings) if result is not None else []
        self.set_findings(findings)
        if result is not None:
            self.lbl_summary.setText(
                f"{fmt_int(len(findings))} itens · recuperável (Seguro+Revisar): {fmt_size(result.recoverable_bytes)}")
        else:
            self.lbl_summary.setText("Nenhuma análise realizada ainda.")

    def set_findings(self, findings: list[Finding]) -> None:
        self.detail.show_finding(None)
        self.model.set_findings(findings)
        present = {f.category.value for f in findings}
        cur = self.cmb_cat.currentData()
        self.cmb_cat.blockSignals(True)
        self.cmb_cat.clear()
        self.cmb_cat.addItem("Todas as categorias", None)
        for c in Category:
            if c.value in present:
                self.cmb_cat.addItem(c.value, c.value)
        self.cmb_cat.setCurrentIndex(max(0, self.cmb_cat.findData(cur)))
        self.cmb_cat.blockSignals(False)
        self.proxy.set_category(self.cmb_cat.currentData())
        col = self.proxy.sortColumn()
        self.proxy.sort(col if col >= 0 else COL_SIZE, self.proxy.sortOrder())

    def select_all_safe(self) -> None:
        rows = [r for r in self.proxy.visible_source_rows()
                if (f := self.model.finding_at(r)) is not None and f.safety is SafetyLevel.SAFE and f.cleanable]
        self.model.set_checked_rows(rows, True)

    # ------------------------------------------------------------------ eventos
    def _on_selection(self, count: int, size: int) -> None:
        self.lbl_sel.setText(f"{fmt_int(count)} itens selecionados · {fmt_size(size)}")
        self.btn_clean.setEnabled(count > 0)

    def _on_current(self, index) -> None:
        f = index.data(FINDING_ROLE) if index.isValid() else None
        if f is not self.detail.finding:
            self.detail.show_finding(f)

    def clean_selected(self) -> None:
        sel = self.model.selected_findings()
        if not sel:
            return
        scan_id = self.state.result.scan_id if self.state.result else None
        report = run_clean_flow(self, sel, self.state.settings, scan_id=scan_id)
        if report is None:
            return
        self.apply_clean_report(report)
        self.state.last_clean = report
        self.state.cleanFinished.emit(report)
        self.state.historyChanged.emit()

    def apply_clean_report(self, report: CleanReport) -> None:
        by_id = {i.finding_id: i for i in report.items}
        for f in self.model.findings():
            it = by_id.get(f.id)
            if it is None:
                continue
            f.size_bytes = max(0, f.size_bytes - it.freed_bytes)
            f.file_count = max(0, f.file_count - it.files_removed)
            f.selected = False
        self.model.refresh_rows()
        self.detail.show_finding(None)
        self.view.clearSelection()
